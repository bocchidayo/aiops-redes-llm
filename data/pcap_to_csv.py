#!/usr/bin/env python3
"""
Generate a rich plain-text summary from PCAP files using dpkt.
Single-pass over the PCAP - all sections computed in one read.

Usage:
    python data/pcap_to_csv.py --input captures/bigFlows.pcap
    python data/pcap_to_csv.py --input captures/bigFlows.pcap --output custom.txt
"""

import sys
import argparse
import os
from collections import defaultdict, Counter

try:
    import dpkt
except ImportError:
    os.system("pip install -q dpkt")
    import dpkt


STANDARD_PORTS = {
    20, 21, 22, 23, 25, 53, 80, 110, 143, 443,
    993, 995, 3306, 5432, 8080, 8443, 3389, 5900,
}

PORT_NAMES = {
    21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
    80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS',
    993: 'IMAPS', 995: 'POP3S', 3306: 'MySQL', 5432: 'PostgreSQL',
    8080: 'HTTP-alt', 8443: 'HTTPS-alt', 3389: 'RDP', 5900: 'VNC',
}


def is_rfc1918(ip_str):
    """True if IP is in 10/8, 172.16/12, or 192.168/16."""
    parts = ip_str.split('.')
    if len(parts) != 4:
        return False
    try:
        a, b = int(parts[0]), int(parts[1])
    except ValueError:
        return False
    return (a == 10) or (a == 172 and 16 <= b <= 31) or (a == 192 and b == 168)


def fmt_dur_long(seconds):
    """'4 min 59 s' - matches original header format."""
    if seconds < 60:
        return f"{int(seconds)} s"
    elif seconds < 3600:
        return f"{int(seconds // 60)} min {int(seconds % 60)} s"
    else:
        return f"{int(seconds // 3600)} h {int((seconds % 3600) // 60)} min"


def fmt_dur_short(seconds):
    """'4m 31s' compact format for conversation durations."""
    if seconds < 60:
        return f"{int(seconds)}s"
    elif seconds < 3600:
        m, s = divmod(int(seconds), 60)
        return f"{m}m {s}s"
    else:
        h, rem = divmod(int(seconds), 3600)
        return f"{h}h {rem // 60}m"


def fmt_offset(seconds):
    """+2m00s format for temporal window display."""
    m, s = divmod(int(seconds), 60)
    return f"+{m}m{s:02d}s"


def fmt_bytes(b):
    if b < 1e6:
        return f"{b / 1e3:.1f} KB"
    elif b < 1e9:
        return f"{b / 1e6:.1f} MB"
    else:
        return f"{b / 1e9:.1f} GB"


def extract_stats(pcap_path):
    WINDOW = 30

    protocol_counts = Counter()
    src_bytes       = defaultdict(int)
    dst_bytes       = defaultdict(int)
    window_buckets  = Counter()

    # flow_key = (src_ip, dst_ip, dst_port, proto_str)
    conv_packets = Counter()
    conv_bytes   = defaultdict(int)
    conv_first   = {}
    conv_last    = {}

    port_packets  = Counter()
    port_proto    = {}                    # port -> 'TCP' | 'UDP'
    port_src_pkts = defaultdict(Counter)  # port -> {src_ip: pkt_count}
    port_dst_pkts = defaultdict(Counter)  # port -> {dst_ip: pkt_count}

    # Internal host profiling (only for packets where src is RFC1918)
    host_dst_ips      = defaultdict(set)
    host_dst_ports    = defaultdict(Counter)
    host_dst_ip_bytes = defaultdict(Counter)
    host_proto        = defaultdict(Counter)

    int_ext_sent = 0   # bytes flowing internal -> external
    ext_int_recv = 0   # bytes flowing external -> internal
    internal_ips = set()
    external_ips = set()

    total_packets = 0
    total_bytes   = 0
    start_time    = None
    end_time      = None

    try:
        with open(pcap_path, 'rb') as f:
            pcap = dpkt.pcap.Reader(f)
            for ts, buf in pcap:
                if start_time is None:
                    start_time = ts
                end_time = ts

                total_packets += 1
                pkt_len = len(buf)
                total_bytes += pkt_len
                window_buckets[int((ts - start_time) / WINDOW)] += 1

                try:
                    eth = dpkt.ethernet.Ethernet(buf)
                    if not isinstance(eth.data, dpkt.ip.IP):
                        continue
                    ip_pkt = eth.data
                    src    = dpkt.utils.inet_to_str(ip_pkt.src)
                    dst    = dpkt.utils.inet_to_str(ip_pkt.dst)

                    src_bytes[src] += pkt_len
                    dst_bytes[dst] += pkt_len

                    src_int = is_rfc1918(src)
                    dst_int = is_rfc1918(dst)

                    if src_int:
                        internal_ips.add(src)
                    else:
                        external_ips.add(src)
                    if dst_int:
                        internal_ips.add(dst)
                    else:
                        external_ips.add(dst)

                    if src_int and not dst_int:
                        int_ext_sent += pkt_len
                    elif not src_int and dst_int:
                        ext_int_recv += pkt_len

                    proto_str = 'Other'
                    dport     = None

                    if isinstance(ip_pkt.data, dpkt.tcp.TCP):
                        proto_str = 'TCP'
                        dport     = ip_pkt.data.dport
                    elif isinstance(ip_pkt.data, dpkt.udp.UDP):
                        proto_str = 'UDP'
                        dport     = ip_pkt.data.dport
                    elif isinstance(ip_pkt.data, dpkt.icmp.ICMP):
                        proto_str = 'ICMP'

                    protocol_counts[proto_str] += 1

                    if dport is not None:
                        key = (src, dst, dport, proto_str)
                        conv_packets[key] += 1
                        conv_bytes[key]   += pkt_len
                        if key not in conv_first:
                            conv_first[key] = ts
                        conv_last[key] = ts

                        port_packets[dport] += 1
                        if dport not in port_proto:
                            port_proto[dport] = proto_str
                        port_src_pkts[dport][src] += 1
                        port_dst_pkts[dport][dst] += 1

                        if src_int:
                            host_dst_ips[src].add(dst)
                            host_dst_ports[src][dport] += 1
                            host_dst_ip_bytes[src][dst] += pkt_len
                            host_proto[src][proto_str] += 1

                except Exception:
                    continue

                if total_packets % 100_000 == 0:
                    print(f"  {total_packets:,} paquetes procesados...", flush=True)

    except Exception as e:
        print(f"Error leyendo PCAP: {e}")
        return None

    return dict(
        start_time=start_time, end_time=end_time,
        total_packets=total_packets, total_bytes=total_bytes,
        protocol_counts=protocol_counts,
        src_bytes=src_bytes, dst_bytes=dst_bytes,
        window_buckets=window_buckets,
        conv_packets=conv_packets, conv_bytes=conv_bytes,
        conv_first=conv_first, conv_last=conv_last,
        port_packets=port_packets, port_proto=port_proto,
        port_src_pkts=port_src_pkts, port_dst_pkts=port_dst_pkts,
        host_dst_ips=host_dst_ips, host_dst_ports=host_dst_ports,
        host_dst_ip_bytes=host_dst_ip_bytes, host_proto=host_proto,
        int_ext_sent=int_ext_sent, ext_int_recv=ext_int_recv,
        internal_ips=internal_ips, external_ips=external_ips,
    )


def build_summary(pcap_path, output_path):
    print(f"Leyendo {pcap_path}...")
    stats = extract_stats(pcap_path)
    if stats is None:
        print("No se pudo extraer estadisticas del PCAP.")
        return

    s        = stats
    dur      = s['end_time'] - s['start_time']
    avg_pkt  = s['total_bytes'] / s['total_packets'] if s['total_packets'] else 0
    pct_base = sum(s['protocol_counts'].values())
    total_p  = s['total_packets']
    lines    = []

    # ─────────────────────────────────────────────────────────────────────
    # SECTION 1: Header
    # ─────────────────────────────────────────────────────────────────────
    lines += [
        f"=== RESUMEN DE CAPTURA DE RED - {os.path.basename(pcap_path)} ===",
        f"Duracion        : {fmt_dur_long(dur)}",
        f"Paquetes totales: {total_p:,}",
        f"Bytes totales   : {fmt_bytes(s['total_bytes'])}",
        f"Tamano medio pkt: {int(avg_pkt)} bytes",
        f"Flujos unicos   : {len(s['conv_packets']):,}",
    ]

    # ─────────────────────────────────────────────────────────────────────
    # SECTION 2: Protocol breakdown
    # ─────────────────────────────────────────────────────────────────────
    lines += ["", "PROTOCOLOS:"]
    for proto in ('TCP', 'UDP', 'ICMP', 'Other'):
        cnt = s['protocol_counts'].get(proto, 0)
        pct = 100.0 * cnt / pct_base if pct_base else 0
        lines.append(f"  {proto:6s}: {cnt:10,} paquetes ({pct:5.1f}%)")

    # ─────────────────────────────────────────────────────────────────────
    # SECTION 3: Internal vs External
    # ─────────────────────────────────────────────────────────────────────
    int_sent = s['int_ext_sent']
    ext_recv = s['ext_int_recv']
    ratio_ie = ext_recv / int_sent if int_sent > 0 else 0.0
    if ratio_ie > 3:
        ratio_nota = ">3x = red receptora"
    elif ratio_ie < 0.5:
        ratio_nota = "<0.5x = emisora inusual"
    else:
        ratio_nota = "normal - entre ambos"

    ext_bytes_sent = sum(s['src_bytes'].get(ip, 0) for ip in s['external_ips'])
    ext_bytes_recv = sum(s['dst_bytes'].get(ip, 0) for ip in s['external_ips'])

    lines += [
        "",
        "IPs INTERNAS (RFC1918):",
        f"  Hosts unicos    : {len(s['internal_ips'])}",
        f"  Bytes enviados  : {fmt_bytes(int_sent)} (interno -> externo)",
        f"  Bytes recibidos : {fmt_bytes(ext_recv)} (externo -> interno)",
        "",
        "IPs EXTERNAS:",
        f"  Hosts unicos    : {len(s['external_ips'])}",
        f"  Bytes enviados  : {fmt_bytes(ext_bytes_sent)}",
        f"  Bytes recibidos : {fmt_bytes(ext_bytes_recv)}",
        "",
        "RATIO ENTRADA/SALIDA:",
        f"  Enviado  (interno->externo): {fmt_bytes(int_sent)}",
        f"  Recibido (externo->interno): {fmt_bytes(ext_recv)}",
        f"  Ratio: {ratio_ie:.1f}x",
        f"  Nota: {ratio_nota}",
    ]

    # ─────────────────────────────────────────────────────────────────────
    # SECTION 4: Top 10 conversations
    # ─────────────────────────────────────────────────────────────────────
    lines += ["", "TOP 10 CONVERSACIONES MAS ACTIVAS:"]
    for rank, (key, pkts) in enumerate(s['conv_packets'].most_common(10), 1):
        src_ip, dst_ip, dport, proto = key
        b       = s['conv_bytes'][key]
        first   = s['conv_first'].get(key, 0)
        last    = s['conv_last'].get(key, 0)
        avg_sz  = b // pkts if pkts else 0
        pct     = 100.0 * pkts / total_p
        src_t   = "INTERNO" if is_rfc1918(src_ip) else "EXTERNO"
        dst_t   = "INTERNO" if is_rfc1918(dst_ip) else "EXTERNO"
        pname   = PORT_NAMES.get(dport, '')
        plabel  = f"{dport}/{pname}" if pname else str(dport)

        lines.append(f"  {rank}. {src_ip} -> {dst_ip}:{plabel} ({proto})")
        lines.append(
            f"     Paquetes: {pkts:,} ({pct:.1f}%) | "
            f"Bytes: {fmt_bytes(b)} | "
            f"Duracion: {fmt_dur_short(last - first)} | "
            f"Pkt medio: {avg_sz} bytes"
        )
        lines.append(f"     Origen: {src_t} | Destino: {dst_t}")

    # ─────────────────────────────────────────────────────────────────────
    # SECTION 5: Per-host profile for top 5 internal IPs by bytes sent
    # ─────────────────────────────────────────────────────────────────────
    int_senders = [
        (ip, s['src_bytes'][ip])
        for ip in s['internal_ips'] if ip in s['src_bytes']
    ]
    top5_int = sorted(int_senders, key=lambda x: -x[1])[:5]

    lines += ["", "PERFIL DE HOSTS INTERNOS (top 5 por bytes enviados):"]
    for ip, sent_b in top5_int:
        recv_b    = s['dst_bytes'].get(ip, 0)
        d_ips     = s['host_dst_ips'].get(ip, set())
        d_ports   = s['host_dst_ports'].get(ip, Counter())
        d_ip_byt  = s['host_dst_ip_bytes'].get(ip, Counter())
        h_proto   = s['host_proto'].get(ip, Counter())

        total_pkts_host = sum(d_ports.values())
        top3_p    = d_ports.most_common(3)
        top3_ip   = d_ip_byt.most_common(3)
        dom_proto = h_proto.most_common(1)[0][0] if h_proto else 'N/A'

        port_parts = []
        for p, cnt in top3_p:
            pct = 100.0 * cnt / total_pkts_host if total_pkts_host else 0
            pn  = PORT_NAMES.get(p, '')
            pl  = f"{p}/{pn}" if pn else str(p)
            port_parts.append(f"{pl} ({pct:.0f}%)")

        ip_parts = [f"{dip} ({fmt_bytes(db)})" for dip, db in top3_ip]

        lines += [
            "",
            f"  {ip} - {fmt_bytes(sent_b)} enviados | {fmt_bytes(recv_b)} recibidos",
            f"    Destinos unicos      : {len(d_ips)} IPs",
            f"    Puertos unicos usados: {len(d_ports)}",
            f"    Puertos mas usados   : {', '.join(port_parts)}",
            f"    Destinos principales : {', '.join(ip_parts)}",
            f"    Protocolo dominante  : {dom_proto}",
        ]

    # ─────────────────────────────────────────────────────────────────────
    # SECTION 6: Non-standard port analysis (top 15, filtered)
    # ─────────────────────────────────────────────────────────────────────
    top15        = s['port_packets'].most_common(15)
    nonstandard  = [(port, cnt) for port, cnt in top15 if port not in STANDARD_PORTS]

    lines += ["", "PUERTOS NO ESTANDAR DETECTADOS:"]
    if not nonstandard:
        lines.append("  (ninguno en el top 15)")
    else:
        for port, cnt in nonstandard:
            proto    = s['port_proto'].get(port, '?')
            src_ctr  = s['port_src_pkts'].get(port, Counter())
            dst_ctr  = s['port_dst_pkts'].get(port, Counter())
            top2_src = src_ctr.most_common(2)
            top2_dst = dst_ctr.most_common(2)

            src_parts = [f"{ip} ({c:,} pkts)" for ip, c in top2_src]
            dst_parts = [ip for ip, _ in top2_dst]

            lines.append(f"  Puerto {port} - {cnt:,} paquetes | {proto} | INUSUAL")
            lines.append(f"    Origenes  ({len(src_ctr)} unicos): {', '.join(src_parts)}")
            lines.append(f"    Destinos  ({len(dst_ctr)} unicos): {', '.join(dst_parts)}")
            lines.append( "    Nota      : Puerto no registrado - investigar aplicacion")

    # ─────────────────────────────────────────────────────────────────────
    # SECTION 7: Temporal activity - top 5 busiest + quietest window
    # ─────────────────────────────────────────────────────────────────────
    WINDOW        = 30
    sorted_win    = sorted(s['window_buckets'].items(), key=lambda x: -x[1])
    top5_win      = sorted_win[:5]
    quietest      = sorted_win[-1] if sorted_win else (0, 0)

    win_labels = [
        "Ventana mas activa   ",
        "2a mas activa        ",
        "3a mas activa        ",
        "4a mas activa        ",
        "5a mas activa        ",
    ]

    lines += ["", "ACTIVIDAD TEMPORAL (ventanas de 30 s):"]
    for i, (bucket, cnt) in enumerate(top5_win):
        s_off = bucket * WINDOW
        e_off = s_off + WINDOW
        lbl   = win_labels[i] if i < len(win_labels) else f"{i+1}a mas activa        "
        lines.append(f"  {lbl}: {fmt_offset(s_off)} -> {fmt_offset(e_off)} | {cnt:,} paquetes")

    if quietest[1] > 0:
        bucket, cnt = quietest
        s_off = bucket * WINDOW
        e_off = s_off + WINDOW
        peak  = top5_win[0][1] if top5_win else 1
        r_tv  = peak / cnt if cnt else 0
        lines.append(f"  Ventana mas tranquila: {fmt_offset(s_off)} -> {fmt_offset(e_off)} | {cnt:,} paquetes")
        lines.append(f"  Pico vs valle        : {r_tv:.1f}x diferencia")

    # ─────────────────────────────────────────────────────────────────────
    # SECTION 8: Automated anomaly flags
    # ─────────────────────────────────────────────────────────────────────
    flags = []

    # Internal IP sending >15 MB in capture window
    for ip in s['internal_ips']:
        mb = s['src_bytes'].get(ip, 0) / 1e6
        if mb > 15:
            flags.append(
                f"  !! {ip} envio {mb:.1f} MB en {fmt_dur_long(dur)} "
                f"- supera umbral de 15 MB"
            )

    # Non-standard port with >50k packets
    for port, cnt in s['port_packets'].most_common():
        if cnt < 50_000:
            break
        if port not in STANDARD_PORTS:
            flags.append(
                f"  !! Puerto {port} tiene {cnt:,} paquetes "
                f"- puerto no estandar con alto volumen"
            )

    # Single conversation representing >10% of total traffic
    for key, pkts in s['conv_packets'].most_common(5):
        pct = 100.0 * pkts / total_p
        if pct >= 10:
            src_ip, dst_ip, dport, proto = key
            flags.append(
                f"  !! Conversacion {src_ip}->{dst_ip}:{dport} ({proto}) representa "
                f"{pct:.1f}% del trafico total - conversacion dominante"
            )

    # Per-host send/receive ratio anomalies (min 100 KB total to filter noise)
    MIN_BYTES = 100_000
    for ip in s['internal_ips']:
        sent = s['src_bytes'].get(ip, 0)
        recv = s['dst_bytes'].get(ip, 0)
        if sent + recv < MIN_BYTES:
            continue
        if recv > 0 and sent / recv > 5:
            flags.append(
                f"  !! {ip}: ratio enviado/recibido = {sent/recv:.1f}x "
                f"- posible exfiltracion"
            )
        if sent > 0 and recv / sent > 10:
            flags.append(
                f"  !! {ip}: ratio recibido/enviado = {recv/sent:.1f}x "
                f"- posible descarga masiva"
            )

    lines += ["", "SENALES DE ALERTA AUTOMATICAS:"]
    if flags:
        lines += flags
    else:
        lines.append("  (ninguna alerta disparada)")

    # ─────────────────────────────────────────────────────────────────────
    text = '\n'.join(lines)

    out_dir = os.path.dirname(output_path)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(text)

    print()
    print(text)
    print()
    print(f"Guardado en {output_path}")


def main():
    parser = argparse.ArgumentParser(
        description='Generate rich plain-text summary from PCAP (dpkt)'
    )
    parser.add_argument('--input',  required=True, help='Input PCAP file')
    parser.add_argument('--output', default='data/bigflows_summary.txt', help='Output file')
    args = parser.parse_args()

    if not os.path.exists(args.input):
        print(f"Error: '{args.input}' no encontrado.")
        sys.exit(1)

    build_summary(args.input, args.output)


if __name__ == '__main__':
    main()
