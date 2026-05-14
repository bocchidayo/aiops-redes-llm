#!/usr/bin/env python3
"""
demo.py - captura trafico en vivo y genera un reporte NOC con un LLM

Uso basico:
    sudo python demo.py                            # Qwen2.5-1.5B local, eth0, 1 min
    sudo python demo.py -i wlan0 -m 2
    sudo python demo.py --model openai/qwen2.5-1.5b-instruct \\
                        --endpoint http://localhost:8000/v1
    sudo python demo.py --model ollama/qwen2.5:1.5b

Salida:
    demo/captures/TIMESTAMP.txt   resumen de trafico (dpkt)
    demo/reports/TIMESTAMP.txt    reporte NOC (LLM)
"""

import argparse
import datetime
import os
import signal
import subprocess
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

try:
    import dpkt
except ImportError:
    sys.exit('Dependencia faltante: pip install dpkt')


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

SYSTEM_PROMPT = (
    "Eres un ingeniero de NOC con experiencia en analisis de rendimiento de redes, "
    "SLA y resolucion de incidencias. Responde siempre en espanol. "
    "Se tecnico, conciso y orientado a la accion."
)

USER_TEMPLATE = """\
Analiza este resumen de trafico de red capturado en tiempo real.
Determina si hay comportamiento anomalo o destacable e indica:

1. Diagnostico: hay trafico inusual? que protocolo, host o puerto llama la atencion?
2. Clasificacion: trafico normal / congestion / posible exfiltracion / escaneo de puertos?
3. Host de interes: que IP o segmento deberia investigarse?
4. Accion recomendada: que debe hacer el equipo ahora mismo?

--- DATOS ---
{summary}
--- FIN ---

Justifica con numeros concretos del resumen.
"""


def is_rfc1918(ip):
    parts = ip.split('.')
    if len(parts) != 4:
        return False
    try:
        a, b = int(parts[0]), int(parts[1])
    except ValueError:
        return False
    return (a == 10) or (a == 172 and 16 <= b <= 31) or (a == 192 and b == 168)


def fmt_bytes(b):
    if b < 1e6:
        return f'{b / 1e3:.1f} KB'
    if b < 1e9:
        return f'{b / 1e6:.1f} MB'
    return f'{b / 1e9:.1f} GB'


def fmt_dur(s):
    s = int(s)
    if s < 60:
        return f'{s}s'
    m, sec = divmod(s, 60)
    return f'{m}m {sec}s'


def fmt_offset(s):
    m, sec = divmod(int(s), 60)
    return f'+{m}m{sec:02d}s'


def run_capture(interface, minutes, pcap_path):
    cmd = ['tcpdump', '-i', interface, '-w', str(pcap_path), '-nn', '-q']
    if os.name != 'nt' and os.geteuid() != 0:
        cmd = ['sudo'] + cmd

    print(f'Capturando en {interface} durante {minutes} min ...')
    print('(Ctrl+C para detener antes)\n')

    proc = subprocess.Popen(cmd, stderr=subprocess.DEVNULL)

    try:
        for elapsed in range(minutes * 60):
            time.sleep(1)
            remaining = minutes * 60 - elapsed - 1
            if remaining > 0 and remaining % 30 == 0:
                print(f'  {remaining}s restantes ...')
    except KeyboardInterrupt:
        print('\nCaptura interrumpida.')
    finally:
        proc.send_signal(signal.SIGTERM)
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()

    if not pcap_path.exists() or pcap_path.stat().st_size == 0:
        print(f'Error: {pcap_path} no existe o esta vacio.')
        print('Verifica que la interfaz sea correcta y que tienes permisos (root/sudo).')
        return False

    print(f'Captura completa - {pcap_path.stat().st_size / 1e6:.1f} MB\n')
    return True


def analyze_pcap(pcap_path):
    WINDOW = 30
    protocol_counts  = Counter()
    src_bytes        = defaultdict(int)
    dst_bytes        = defaultdict(int)
    window_buckets   = Counter()
    conv_packets     = Counter()
    conv_bytes       = defaultdict(int)
    conv_first       = {}
    conv_last        = {}
    port_packets     = Counter()
    port_proto       = {}
    port_src_pkts    = defaultdict(Counter)
    port_dst_pkts    = defaultdict(Counter)
    host_dst_ips     = defaultdict(set)
    host_dst_ports   = defaultdict(Counter)
    host_dst_ip_bytes = defaultdict(Counter)
    host_proto       = defaultdict(Counter)
    int_ext_sent     = 0
    ext_int_recv     = 0
    internal_ips     = set()
    external_ips     = set()
    total_packets    = 0
    total_bytes      = 0
    start_time       = None
    end_time         = None

    with open(pcap_path, 'rb') as f:
        for ts, buf in dpkt.pcap.Reader(f):
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
                ip_pkt  = eth.data
                src     = dpkt.utils.inet_to_str(ip_pkt.src)
                dst     = dpkt.utils.inet_to_str(ip_pkt.dst)

                src_bytes[src] += pkt_len
                dst_bytes[dst] += pkt_len

                src_int = is_rfc1918(src)
                dst_int = is_rfc1918(dst)

                (internal_ips if src_int else external_ips).add(src)
                (internal_ips if dst_int else external_ips).add(dst)

                if src_int and not dst_int:
                    int_ext_sent += pkt_len
                elif not src_int and dst_int:
                    ext_int_recv += pkt_len

                proto_str = 'Other'
                dport     = None
                if isinstance(ip_pkt.data, dpkt.tcp.TCP):
                    proto_str, dport = 'TCP', ip_pkt.data.dport
                elif isinstance(ip_pkt.data, dpkt.udp.UDP):
                    proto_str, dport = 'UDP', ip_pkt.data.dport
                elif isinstance(ip_pkt.data, dpkt.icmp.ICMP):
                    proto_str = 'ICMP'

                protocol_counts[proto_str] += 1

                if dport is not None:
                    key = (src, dst, dport, proto_str)
                    conv_packets[key]  += 1
                    conv_bytes[key]    += pkt_len
                    conv_first.setdefault(key, ts)
                    conv_last[key]      = ts

                    port_packets[dport] += 1
                    port_proto.setdefault(dport, proto_str)
                    port_src_pkts[dport][src] += 1
                    port_dst_pkts[dport][dst] += 1

                    if src_int:
                        host_dst_ips[src].add(dst)
                        host_dst_ports[src][dport]    += 1
                        host_dst_ip_bytes[src][dst]   += pkt_len
                        host_proto[src][proto_str]    += 1
            except Exception:
                continue

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


def build_summary(s, capture_ts):
    if s['start_time'] is None:
        return 'Sin paquetes IP capturados.'

    dur      = s['end_time'] - s['start_time']
    avg_pkt  = s['total_bytes'] / s['total_packets'] if s['total_packets'] else 0
    pct_base = sum(s['protocol_counts'].values())
    total_p  = s['total_packets']
    lines    = []

    lines += [
        f'=== CAPTURA DE RED - {capture_ts} ===',
        f'Duracion        : {fmt_dur(dur)}',
        f'Paquetes totales: {total_p:,}',
        f'Bytes totales   : {fmt_bytes(s["total_bytes"])}',
        f'Tamano medio pkt: {int(avg_pkt)} bytes',
        f'Flujos unicos   : {len(s["conv_packets"]):,}',
    ]

    lines += ['', 'PROTOCOLOS:']
    for proto in ('TCP', 'UDP', 'ICMP', 'Other'):
        cnt = s['protocol_counts'].get(proto, 0)
        pct = 100.0 * cnt / pct_base if pct_base else 0
        lines.append(f'  {proto:6s}: {cnt:8,} paquetes ({pct:5.1f}%)')

    int_sent  = s['int_ext_sent']
    ext_recv  = s['ext_int_recv']
    ratio_ie  = ext_recv / int_sent if int_sent > 0 else 0.0
    if ratio_ie > 3:
        ratio_nota = '>3x = red receptora'
    elif ratio_ie < 0.5:
        ratio_nota = '<0.5x = emisora inusual'
    else:
        ratio_nota = 'normal'

    lines += [
        '',
        f'IPs INTERNAS : {len(s["internal_ips"])} hosts',
        f'  Enviado    : {fmt_bytes(int_sent)} (interno -> externo)',
        f'  Recibido   : {fmt_bytes(ext_recv)} (externo -> interno)',
        f'  Ratio      : {ratio_ie:.1f}x - {ratio_nota}',
        f'IPs EXTERNAS : {len(s["external_ips"])} hosts',
    ]

    lines += ['', 'TOP 10 CONVERSACIONES:']
    for rank, (key, pkts) in enumerate(s['conv_packets'].most_common(10), 1):
        src_ip, dst_ip, dport, proto = key
        b      = s['conv_bytes'][key]
        first  = s['conv_first'].get(key, 0)
        last   = s['conv_last'].get(key, 0)
        pct    = 100.0 * pkts / total_p
        src_t  = 'INT' if is_rfc1918(src_ip) else 'EXT'
        dst_t  = 'INT' if is_rfc1918(dst_ip) else 'EXT'
        pname  = PORT_NAMES.get(dport, '')
        plabel = f'{dport}/{pname}' if pname else str(dport)
        avg_sz = b // pkts if pkts else 0
        lines.append(
            f'  {rank:2d}. [{src_t}]{src_ip} -> [{dst_t}]{dst_ip}:{plabel} ({proto})'
        )
        lines.append(
            f'      {pkts:,} pkts ({pct:.1f}%) | {fmt_bytes(b)} | '
            f'dur {fmt_dur(last - first)} | avg {avg_sz}B'
        )

    top15       = s['port_packets'].most_common(15)
    nonstandard = [(p, c) for p, c in top15 if p not in STANDARD_PORTS]
    if nonstandard:
        lines += ['', 'PUERTOS NO ESTANDAR (top 15):']
        for port, cnt in nonstandard:
            proto    = s['port_proto'].get(port, '?')
            src_ctr  = s['port_src_pkts'].get(port, Counter())
            dst_ctr  = s['port_dst_pkts'].get(port, Counter())
            top2_src = src_ctr.most_common(2)
            top2_dst = [ip for ip, _ in dst_ctr.most_common(2)]
            lines.append(f'  {port} | {proto} | {cnt:,} pkts | INUSUAL')
            lines.append(f'    Orig: {", ".join(f"{ip}({c:,})" for ip, c in top2_src)}')
            lines.append(f'    Dest: {", ".join(top2_dst)}')

    WINDOW     = 30
    sorted_win = sorted(s['window_buckets'].items(), key=lambda x: -x[1])
    if sorted_win:
        lines += ['', 'VENTANAS DE 30s (top 3 + quietest):']
        for bucket, cnt in sorted_win[:3]:
            s_off = bucket * WINDOW
            lines.append(f'  {fmt_offset(s_off)}->{fmt_offset(s_off + WINDOW)} | {cnt:,} pkts')
        q_b, q_c = sorted_win[-1]
        lines.append(f'  Quietest: {fmt_offset(q_b * WINDOW)} | {q_c:,} pkts')
        if sorted_win[0][1] > 0 and q_c > 0:
            lines.append(f'  Pico/valle: {sorted_win[0][1] / q_c:.1f}x')

    flags = []
    for ip in s['internal_ips']:
        mb = s['src_bytes'].get(ip, 0) / 1e6
        if mb > 15:
            flags.append(f'  !! {ip} envio {mb:.1f} MB - supera umbral 15 MB')

    for port, cnt in s['port_packets'].most_common():
        if cnt < 50_000:
            break
        if port not in STANDARD_PORTS:
            flags.append(f'  !! Puerto {port}: {cnt:,} pkts no estandar con alto volumen')

    for key, pkts in s['conv_packets'].most_common(3):
        pct = 100.0 * pkts / total_p
        if pct >= 10:
            src_ip, dst_ip, dport, proto = key
            flags.append(f'  !! {src_ip}->{dst_ip}:{dport} = {pct:.1f}% del trafico total')

    MIN_BYTES = 100_000
    for ip in s['internal_ips']:
        sent = s['src_bytes'].get(ip, 0)
        recv = s['dst_bytes'].get(ip, 0)
        if sent + recv < MIN_BYTES:
            continue
        if recv > 0 and sent / recv > 5:
            flags.append(f'  !! {ip}: sent/recv={sent/recv:.1f}x - posible exfiltracion')
        if sent > 0 and recv / sent > 10:
            flags.append(f'  !! {ip}: recv/sent={recv/sent:.1f}x - posible descarga masiva')

    lines += ['', 'ALERTAS:']
    lines += flags if flags else ['  ninguna']

    return '\n'.join(lines)


def call_local_llm(summary):
    try:
        import torch
        from transformers import AutoModelForCausalLM, AutoTokenizer, pipeline
    except ImportError:
        sys.exit('Dependencias faltantes: pip install torch transformers accelerate')

    MODEL_ID  = 'Qwen/Qwen2.5-1.5B-Instruct'
    dtype     = torch.float16 if torch.cuda.is_available() else torch.float32
    tokenizer = AutoTokenizer.from_pretrained(MODEL_ID)
    model     = AutoModelForCausalLM.from_pretrained(MODEL_ID, torch_dtype=dtype, device_map='auto')
    pipe      = pipeline('text-generation', model=model, tokenizer=tokenizer)

    result = pipe(
        [
            {'role': 'system', 'content': SYSTEM_PROMPT},
            {'role': 'user',   'content': USER_TEMPLATE.format(summary=summary)},
        ],
        max_new_tokens=1500,
        temperature=0.3,
        do_sample=True,
        pad_token_id=tokenizer.eos_token_id,
    )
    return result[0]['generated_text'][-1]['content']


def call_external_llm(summary, model, base_url, api_key):
    try:
        import litellm
    except ImportError:
        sys.exit('Dependencia faltante: pip install litellm')

    litellm.suppress_debug_info = True

    kwargs = dict(
        model=model,
        messages=[
            {'role': 'system', 'content': SYSTEM_PROMPT},
            {'role': 'user',   'content': USER_TEMPLATE.format(summary=summary)},
        ],
        max_tokens=1500,
        temperature=0.3,
    )
    if base_url:
        kwargs['api_base'] = base_url
    if api_key:
        kwargs['api_key'] = api_key

    resp = litellm.completion(**kwargs)
    return resp.choices[0].message.content


def main():
    parser = argparse.ArgumentParser(
        description='Captura trafico de red y genera un reporte NOC con un LLM.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  sudo python demo.py
  sudo python demo.py -i wlan0 -m 2
  sudo python demo.py --model openai/qwen2.5-1.5b-instruct --endpoint http://localhost:8000/v1
  sudo python demo.py --model ollama/qwen2.5:1.5b
  sudo python demo.py --keep-pcap
        """,
    )
    parser.add_argument('-i', '--interface',  default='eth0',
                        help='Interfaz de red (default: eth0)')
    parser.add_argument('-m', '--minutes',    type=int, default=1,
                        help='Duracion de la captura en minutos (default: 1)')
    parser.add_argument('--model',            default=None,
                        help='Modelo LiteLLM, ej: openai/qwen2.5-1.5b | ollama/qwen2.5:1.5b')
    parser.add_argument('--endpoint',         default=None,
                        help='URL base del endpoint OpenAI-compatible, ej: http://localhost:8000/v1')
    parser.add_argument('--api-key',          default='none',
                        help='API key del endpoint (default: none)')
    parser.add_argument('--output-dir',       default='demo',
                        help='Carpeta raiz de salida (default: demo)')
    parser.add_argument('--keep-pcap',        action='store_true',
                        help='Conservar el .pcap crudo despues del analisis')
    args = parser.parse_args()

    base_dir     = Path(args.output_dir)
    captures_dir = base_dir / 'captures'
    reports_dir  = base_dir / 'reports'
    pcap_dir     = base_dir / 'pcap'

    for d in (captures_dir, reports_dir, pcap_dir):
        d.mkdir(parents=True, exist_ok=True)

    ts         = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    pcap_path  = pcap_dir     / f'{ts}.pcap'
    cap_path   = captures_dir / f'{ts}.txt'
    rep_path   = reports_dir  / f'{ts}.txt'

    use_external = bool(args.model or args.endpoint)
    llm_label    = args.model if args.model else 'Qwen/Qwen2.5-1.5B-Instruct (local)'

    print('=' * 52)
    print(' Demo AIOps NOC')
    print('=' * 52)
    print(f'  Timestamp : {ts}')
    print(f'  Interfaz  : {args.interface}')
    print(f'  Duracion  : {args.minutes} min')
    print(f'  LLM       : {llm_label}')
    if args.endpoint:
        print(f'  Endpoint  : {args.endpoint}')
    print(f'  Salida    : {base_dir}/')
    print('=' * 52)
    print()

    if not run_capture(args.interface, args.minutes, pcap_path):
        sys.exit(1)

    print('Analizando con dpkt ...')
    stats = analyze_pcap(pcap_path)

    if stats['total_packets'] == 0:
        print('La captura no contiene paquetes IP validos.')
        sys.exit(1)

    summary = build_summary(stats, ts)
    cap_path.write_text(summary, encoding='utf-8')
    print(f'Resumen guardado -> {cap_path}\n')
    print(summary)
    print()

    print('Generando reporte NOC ...')
    t0 = time.time()

    if use_external:
        model_str = args.model or 'openai/qwen2.5-1.5b-instruct'
        if args.endpoint and '/' not in model_str:
            model_str = 'openai/' + model_str
        report_text = call_external_llm(summary, model_str, args.endpoint, args.api_key)
    else:
        report_text = call_local_llm(summary)

    elapsed = time.time() - t0
    ts_full = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    rep_content = '\n'.join([
        f'=== REPORTE NOC - {ts_full} ===',
        f'Modelo    : {llm_label}',
        f'Captura   : {cap_path.name}',
        f'Tiempo    : {elapsed:.1f}s',
        '',
        report_text,
    ])

    rep_path.write_text(rep_content, encoding='utf-8')
    print(f'\nReporte guardado -> {rep_path}\n')
    print(rep_content)

    if not args.keep_pcap:
        pcap_path.unlink(missing_ok=True)
        try:
            pcap_dir.rmdir()
        except OSError:
            pass

    print('\n' + '=' * 52)
    print(f'  captures/{ts}.txt')
    print(f'  reports/{ts}.txt')
    print('=' * 52)


if __name__ == '__main__':
    main()
