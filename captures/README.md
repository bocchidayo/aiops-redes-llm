# captures/

Esta carpeta contiene capturas de tráfico real en formato `.pcap` o `.cap`.
Los archivos PCAP están en `.gitignore` - solo se versiona este README.

## bigFlows.pcap

Captura de 5 minutos de tráfico real de red privada (~368 MB).

Descarga manual:
```bash
wget https://s3.amazonaws.com/tcpreplay-pcap-files/bigFlows.pcap -P captures/
```

O deja que la Celda 11 del notebook lo descargue automáticamente.

## Generar el resumen para el LLM

```bash
pip install scapy
python data/pcap_to_csv.py --input captures/bigFlows.pcap
```

Genera `data/bigflows_summary.txt` - resumen de texto plano para el LLM.

## Capturar tu propio tráfico

```bash
sudo tcpdump -i eth0 -w captures/mi_captura.pcap -G 1800 -W 1
```
