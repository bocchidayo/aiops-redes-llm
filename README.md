<div align="center">

# AIOps en Redes: Automatización Inteligente con LLMs

Workshop de ~45 minutos · Universidad Tecnológica de Panamá

**Eduardo Chong** - Cisco Network Academy UTP

<br>

[![Open in Colab](https://colab.research.google.com/assets/colab-badge.svg)](https://colab.research.google.com/github/bocchidayo/aiops-redes-llm/blob/main/notebook/aiops_workshop.ipynb)
![Python](https://img.shields.io/badge/Python-3.10+-blue?logo=python&logoColor=white)
![Model](https://img.shields.io/badge/LLM-Qwen2.5--1.5B-orange?logo=huggingface&logoColor=white)
![Platform](https://img.shields.io/badge/Plataforma-Google%20Colab%20T4-F9AB00?logo=googlecolab&logoColor=white)
[![License: CC BY 4.0](https://img.shields.io/badge/Licencia-CC%20BY%204.0-lightgrey?logo=creativecommons&logoColor=white)](https://creativecommons.org/licenses/by/4.0/)

<br>

**Requisito único:** cuenta de Google · GPU T4 gratis incluida en Colab

</div>

---

## Instrucciones

Abre el notebook en Colab y activa la GPU T4 antes de empezar:  
**Entorno de ejecución → Cambiar tipo de entorno → T4 GPU**

### Paso 1 - Instalar y cargar datos (celdas 1–3, ~5 min)

Ejecuta las primeras tres celdas. La celda 3 descarga automáticamente el dataset de tráfico desde este repositorio.

### Paso 2 - Alertas y visualización (celdas 4–5, ~10 min)

La celda 4 detecta condiciones anómalas automáticamente (alto delay, pérdida de paquetes, congestión, consumo excesivo de ancho de banda) **antes** de mostrar cualquier gráfica. La celda 5 genera un dashboard con cuatro métricas operacionales.

### Paso 3 - Análisis estadístico y diagnóstico con LLM (celdas 6–8, ~15 min)

La celda 6 compara baseline vs ventana de anomalía. La celda 7 carga Qwen2.5-1.5B localmente y genera un diagnóstico NOC. La primera ejecución descarga ~3 GB del modelo - es normal que tarde 3–5 minutos.

### Paso 4 - Challenge con tráfico real (celdas 11–14, opcional)

La celda 11 carga automáticamente el resumen de bigFlows.pcap desde el repositorio. La celda 13 abre un chat libre con el modelo donde puedes hacer preguntas sobre el tráfico real.

---

## Estructura del repositorio

```
.
├── notebook/
│   └── aiops_workshop.ipynb       Notebook del workshop - Google Colab T4
├── demo.py                        Captura en vivo + reporte NOC con LLM (standalone)
├── data/
│   ├── generar_trafico.py         Generador de datasets sintéticos (4 escenarios, semilla fija)
│   ├── pcap_to_csv.py             Genera resumen de texto plano desde .pcap (dpkt)
│   ├── bigflows_summary.txt       Resumen pre-generado de bigFlows.pcap
│   ├── trafico_red.csv            Dataset escenario A: DDoS entrante (minuto 17)
│   ├── trafico_escenario_b.csv    Dataset escenario B: Degradación de red (minuto 8)
│   ├── trafico_escenario_c.csv    Dataset escenario C: Congestión + alto delay (minuto 22)
│   └── trafico_escenario_d.csv    Dataset escenario D: Consumo exagerado de BW (minuto 12)
└── captures/
    └── README.md                  Instrucciones para capturas PCAP propias
```

---

## Dataset

Flujos de red sintéticos que simulan 30 minutos de tráfico en una red corporativa ficticia. Cada escenario oculta un problema operacional diferente.

| Columna | Descripción |
|---|---|
| `minuto` | Ventana temporal (0–29) |
| `src_ip` / `dst_ip` | IP de origen y destino |
| `puerto` | Puerto de destino |
| `protocolo` | TCP o UDP |
| `bytes` / `packets` | Volumen y cantidad de paquetes del flujo |
| `duration_ms` | Duración total del flujo en milisegundos |
| `latency_ms` | Latencia estimada del flujo |
| `jitter_ms` | Variación de latencia |
| `packet_loss_pct` | Porcentaje de pérdida de paquetes |
| `retransmissions` | Número de retransmisiones TCP |
| `queue_depth` | Profundidad de la cola (0–100) |

Para regenerar los datasets:

```bash
python data/generar_trafico.py               # escenario A (default)
python data/generar_trafico.py --escenario B
python data/generar_trafico.py --escenario C
python data/generar_trafico.py --escenario D
python data/generar_trafico.py --todos       # genera los cuatro
```

### Variantes de escenario

| Escenario | Problema operacional | Minuto |
|---|---|---|
| A (default) | DDoS entrante - spike en pps y bytes, cola llena | 17 |
| B | Degradación de red - packet loss >15%, retransmisiones altas | 8 |
| C | Congestión + alto delay - latencia >300 ms, jitter alto | 22 |
| D | Consumo exagerado de BW - un solo host consume >80% del uplink | 12 |

---

## Challenge PCAP

La sección opcional (celdas 11–14) permite analizar tráfico real en lugar del dataset sintético.

La **celda 11** carga el resumen de bigFlows.pcap directamente desde el repositorio - sin descargas adicionales. Si quieres usar tu propia captura:

```bash
pip install dpkt
python data/pcap_to_csv.py --input captures/mi_captura.pcap
```

### Capturar tu propio tráfico

```bash
sudo tcpdump -i eth0 -w captures/mi_captura.pcap -G 1800 -W 1
```

---

## demo.py - captura en vivo

Script independiente que captura tráfico en tiempo real y genera un reporte NOC con un LLM.

```bash
# Dependencias
python3 -m venv .venv
source .venv/bin/activate
pip install dpkt torch --index-url https://download.pytorch.org/whl/cpu
pip install transformers accelerate numpy

# Uso básico (eth0, 1 minuto, Qwen2.5-1.5B local)
sudo -E .venv/bin/python3 demo.py

# Opciones
sudo -E .venv/bin/python3 demo.py -i wlan0 -m 5
sudo -E .venv/bin/python3 demo.py --model openai/qwen2.5-1.5b-instruct --endpoint http://localhost:8000/v1
sudo -E .venv/bin/python3 demo.py --model ollama/qwen2.5:1.5b
sudo -E .venv/bin/python3 demo.py --keep-pcap
```

Los resultados se guardan en `demo/captures/` (resumen de tráfico) y `demo/reports/` (reporte del LLM), ambos nombrados con timestamp.

---

## Si algo falla

**El modelo no carga en Colab**  
Verifica que la GPU esté activa antes de ejecutar la celda 7. En Colab: *Entorno de ejecución → Ver recursos*. Si `torch.cuda.is_available()` devuelve `False`, reconecta la sesión y confirma que el tipo de entorno es T4.

**El dataset no descarga**  
El notebook apunta al branch `main`. Si trabajas desde un fork o branch distinto, actualiza la variable `URL_DATOS` en la celda 3 con la URL raw correcta de tu repositorio.

---

*Workshop AIOps en Redes - Panamá*
