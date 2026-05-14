#!/usr/bin/env python3
"""
Generador de tráfico de red sintético con anomalías de NetOps.

Escenarios disponibles:
  A (default) - DDoS entrante en minuto 17              (anomalia_ddos)
  B           - Degradación de red en minuto 8          (anomalia_degradacion)
  C           - Congestión + alto delay en minuto 22    (anomalia_congestion)
  D           - Consumo exagerado de ancho de banda en minuto 12  (anomalia_bandwidth)

Uso:
  python generar_trafico.py                  # escenario A → trafico_red.csv
  python generar_trafico.py --escenario B    # escenario B → trafico_escenario_b.csv
  python generar_trafico.py --escenario C    # escenario C → trafico_escenario_c.csv
  python generar_trafico.py --escenario D    # escenario D → trafico_escenario_d.csv
  python generar_trafico.py --todos          # genera los cuatro CSVs
"""

import argparse
import csv
import math
import os
import random

SEMILLA_BASE = 42
DURACION_MINUTOS = 30
DIRECTORIO = os.path.dirname(os.path.abspath(__file__))

IPS_INTERNAS = [f"10.0.{a}.{b}" for a in range(1, 4) for b in range(10, 50)]
IPS_EXTERNAS_OK = [
    "8.8.8.8", "8.8.4.4",
    "1.1.1.1", "1.0.0.1",
    "151.101.1.140",
    "104.16.0.1", "104.16.0.2",
    "13.32.0.1",
    "52.84.0.10",
    "172.217.0.1",
    "216.58.0.1",
]
PUERTOS_COMUNES = [80, 443, 53, 22, 25, 587, 993, 8080, 8443, 3306, 5432]


# ---------------------------------------------------------------------------
# Utilidades comunes
# ---------------------------------------------------------------------------

def ruido(media, desv, minimo=1):
    """Genera valor con distribución gaussiana."""
    return max(minimo, int(random.gauss(media, desv)))


def flujo_normal(minuto: int) -> dict:
    """Genera un flujo de tráfico normal."""
    hora = 8 + minuto / 60
    factor = 1.0 + 0.3 * math.sin(math.pi * (hora - 8) / 9)
    puerto = random.choice(PUERTOS_COMUNES)

    return {
        "minuto":          minuto,
        "src_ip":          random.choice(IPS_INTERNAS),
        "dst_ip":          random.choice(IPS_EXTERNAS_OK),
        "protocolo":       "UDP" if puerto == 53 else "TCP",
        "puerto":          puerto,
        "bytes":           ruido(25000 * factor, 8000, 200),
        "packets":         ruido(60 * factor, 15, 2),
        "duration_ms":     ruido(350, 120, 10),
        "latency_ms":      ruido(20, 5, 5),
        "jitter_ms":       ruido(4, 2, 1),
        "packet_loss_pct": round(max(0, random.gauss(0.3, 0.2)), 2),
        "retransmissions": ruido(1, 1, 0),
        "queue_depth":     ruido(10, 5, 0),
        "etiqueta":        "normal",
    }


# ---------------------------------------------------------------------------
# Escenario A - DDoS entrante (minuto 17)
# ---------------------------------------------------------------------------

def anomalia_a_ddos(minuto: int) -> dict:
    """Genera un flujo de ataque DDoS: spike en pps y bytes."""
    return {
        "minuto":          minuto,
        "src_ip":          random.choice(IPS_INTERNAS),
        "dst_ip":          random.choice(IPS_EXTERNAS_OK),
        "protocolo":       "TCP",
        "puerto":          random.choice([80, 443, 8080]),
        "bytes":           ruido(500000, 100000, 200000),
        "packets":         ruido(3000, 500, 1000),
        "duration_ms":     ruido(200, 50, 50),
        "latency_ms":      ruido(20, 5, 5),          # latencia normal
        "jitter_ms":       ruido(4, 2, 1),           # jitter normal
        "packet_loss_pct": ruido(8, 2, 3),           # pérdida elevada
        "retransmissions": ruido(5, 2, 2),
        "queue_depth":     ruido(90, 5, 70),         # cola profunda
        "etiqueta":        "anomalia_ddos",
    }


# ---------------------------------------------------------------------------
# Escenario B - Degradación de red (minuto 8)
# ---------------------------------------------------------------------------

def anomalia_b_degradacion(minuto: int) -> dict:
    """Genera un flujo con degradación: alta pérdida y retransmisiones."""
    return {
        "minuto":          minuto,
        "src_ip":          random.choice(IPS_INTERNAS),
        "dst_ip":          random.choice(IPS_EXTERNAS_OK),
        "protocolo":       "TCP",
        "puerto":          random.choice(PUERTOS_COMUNES),
        "bytes":           ruido(25000, 8000, 200),
        "packets":         ruido(60, 15, 2),
        "duration_ms":     ruido(350, 120, 10),
        "latency_ms":      ruido(180, 30, 100),      # latencia elevada
        "jitter_ms":       ruido(40, 10, 20),        # jitter elevado
        "packet_loss_pct": ruido(22, 5, 15),         # pérdida muy alta
        "retransmissions": ruido(45, 10, 20),        # muchas retransmisiones
        "queue_depth":     ruido(10, 5, 0),
        "etiqueta":        "anomalia_degradacion",
    }


# ---------------------------------------------------------------------------
# Escenario C - Congestión + alto delay (minuto 22)
# ---------------------------------------------------------------------------

def anomalia_c_congestion(minuto: int) -> dict:
    """Genera un flujo con congestión: latencia muy alta, jitter, cola llena."""
    return {
        "minuto":          minuto,
        "src_ip":          random.choice(IPS_INTERNAS),
        "dst_ip":          random.choice(IPS_EXTERNAS_OK),
        "protocolo":       "TCP",
        "puerto":          random.choice(PUERTOS_COMUNES),
        "bytes":           ruido(25000, 8000, 200),
        "packets":         ruido(60, 15, 2),
        "duration_ms":     ruido(350, 120, 10),
        "latency_ms":      ruido(420, 80, 300),      # latencia muy alta
        "jitter_ms":       ruido(120, 30, 60),       # jitter muy alto
        "packet_loss_pct": ruido(12, 3, 5),          # pérdida moderada
        "retransmissions": ruido(10, 3, 5),
        "queue_depth":     ruido(95, 3, 85),         # cola casi llena
        "etiqueta":        "anomalia_congestion",
    }


# ---------------------------------------------------------------------------
# Escenario D - Consumo exagerado de ancho de banda (minuto 12)
# ---------------------------------------------------------------------------

BANDWIDTH_HOG_IP = "10.0.1.77"  # Host que consume >80% del ancho de banda


def anomalia_d_bandwidth(minuto: int) -> dict:
    """Genera un flujo con consumo exagerado de bytes."""
    return {
        "minuto":          minuto,
        "src_ip":          BANDWIDTH_HOG_IP,
        "dst_ip":          random.choice(IPS_EXTERNAS_OK),
        "protocolo":       "TCP",
        "puerto":          random.choice([80, 443, 8080]),
        "bytes":           ruido(2000000, 300000, 1000000),  # bytes muy altos
        "packets":         ruido(600, 100, 200),
        "duration_ms":     ruido(500, 150, 50),
        "latency_ms":      ruido(20, 5, 5),          # latencia normal
        "jitter_ms":       ruido(4, 2, 1),           # jitter normal
        "packet_loss_pct": ruido(0.5, 0.3, 0),       # pérdida normal
        "retransmissions": ruido(1, 1, 0),
        "queue_depth":     ruido(10, 5, 0),
        "etiqueta":        "anomalia_bandwidth",
    }


# ---------------------------------------------------------------------------
# Generador principal
# ---------------------------------------------------------------------------

ARCHIVOS = {
    "A": "trafico_red.csv",
    "B": "trafico_escenario_b.csv",
    "C": "trafico_escenario_c.csv",
    "D": "trafico_escenario_d.csv",
}

COLUMNAS = [
    "id_flujo", "minuto", "src_ip", "dst_ip", "puerto",
    "protocolo", "bytes", "packets", "duration_ms",
    "latency_ms", "jitter_ms", "packet_loss_pct",
    "retransmissions", "queue_depth", "etiqueta",
]


def generar_dataset(escenario: str = "A") -> str:
    """Genera dataset de tráfico para un escenario específico."""
    random.seed(SEMILLA_BASE)
    filas = []
    id_flujo = 1

    for minuto in range(DURACION_MINUTOS):
        anomalias_minuto = []

        # --- Inyección de anomalías según escenario ---
        if escenario == "A" and minuto == 17:
            # DDoS: muchos flujos con spike en pps y bytes
            for _ in range(50):
                anomalias_minuto.append(anomalia_a_ddos(minuto))

        elif escenario == "B" and minuto == 8:
            # Degradación: alta pérdida y retransmisiones
            for _ in range(40):
                anomalias_minuto.append(anomalia_b_degradacion(minuto))

        elif escenario == "C" and minuto == 22:
            # Congestión: latencia muy alta y cola llena
            for _ in range(45):
                anomalias_minuto.append(anomalia_c_congestion(minuto))

        elif escenario == "D" and minuto == 12:
            # Consumo de ancho de banda: un host dominante
            for _ in range(35):
                anomalias_minuto.append(anomalia_d_bandwidth(minuto))

        # --- Tráfico normal del minuto ---
        # Más flujos normales en minutos con anomalía para enmascarar
        n_normal = ruido(20, 4, 8) if anomalias_minuto else ruido(13, 3, 4)
        flujos_normales = [flujo_normal(minuto) for _ in range(n_normal)]

        # Combinar y asignar IDs
        todos = anomalias_minuto + flujos_normales
        random.shuffle(todos)
        for fila in todos:
            fila["id_flujo"] = id_flujo
            filas.append(fila)
            id_flujo += 1

    archivo = os.path.join(DIRECTORIO, ARCHIVOS[escenario])
    with open(archivo, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=COLUMNAS)
        writer.writeheader()
        writer.writerows(filas)

    total = len(filas)
    anomalos = sum(1 for r in filas if r["etiqueta"] != "normal")
    print(f"[Escenario {escenario}] {archivo}")
    print(f"  Total flujos : {total}  |  Normales: {total - anomalos}  |  Anómalos: {anomalos}")
    return archivo


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Genera datasets de tráfico de red sintético con anomalías de NetOps."
    )
    parser.add_argument(
        "--escenario",
        choices=["A", "B", "C", "D"],
        default="A",
        help="Escenario a generar (default: A)",
    )
    parser.add_argument(
        "--todos",
        action="store_true",
        help="Genera los cuatro escenarios (A, B, C y D)",
    )
    args = parser.parse_args()

    if args.todos:
        for esc in ["A", "B", "C", "D"]:
            generar_dataset(esc)
    else:
        generar_dataset(args.escenario)
