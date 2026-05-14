"""Tests mínimos del generador de tráfico sintético.

Ejecutar desde la raíz del repo:
    python -m pytest data/test_generador.py -v

O directamente sin pytest:
    python data/test_generador.py
"""
import csv
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from generar_trafico import ARCHIVOS, DIRECTORIO, generar_dataset


def _leer(escenario: str) -> list[dict]:
    archivo = os.path.join(DIRECTORIO, ARCHIVOS[escenario])
    with open(archivo, encoding="utf-8") as f:
        return list(csv.DictReader(f))


def test_reproducibilidad_escenario_a():
    generar_dataset("A")
    filas1 = _leer("A")
    generar_dataset("A")
    filas2 = _leer("A")
    assert filas1 == filas2, "Dos ejecuciones con la misma semilla deberían producir CSVs idénticos"


def test_reproducibilidad_todos_los_escenarios():
    for esc in ("A", "B", "C"):
        generar_dataset(esc)
        primera = _leer(esc)
        generar_dataset(esc)
        segunda = _leer(esc)
        assert primera == segunda, f"Escenario {esc} no es reproducible"


def test_anomalia_a_en_minuto_17():
    generar_dataset("A")
    filas = _leer("A")
    anomalas = [f for f in filas if f["minuto"] == "17" and f["etiqueta"].startswith("anomalia")]
    assert len(anomalas) >= 60, "Esperaba al menos 60 flujos anómalos en el minuto 17 (escaneo + exfiltración)"
    assert any(f["etiqueta"] == "anomalia_exfiltracion" for f in anomalas)
    assert any(f["etiqueta"] == "anomalia_escaneo" for f in anomalas)


def test_columnas_esperadas():
    generar_dataset("A")
    filas = _leer("A")
    esperadas = {"id_flujo", "minuto", "src_ip", "dst_ip", "dst_puerto",
                 "protocolo", "bytes_salida", "bytes_entrada", "paquetes",
                 "duracion_ms", "etiqueta"}
    assert set(filas[0].keys()) == esperadas


if __name__ == "__main__":
    test_reproducibilidad_escenario_a()
    test_reproducibilidad_todos_los_escenarios()
    test_anomalia_a_en_minuto_17()
    test_columnas_esperadas()
    print("✅ Todos los tests pasaron")
