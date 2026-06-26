"""
Motor de análise e diagnóstico de logs do Windows Server.
Detecta padrões, anomalias e gera recomendações.
"""

import pandas as pd
import numpy as np
from datetime import timedelta
from modules.knowledge_base import KNOWLEDGE_BASE, SEVERITY_ORDER


def get_summary_stats(df: pd.DataFrame) -> dict:
    """Gera estatísticas resumidas do dataset."""
    stats = {
        "total_events": len(df),
        "critical_count": len(df[df["Level"] == "Critical"]),
        "error_count": len(df[df["Level"] == "Error"]),
        "warning_count": len(df[df["Level"] == "Warning"]),
        "info_count": len(df[df["Level"] == "Information"]),
        "unique_sources": df["Source"].nunique(),
        "unique_event_ids": df["EventID"].nunique(),
        "date_range_start": df["TimeCreated"].min(),
        "date_range_end": df["TimeCreated"].max(),
        "computers": df["Computer"].unique().tolist() if "Computer" in df.columns else [],
    }
    return stats


def detect_brute_force(df: pd.DataFrame, threshold: int = 10, window_minutes: int = 5) -> list[dict]:
    """Detecta possíveis ataques de força bruta (Event ID 4625)."""
    incidents = []
    failed_logins = df[df["EventID"] == 4625].copy()

    if failed_logins.empty or failed_logins["TimeCreated"].isna().all():
        return incidents

    failed_logins = failed_logins.dropna(subset=["TimeCreated"]).sort_values("TimeCreated")

    # Janela deslizante
    for i in range(len(failed_logins)):
        window_start = failed_logins.iloc[i]["TimeCreated"]
        window_end = window_start + timedelta(minutes=window_minutes)
        count = len(failed_logins[
            (failed_logins["TimeCreated"] >= window_start) &
            (failed_logins["TimeCreated"] <= window_end)
        ])
        if count >= threshold:
            incidents.append({
                "type": "Brute Force Detectado",
                "severity": "Critical",
                "time": window_start,
                "detail": f"{count} falhas de logon (Event 4625) em {window_minutes} minutos.",
                "recommendation": "Bloqueie o IP de origem e revise a política de lockout de conta.",
                "event_ids": [4625],
            })
            break  # Evita duplicatas

    return incidents


def detect_service_crashes(df: pd.DataFrame, threshold: int = 3) -> list[dict]:
    """Detecta serviços que falharam múltiplas vezes."""
    incidents = []
    service_events = df[df["EventID"].isin([7034, 7031])].copy()

    if service_events.empty:
        return incidents

    counts = service_events.groupby("Source").size()
    for source, count in counts.items():
        if count >= threshold:
            incidents.append({
                "type": "Serviço Instável",
                "severity": "Error",
                "time": service_events[service_events["Source"] == source]["TimeCreated"].max(),
                "detail": f"Serviço '{source}' falhou {count} vezes.",
                "recommendation": "Configure recuperação automática e investigue a causa raiz.",
                "event_ids": [7034, 7031],
            })

    return incidents


def detect_unexpected_reboots(df: pd.DataFrame) -> list[dict]:
    """Detecta reinicializações inesperadas."""
    incidents = []
    reboot_events = df[df["EventID"].isin([41, 6008, 1001])].copy()

    if reboot_events.empty:
        return incidents

    for _, row in reboot_events.iterrows():
        incidents.append({
            "type": "Reinicialização Inesperada",
            "severity": "Critical",
            "time": row["TimeCreated"],
            "detail": f"Event ID {int(row['EventID'])} detectado: {KNOWLEDGE_BASE.get(int(row['EventID']), {}).get('title', 'Evento crítico de sistema')}",
            "recommendation": "Analise dumps de memória e verifique hardware.",
            "event_ids": [41, 6008, 1001],
        })

    return incidents[:10]  # Limita a 10 ocorrências


def detect_privilege_escalation(df: pd.DataFrame) -> list[dict]:
    """Detecta possível escalação de privilégios."""
    incidents = []
    priv_events = df[df["EventID"].isin([4732, 4728, 4756])].copy()

    if priv_events.empty:
        return incidents

    for _, row in priv_events.iterrows():
        incidents.append({
            "type": "Escalação de Privilégio",
            "severity": "Critical",
            "time": row["TimeCreated"],
            "detail": f"Event ID {int(row['EventID'])}: Usuário adicionado a grupo privilegiado.",
            "recommendation": "Verifique imediatamente se a alteração foi autorizada.",
            "event_ids": [4732, 4728, 4756],
        })

    return incidents[:10]


def detect_disk_errors(df: pd.DataFrame) -> list[dict]:
    """Detecta erros de disco."""
    incidents = []
    disk_events = df[df["EventID"].isin([7, 51, 11, 15])].copy()

    if disk_events.empty:
        return incidents

    count = len(disk_events)
    if count > 0:
        incidents.append({
            "type": "Erros de Disco Detectados",
            "severity": "Error" if count < 5 else "Critical",
            "time": disk_events["TimeCreated"].max(),
            "detail": f"{count} erro(s) de disco/I/O detectados.",
            "recommendation": "Execute chkdsk e verifique S.M.A.R.T. do disco imediatamente.",
            "event_ids": [7, 51, 11, 15],
        })

    return incidents


def run_full_analysis(df: pd.DataFrame) -> list[dict]:
    """Executa todas as análises e retorna lista consolidada de incidentes."""
    all_incidents = []
    all_incidents.extend(detect_unexpected_reboots(df))
    all_incidents.extend(detect_privilege_escalation(df))
    all_incidents.extend(detect_brute_force(df))
    all_incidents.extend(detect_service_crashes(df))
    all_incidents.extend(detect_disk_errors(df))

    # Ordena por severidade
    severity_map = {"Critical": 0, "Error": 1, "Warning": 2, "Information": 3}
    all_incidents.sort(key=lambda x: severity_map.get(x["severity"], 99))

    return all_incidents


def get_top_event_ids(df: pd.DataFrame, top_n: int = 10) -> pd.DataFrame:
    """Retorna os Event IDs mais frequentes com descrição."""
    counts = df.groupby("EventID").size().reset_index(name="Count")
    counts = counts.sort_values("Count", ascending=False).head(top_n)
    counts["EventID"] = counts["EventID"].astype(int)
    counts["Title"] = counts["EventID"].map(
        lambda eid: KNOWLEDGE_BASE.get(eid, {}).get("title", "Evento não catalogado")
    )
    counts["Category"] = counts["EventID"].map(
        lambda eid: KNOWLEDGE_BASE.get(eid, {}).get("category", "Desconhecido")
    )
    counts["Severity"] = counts["EventID"].map(
        lambda eid: KNOWLEDGE_BASE.get(eid, {}).get("severity", "Unknown")
    )
    return counts


def get_timeline_data(df: pd.DataFrame) -> pd.DataFrame:
    """Prepara dados para gráfico de timeline por hora."""
    timeline = df.dropna(subset=["TimeCreated"]).copy()
    timeline["Hour"] = timeline["TimeCreated"].dt.floor("H")
    grouped = timeline.groupby(["Hour", "Level"]).size().reset_index(name="Count")
    return grouped


def get_knowledge_for_event(event_id: int) -> dict | None:
    """Retorna informações da base de conhecimento para um Event ID."""
    return KNOWLEDGE_BASE.get(event_id)
