"""
Parser e normalizador de arquivos CSV exportados do Event Viewer.
Suporta múltiplos formatos de exportação (GUI e PowerShell).
"""

import pandas as pd
import numpy as np
from dateutil import parser as date_parser
import io
import re


# Mapeamentos de colunas para normalização
COLUMN_ALIASES = {
    "eventid": "EventID",
    "event id": "EventID",
    "id": "EventID",
    "event_id": "EventID",

    "level": "Level",
    "leveldisplayname": "Level",
    "level display name": "Level",
    "entrytype": "Level",
    "entry type": "Level",
    "type": "Level",

    "source": "Source",
    "providername": "Source",
    "provider name": "Source",
    "provider": "Source",

    "timecreated": "TimeCreated",
    "time created": "TimeCreated",
    "timegenerated": "TimeCreated",
    "time generated": "TimeCreated",
    "date and time": "TimeCreated",
    "datetime": "TimeCreated",
    "date": "TimeCreated",
    "timestamp": "TimeCreated",

    "message": "Message",
    "description": "Message",

    "computer": "Computer",
    "computername": "Computer",
    "computer name": "Computer",
    "machinename": "Computer",

    "logname": "LogName",
    "log name": "LogName",
    "log": "LogName",
    "channel": "LogName",

    "task": "TaskCategory",
    "taskcategory": "TaskCategory",
    "task category": "TaskCategory",
    "taskdisplayname": "TaskCategory",

    "userid": "UserID",
    "user id": "UserID",
    "user": "UserID",
}

LEVEL_NORMALIZATION = {
    "critical": "Critical",
    "error": "Error",
    "warning": "Warning",
    "warn": "Warning",
    "information": "Information",
    "info": "Information",
    "informational": "Information",
    "verbose": "Verbose",
    "audit success": "Information",
    "audit failure": "Error",
    "successaudit": "Information",
    "failureaudit": "Error",
}


def normalize_columns(df: pd.DataFrame) -> pd.DataFrame:
    """Normaliza os nomes das colunas para o padrão interno."""
    rename_map = {}
    for col in df.columns:
        normalized = col.strip().lower()
        if normalized in COLUMN_ALIASES:
            rename_map[col] = COLUMN_ALIASES[normalized]
    return df.rename(columns=rename_map)


def normalize_level(level_series: pd.Series) -> pd.Series:
    """Normaliza os valores da coluna Level."""
    return level_series.astype(str).str.strip().str.lower().map(
        lambda x: LEVEL_NORMALIZATION.get(x, x.title() if x != "nan" else "Unknown")
    )


def parse_datetime(dt_series: pd.Series) -> pd.Series:
    """Tenta converter a coluna de data/hora para datetime."""
    def safe_parse(val):
        if pd.isna(val) or str(val).strip() in ("", "nan", "NaT"):
            return pd.NaT
        try:
            return date_parser.parse(str(val), dayfirst=False)
        except Exception:
            return pd.NaT

    try:
        result = pd.to_datetime(dt_series, infer_datetime_format=True, errors="coerce")
        if result.isna().sum() > len(dt_series) * 0.5:
            result = dt_series.apply(safe_parse)
        return result
    except Exception:
        return dt_series.apply(safe_parse)


def parse_event_id(eid_series: pd.Series) -> pd.Series:
    """Converte EventID para inteiro, tratando valores inválidos."""
    def extract_id(val):
        if pd.isna(val):
            return np.nan
        s = str(val).strip()
        match = re.search(r"\d+", s)
        return int(match.group()) if match else np.nan

    return eid_series.apply(extract_id)


def load_csv(file_obj) -> tuple[pd.DataFrame | None, str]:
    """
    Carrega e normaliza um arquivo CSV do Event Viewer.
    Retorna (DataFrame normalizado, mensagem de status).
    """
    try:
        # Detecta encoding e separador
        raw = file_obj.read()
        file_obj.seek(0)

        # Tenta diferentes encodings
        for encoding in ("utf-8-sig", "utf-8", "latin-1", "cp1252"):
            try:
                content = raw.decode(encoding)
                break
            except UnicodeDecodeError:
                continue
        else:
            return None, "Erro: Não foi possível decodificar o arquivo. Tente salvar como UTF-8."

        # Detecta separador
        first_line = content.split("\n")[0]
        sep = ";" if first_line.count(";") > first_line.count(",") else ","

        df = pd.read_csv(
            io.StringIO(content),
            sep=sep,
            dtype=str,
            on_bad_lines="skip",
            encoding_errors="replace",
        )

        if df.empty:
            return None, "Arquivo CSV está vazio ou sem dados válidos."

        # Normaliza colunas
        df = normalize_columns(df)

        # Garante colunas mínimas
        required = ["EventID", "Level", "Source", "TimeCreated"]
        missing = [c for c in required if c not in df.columns]
        if missing:
            available = ", ".join(df.columns.tolist())
            return None, (
                f"Colunas obrigatórias não encontradas: {', '.join(missing)}.\n"
                f"Colunas disponíveis no arquivo: {available}\n\n"
                f"Use o script PowerShell fornecido para exportar no formato correto."
            )

        # Normaliza tipos
        df["EventID"] = parse_event_id(df["EventID"])
        df["Level"] = normalize_level(df["Level"])
        df["TimeCreated"] = parse_datetime(df["TimeCreated"])

        # Preenche colunas opcionais ausentes
        for col in ["Message", "Computer", "LogName", "TaskCategory", "UserID"]:
            if col not in df.columns:
                df[col] = "N/A"

        # Remove linhas sem EventID
        df = df.dropna(subset=["EventID"])
        df["EventID"] = df["EventID"].astype(int)

        # Ordena por data
        df = df.sort_values("TimeCreated", ascending=False).reset_index(drop=True)

        total = len(df)
        return df, f"Arquivo carregado com sucesso: {total:,} eventos encontrados."

    except Exception as e:
        return None, f"Erro ao processar o arquivo: {str(e)}"
