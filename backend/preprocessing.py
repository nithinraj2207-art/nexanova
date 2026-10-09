"""
CyberDNA - Data Preprocessing Module
Validates CSV inputs, parses and cleans security events, handles missing data,
and prepares structured event streams for behavioral analysis.
"""

import pandas as pd
import numpy as np
import io
import re
from datetime import datetime
from typing import Tuple, List, Dict, Any, Optional

REQUIRED_COLUMNS = [
    "timestamp",
    "user",
    "source_ip",
    "destination_ip",
    "event_type",
    "severity",
    "resource",
    "status"
]

VALID_SEVERITIES = ["Low", "Medium", "High", "Critical", "Informational"]


class PreprocessingError(Exception):
    """User-friendly exception for data preprocessing & CSV validation errors."""
    pass


def validate_and_load_csv(file_content: bytes | str) -> pd.DataFrame:
    """
    Validates CSV columns and structure.
    Returns cleaned pandas DataFrame or raises PreprocessingError with friendly message.
    """
    if isinstance(file_content, bytes):
        try:
            # Try utf-8 first, fallback to latin-1
            text = file_content.decode("utf-8")
        except UnicodeDecodeError:
            try:
                text = file_content.decode("latin-1")
            except Exception:
                raise PreprocessingError("Invalid file encoding. Please provide a UTF-8 encoded CSV file.")
    else:
        text = str(file_content)

    if not text.strip():
        raise PreprocessingError("The uploaded CSV file is empty. Please provide a valid security log file.")

    try:
        df = pd.read_csv(io.StringIO(text))
    except Exception as e:
        raise PreprocessingError(f"Unable to parse CSV data: {str(e)}. Please check file formatting.")

    if df.empty:
        raise PreprocessingError("The uploaded CSV file contains no log rows. Please provide data records.")

    # Normalize column headers (strip whitespace, lowercase)
    df.columns = [c.strip().lower() for c in df.columns]

    # Check required columns
    missing_cols = [col for col in REQUIRED_COLUMNS if col not in df.columns]
    if missing_cols:
        missing_str = ", ".join(missing_cols)
        raise PreprocessingError(
            f"Invalid security log format. Please check the required columns. Missing: {missing_str}"
        )

    # Clean and standardize fields
    df = clean_dataframe(df)

    if len(df) == 0:
        raise PreprocessingError("All rows contained invalid or unparseable timestamps. Please verify your log dates.")

    return df


def clean_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    """Cleans string values, parses timestamps, and sorts chronologically."""
    df = df.copy()

    # Fill NA values gracefully
    df["user"] = df["user"].fillna("Unknown").astype(str).str.strip()
    df["source_ip"] = df["source_ip"].fillna("127.0.0.1").astype(str).str.strip()
    df["destination_ip"] = df["destination_ip"].fillna("Internal").astype(str).str.strip()
    df["event_type"] = df["event_type"].fillna("Generic Activity").astype(str).str.strip()
    df["severity"] = df["severity"].fillna("Low").astype(str).str.strip().str.capitalize()
    df["resource"] = df["resource"].fillna("Default Resource").astype(str).str.strip()
    df["status"] = df["status"].fillna("Success").astype(str).str.strip().str.capitalize()

    # Map standard severity names
    def standardize_severity(sev):
        s = sev.capitalize()
        if s in ["Critical", "Crit"]:
            return "Critical"
        elif s in ["High"]:
            return "High"
        elif s in ["Medium", "Med"]:
            return "Medium"
        elif s in ["Low", "Info", "Informational"]:
            return "Low"
        return "Medium"

    df["severity"] = df["severity"].apply(standardize_severity)

    # Timestamp parsing
    try:
        df["parsed_timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
        # Drop rows where timestamp couldn't be parsed at all
        df = df.dropna(subset=["parsed_timestamp"])
        df = df.sort_values(by="parsed_timestamp").reset_index(drop=True)
    except Exception:
        # If datetime parsing fails, retain original order
        df["parsed_timestamp"] = pd.to_datetime(datetime.now())

    # Keep original timestamp as formatted string for display
    df["timestamp"] = df["parsed_timestamp"].dt.strftime("%Y-%m-%d %H:%M:%S")

    return df


def dataframe_to_event_list(df: pd.DataFrame) -> List[Dict[str, Any]]:
    """Converts cleaned DataFrame to a list of event dictionaries."""
    events = []
    for idx, row in df.iterrows():
        events.append({
            "id": int(idx + 1),
            "timestamp": str(row["timestamp"]),
            "user": str(row["user"]),
            "source_ip": str(row["source_ip"]),
            "destination_ip": str(row["destination_ip"]),
            "event_type": str(row["event_type"]),
            "severity": str(row["severity"]),
            "resource": str(row["resource"]),
            "status": str(row["status"]),
            "is_suspicious": False,
            "risk_contribution": 0
        })
    return events
