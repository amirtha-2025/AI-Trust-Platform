import os
import ssl
import json
from datetime import datetime

import pyexasol


EXASOL_HOST = os.getenv(
    "EXASOL_HOST",
    "exasol-71ce9ac0-n11.malaysiawest.cloudapp.azure.com"
)

EXASOL_USER = os.getenv("EXASOL_USER", "sys")
EXASOL_PASSWORD = os.getenv("EXASOL_PASSWORD")


def get_connection():
    if not EXASOL_PASSWORD:
        raise RuntimeError(
            "EXASOL_PASSWORD is not set. "
            "Set it in PowerShell before running the app."
        )

    return pyexasol.connect(
        dsn=f"{EXASOL_HOST}:8563",
        user=EXASOL_USER,
        password=EXASOL_PASSWORD,
        schema="AI_TRUST",
        encryption=True,
        websocket_sslopt={
            "cert_reqs": ssl.CERT_NONE
        }
    )


def save_event(event):
    conn = get_connection()

    event_time = (
        event.get("timestamp")
        or event.get("event_time")
        or datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    )

    component = (
        event.get("component")
        or event.get("type")
        or event.get("event_type")
        or "UNKNOWN"
    )

    user_input = (
        event.get("user_input")
        or event.get("prompt")
        or ""
    )

    status = event.get("status", "")
    risk_score = event.get("risk_score", 0)

    threats = event.get("threats", [])

    if isinstance(threats, list):
        threats = json.dumps(threats)

    ai_decision = (
        event.get("ai_decision")
        or event.get("decision")
        or event.get("red_team_result")
        or ""
    )

    query = """
        INSERT INTO AI_SECURITY_EVENTS
        (
            EVENT_TIME,
            COMPONENT,
            USER_INPUT,
            STATUS,
            RISK_SCORE,
            THREATS,
            AI_DECISION
        )
        VALUES (
            CURRENT_TIMESTAMP,
            {component!s},
            {user_input!s},
            {status!s},
            {risk_score!d},
            {threats!s},
            {ai_decision!s}
        )
    """

    params = {
        "component": component,
        "user_input": user_input,
        "status": status,
        "risk_score": int(risk_score),
        "threats": threats,
        "ai_decision": ai_decision,
    }

    conn.execute(query, params)
    conn.close()

def load_events():
    conn = get_connection()

    stmt = conn.execute(
        """
        SELECT
            EVENT_TIME,
            COMPONENT,
            USER_INPUT,
            STATUS,
            RISK_SCORE,
            THREATS,
            AI_DECISION
        FROM AI_SECURITY_EVENTS
        ORDER BY EVENT_TIME DESC
        """
    )

    events = []

    for row in stmt:
        threats = row[5]

        try:
            threats = json.loads(threats) if threats else []
        except (json.JSONDecodeError, TypeError):
            threats = [threats] if threats else []

        events.append(
            {
                "timestamp": str(row[0]),
                "event_type": row[1],
                "component": row[1],
                "user_input": row[2],
                "prompt": row[2],
                "status": row[3],
                "risk_score": float(row[4]) if row[4] is not None else 0,
                "threats": threats,
                "ai_decision": row[6],
                "decision": row[6],
                "red_team_result": row[6],
            }
        )

    conn.close()

    return events