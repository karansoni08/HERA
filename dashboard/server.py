import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import random
from datetime import datetime
from flask import Flask, jsonify, request, send_from_directory
from core.trace.trace_analyzer import TRACEAnalyzer
from core.database.db import init_db, get_executive_data, get_recent_threats

trace = TRACEAnalyzer()

app = Flask(__name__, static_folder='static')
init_db()

INDICATOR_THREATS = {
    "Privilege Escalation": {"indicators": ["Privilege Escalation"],                              "origin": "Internal", "severity": "Critical"},
    "USB Events":           {"indicators": ["USB Device Connected"],                              "origin": "Internal", "severity": "High"},
    "Failed Logins":        {"indicators": ["Multiple Failed Logins"],                            "origin": "External", "severity": "High"},
    "Unknown Location":     {"indicators": [],                                                    "origin": "External", "severity": "Medium"},
    "Mass Downloads":       {"indicators": ["USB Device Connected", "Privilege Escalation"],      "origin": "External", "severity": "Critical"},
    "Normal Login":         {"indicators": [],                                                    "origin": "Internal", "severity": "Low"},
}

USERS     = ["admin", "john", "alice", "root", "devops", "guest"]
ACTIONS   = ["login", "mass_download", "file_access", "usb_mount", "ssh_access", "privilege_escalation"]
LOCATIONS = ["internal", "canada", "usa", "unknown", "germany"]


def risk_score(failed, usb, priv):
    s = 0
    if failed > 3: s += 30
    if usb:        s += 30
    if priv:       s += 40
    return s


def severity(score):
    if score >= 70: return "Critical"
    if score >= 50: return "High"
    if score >= 30: return "Medium"
    return "Low"


@app.route('/')
def index():
    return send_from_directory(app.static_folder, 'index.html')


@app.route('/api/executive')
def executive():
    period   = request.args.get('period',   'week')
    sev_f    = request.args.get('severity', 'all')
    origin_f = request.args.get('origin',   'all')
    user_f   = request.args.get('user',     'all')

    d = get_executive_data(period, sev_f, origin_f, user_f)

    threats_n  = d['total']
    critical_n = d['critical']
    prev_n     = d['prev_total']
    vs_label   = d['vs_label']
    ind        = d['ind_counts']

    threats_note  = f'{vs_label} {prev_n}'
    critical_note = f'vs target {max(1, round(threats_n * 0.2))}'

    return jsonify({
        "kpis": [
            {"label": "Threats Detected", "value": str(threats_n),     "trend_up": threats_n > prev_n, "note": threats_note,  "good": False, "badge": False},
            {"label": "Critical Alerts",  "value": str(critical_n),    "trend_up": True,               "note": critical_note, "good": False, "badge": False},
            {"label": "Avg Risk Score",   "value": str(d['avg_risk']), "trend_up": True,               "note": "threshold 50","good": False, "badge": False},
            {"label": "External Origin",  "value": d['ext_pct'],       "trend_up": True,               "note": "vs baseline 25%", "good": False, "badge": False},
            {"label": "AI Confidence",    "value": "93%",              "trend_up": True,               "note": "+2% MoM",    "good": True,  "badge": True},
        ],
        "threat_trend": {
            "labels":   d['trend_labels'],
            "actual":   d['trend_actual'],
            "baseline": d['trend_baseline'],
        },
        "indicators": {
            "labels": ["Failed Logins", "USB Connected", "Priv. Escalation", "Unknown Location"],
            "counts": ind,
        }
    })


@app.route('/api/operations')
def operations():
    users = random.sample(USERS, 4)
    events = []
    for u in users:
        failed = random.choice([0, 0, 4, 6])
        usb    = random.choice([True, False, False])
        priv   = random.choice([True, False, False])
        score  = risk_score(failed, usb, priv)
        events.append({"user": u, "usb": usb, "priv": priv, "failed": failed,
                        "location": random.choice(LOCATIONS), "risk_score": score})

    top      = max(events, key=lambda e: e["risk_score"])
    critical = top["risk_score"] >= 70
    indics   = (["USB Device Connected"]   if top["usb"]        else []) + \
               (["Privilege Escalation"]   if top["priv"]       else []) + \
               (["Multiple Failed Logins"] if top["failed"] > 3 else [])

    threat_dict = {
        "indicators": indics,
        "origin":     "External" if top["location"] == "unknown" else "Internal",
        "severity":   severity(top["risk_score"])
    }
    trace_result = trace.analyze(threat_dict)

    db_recent = get_recent_threats(limit=5)
    recent = [
        {
            "time":       r["time"][-8:],
            "user":       r["user"],
            "action":     "threat detected",
            "location":   r["origin"].lower(),
            "risk_score": r["risk_score"],
            "severity":   r["severity"],
        }
        for r in db_recent
    ] or [
        {
            "time": datetime.now().strftime("%H:%M:%S"),
            "user": random.choice(USERS),
            "action": random.choice(ACTIONS),
            "location": random.choice(LOCATIONS),
            "risk_score": risk_score(random.choice([0, 5]), random.choice([True, False]), random.choice([True, False])),
            "severity": "Medium",
        }
        for _ in range(5)
    ]

    return jsonify({
        "alert": {
            "active":  critical,
            "message": (f"CRITICAL — Risk score {top['risk_score']}/100 for user '{top['user']}'. "
                        f"Indicators: {', '.join(indics) if indics else 'Anomalous behaviour'}. "
                        f"Immediate containment required.")
        },
        "user_risks": [{"user": e["user"], "risk_score": e["risk_score"]} for e in events],
        "severity_heatmap": [
            {"label": "Privilege Escalation", "status": "critical"},
            {"label": "USB Events",           "status": "high"},
            {"label": "Failed Logins",        "status": "high"},
            {"label": "Unknown Location",     "status": "medium"},
            {"label": "Mass Downloads",       "status": "critical"},
            {"label": "Normal Login",         "status": "low"},
        ],
        "recent_incidents": recent,
        "ai_response": (f"{sum(1 for e in events if e['risk_score'] >= 50)} active threats — "
                        f"containment actions queued by AI response engine."),
        "trace": {
            "user":     top["user"],
            "risk":     top["risk_score"],
            "severity": threat_dict["severity"],
            "origin":   threat_dict["origin"],
            "findings": trace_result
        }
    })


@app.route('/api/trace')
def trace_for_indicator():
    indicator = request.args.get('indicator', '')
    threat    = INDICATOR_THREATS.get(indicator, {"indicators": [], "origin": "Internal", "severity": "Low"})
    findings  = trace.analyze(threat)
    return jsonify({
        "indicator": indicator,
        "severity":  threat["severity"],
        "origin":    threat["origin"],
        "findings":  findings
    })


if __name__ == '__main__':
    app.run(debug=True, port=8080)
