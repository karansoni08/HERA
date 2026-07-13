"""
Seed hera.db with 90 days of synthetic historical threat data.
Run once: python scripts/seed_db.py
Re-running is safe — it clears existing data first.
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import random
import json
from datetime import datetime, timedelta
from core.database.db import init_db, _conn, DB_PATH
from core.trace.trace_analyzer import TRACEAnalyzer

trace = TRACEAnalyzer()

USERS     = ["admin", "john", "alice", "root", "devops", "guest"]
ACTIONS   = ["login", "mass_download", "file_access", "usb_mount", "ssh_access", "privilege_escalation"]
LOCATIONS = ["internal", "canada", "usa", "unknown", "germany"]

# Every ~30 days there's a 5-day attack campaign with higher anomaly rates
CAMPAIGN_STARTS = [5, 35, 65, 95, 125, 155, 185, 215, 245, 275, 305, 340]  # days from 365 days ago


def in_campaign(day_offset):
    return any(s <= day_offset <= s + 4 for s in CAMPAIGN_STARTS)


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


def gen_event(ts, campaign=False):
    user     = random.choice(USERS)
    action   = random.choice(ACTIONS)
    location = random.choice(LOCATIONS)
    if campaign:
        failed = random.choice([0, 0, 4, 6, 6])
        usb    = random.choice([True, True, False])
        priv   = random.choice([True, False, False])
    else:
        failed = random.choice([0, 0, 0, 4])
        usb    = random.choice([True, False, False, False])
        priv   = random.choice([True, False, False, False])
    score = risk_score(failed, usb, priv)
    return {
        "timestamp": ts.isoformat(),
        "user": user, "action": action, "location": location,
        "failed_attempts": failed, "usb_connected": int(usb),
        "privilege_escalation": int(priv),
        "risk_score": score, "is_anomaly": int(score >= 50),
    }, usb, priv, failed, score, location


def seed():
    init_db()
    c = _conn()
    c.execute("DELETE FROM events")
    c.execute("DELETE FROM threats")
    c.commit()

    now   = datetime.now()
    start = now - timedelta(days=365)

    events_batch  = []
    threats_batch = []

    for day in range(365):
        day_start = start + timedelta(days=day)
        campaign  = in_campaign(day)
        # 8-25 events per day (more during campaigns)
        n_events = random.randint(18, 30) if campaign else random.randint(6, 18)

        for _ in range(n_events):
            minutes = random.randint(0, 1439)
            ts      = day_start + timedelta(minutes=minutes)
            ev, usb, priv, failed, score, location = gen_event(ts, campaign)
            events_batch.append((
                ev['timestamp'], ev['user'], ev['action'], ev['location'],
                failed, int(usb), int(priv), score, ev['is_anomaly']
            ))

            if score >= 50:
                indicators = (["Multiple Failed Logins"] if failed > 3 else []) + \
                             (["USB Device Connected"]   if usb        else []) + \
                             (["Privilege Escalation"]   if priv       else [])
                origin = "External" if location == "unknown" else "Internal"
                t_dict = {"indicators": indicators, "origin": origin, "severity": severity(score)}
                tr = trace.analyze(t_dict)
                threats_batch.append((
                    ev['timestamp'], ev['user'], score, severity(score), origin,
                    json.dumps(indicators),
                    tr.get('threat', ''), tr.get('exposure', ''),
                    tr.get('root_cause', ''), tr.get('actor', ''),
                    json.dumps(tr.get('containment', []))
                ))

    c.executemany(
        "INSERT INTO events (timestamp,user,action,location,failed_attempts,usb_connected,privilege_escalation,risk_score,is_anomaly) VALUES (?,?,?,?,?,?,?,?,?)",
        events_batch
    )
    c.executemany(
        "INSERT INTO threats (timestamp,user,risk_score,severity,origin,indicators,trace_threat,trace_exposure,trace_root_cause,trace_actor,trace_containment) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        threats_batch
    )
    c.commit()
    c.close()

    print(f"[seed] Done. {len(events_batch)} events, {len(threats_batch)} threats → {DB_PATH}")


if __name__ == "__main__":
    seed()
