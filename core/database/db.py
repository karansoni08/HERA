import os
import json
import sqlite3
from datetime import datetime, timedelta

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_LOCAL_DB = os.path.join(PROJECT_ROOT, 'data', 'hera.db')
_TMP_DB   = '/tmp/hera.db'


def _db_path():
    """Return writable DB path. On read-only filesystems (Vercel) copy bundled DB to /tmp."""
    data_dir = os.path.join(PROJECT_ROOT, 'data')
    if os.access(data_dir, os.W_OK):
        return _LOCAL_DB
    if not os.path.exists(_TMP_DB) and os.path.exists(_LOCAL_DB):
        import shutil
        shutil.copy2(_LOCAL_DB, _TMP_DB)
    return _TMP_DB


DB_PATH = _LOCAL_DB  # kept for seed script compatibility

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp            TEXT    NOT NULL,
    user                 TEXT    NOT NULL,
    action               TEXT    NOT NULL,
    location             TEXT    NOT NULL,
    failed_attempts      INTEGER DEFAULT 0,
    usb_connected        INTEGER DEFAULT 0,
    privilege_escalation INTEGER DEFAULT 0,
    risk_score           INTEGER DEFAULT 0,
    is_anomaly           INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS threats (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp         TEXT NOT NULL,
    user              TEXT NOT NULL,
    risk_score        INTEGER NOT NULL,
    severity          TEXT NOT NULL,
    origin            TEXT NOT NULL,
    indicators        TEXT NOT NULL,
    trace_threat      TEXT,
    trace_exposure    TEXT,
    trace_root_cause  TEXT,
    trace_actor       TEXT,
    trace_containment TEXT
);
"""


def _conn():
    path = _db_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    c = sqlite3.connect(path)
    c.row_factory = sqlite3.Row
    return c


def init_db():
    c = _conn()
    c.executescript(SCHEMA)
    c.commit()
    c.close()


# ── Write ──────────────────────────────────────────────────────────

def log_event(event: dict, risk_score: int, is_anomaly: bool):
    c = _conn()
    c.execute(
        "INSERT INTO events (timestamp,user,action,location,failed_attempts,usb_connected,privilege_escalation,risk_score,is_anomaly) VALUES (?,?,?,?,?,?,?,?,?)",
        (event.get('timestamp', datetime.now().isoformat()), event['user'], event['action'],
         event['location'], int(event['failed_attempts']), int(event['usb_connected']),
         int(event['privilege_escalation']), risk_score, int(is_anomaly))
    )
    c.commit()
    c.close()


def log_threat(user, risk_score, severity, origin, indicators, trace_result, timestamp=None):
    c = _conn()
    c.execute(
        "INSERT INTO threats (timestamp,user,risk_score,severity,origin,indicators,trace_threat,trace_exposure,trace_root_cause,trace_actor,trace_containment) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        (timestamp or datetime.now().isoformat(), user, risk_score, severity, origin,
         json.dumps(indicators),
         trace_result.get('threat', ''),   trace_result.get('exposure', ''),
         trace_result.get('root_cause', ''), trace_result.get('actor', ''),
         json.dumps(trace_result.get('containment', [])))
    )
    c.commit()
    c.close()


# ── Query helpers ───────────────────────────────────────────────────

def _period_filter(period):
    if period == 'day':
        return "date(timestamp) = date('now')",                                                              \
               "date(timestamp) = date('now','-1 day')",                                                    \
               "vs yesterday"
    if period == 'week':
        return "timestamp >= datetime('now','-7 days')",                                                    \
               "timestamp >= datetime('now','-14 days') AND timestamp < datetime('now','-7 days')",         \
               "vs last week"
    if period == 'month':
        return "timestamp >= datetime('now','-30 days')",                                                   \
               "timestamp >= datetime('now','-60 days') AND timestamp < datetime('now','-30 days')",        \
               "vs last month"
    # year
    return "timestamp >= datetime('now','-365 days')",                                                      \
           "timestamp >= datetime('now','-730 days') AND timestamp < datetime('now','-365 days')",          \
           "vs last year"


def _extra_filters(sev_f, origin_f, user_f):
    clauses, params = [], []
    if sev_f not in ('all', ''):
        clauses.append("severity = ?"); params.append(sev_f.title())
    if origin_f not in ('all', ''):
        clauses.append("origin = ?");   params.append(origin_f.title())
    if user_f not in ('all', ''):
        clauses.append("user = ?");     params.append(user_f)
    sql = (" AND " + " AND ".join(clauses)) if clauses else ""
    return sql, params


def _trend(period, c, extra_sql, params):
    now = datetime.now()

    if period == 'day':
        labels = [f'{h:02d}:00' for h in range(0, 24, 2)]
        rows = c.execute(
            f"SELECT CAST(strftime('%H',timestamp) AS INTEGER)/2*2 AS blk, COUNT(*) AS cnt "
            f"FROM threats WHERE date(timestamp)=date('now'){extra_sql} GROUP BY blk", params
        ).fetchall()
        data = {r['blk']: r['cnt'] for r in rows}
        actual = [data.get(h, 0) for h in range(0, 24, 2)]
        base_row = c.execute("SELECT CAST(COUNT(*) AS REAL)/30/12 AS v FROM threats WHERE timestamp>=datetime('now','-30 days')").fetchone()
        baseline = [round(base_row['v'] or 0, 1)] * 12

    elif period == 'week':
        dates = [(now - timedelta(days=6 - i)) for i in range(7)]
        labels  = [d.strftime('%a')      for d in dates]
        dstrs   = [d.strftime('%Y-%m-%d') for d in dates]
        rows = c.execute(
            f"SELECT date(timestamp) AS day, COUNT(*) AS cnt FROM threats "
            f"WHERE timestamp>=datetime('now','-7 days'){extra_sql} GROUP BY day", params
        ).fetchall()
        data = {r['day']: r['cnt'] for r in rows}
        actual = [data.get(d, 0) for d in dstrs]
        base_row = c.execute("SELECT CAST(COUNT(*) AS REAL)/30 AS v FROM threats WHERE timestamp>=datetime('now','-30 days')").fetchone()
        baseline = [round(base_row['v'] or 0)] * 7

    elif period == 'month':
        labels = ['Week 1', 'Week 2', 'Week 3', 'Week 4']
        actual = []
        for w in range(4, 0, -1):
            cnt = c.execute(
                f"SELECT COUNT(*) AS cnt FROM threats "
                f"WHERE timestamp>=datetime('now','-{w*7} days') AND timestamp<datetime('now','-{(w-1)*7} days'){extra_sql}",
                params
            ).fetchone()['cnt']
            actual.append(cnt)
        base_row = c.execute("SELECT CAST(COUNT(*) AS REAL)/52 AS v FROM threats WHERE timestamp>=datetime('now','-365 days')").fetchone()
        baseline = [round(base_row['v'] or 0)] * 4

    else:  # year
        months = [(now - timedelta(days=30 * (11 - i))) for i in range(12)]
        labels = [m.strftime('%b') for m in months]
        actual = []
        for i in range(12):
            s = (now - timedelta(days=30 * (11 - i))).strftime('%Y-%m-%d')
            e = (now - timedelta(days=30 * (10 - i))).strftime('%Y-%m-%d')
            cnt = c.execute(
                f"SELECT COUNT(*) AS cnt FROM threats WHERE date(timestamp)>=? AND date(timestamp)<?{extra_sql}",
                [s, e] + params
            ).fetchone()['cnt']
            actual.append(cnt)
        total = sum(actual)
        baseline = [round(total / 12) if total else 0] * 12

    return labels, actual, baseline


# ── Main query used by the dashboard ──────────────────────────────

def get_executive_data(period='week', sev_f='all', origin_f='all', user_f='all'):
    c = _conn()
    curr_f, prev_f, vs_label = _period_filter(period)
    extra_sql, params = _extra_filters(sev_f, origin_f, user_f)

    curr = c.execute(
        f"SELECT COUNT(*) AS total, "
        f"SUM(CASE WHEN severity='Critical' THEN 1 ELSE 0 END) AS critical, "
        f"AVG(risk_score) AS avg_risk, "
        f"SUM(CASE WHEN origin='External' THEN 1 ELSE 0 END) AS external "
        f"FROM threats WHERE {curr_f}{extra_sql}", params
    ).fetchone()

    prev_total = c.execute(
        f"SELECT COUNT(*) AS cnt FROM threats WHERE {prev_f}{extra_sql}", params
    ).fetchone()['cnt'] or 0

    labels, actual, baseline = _trend(period, c, extra_sql, params)

    ind_rows = c.execute(
        f"SELECT indicators, origin FROM threats WHERE {curr_f}{extra_sql}", params
    ).fetchall()
    c.close()

    total    = curr['total']    or 0
    critical = curr['critical'] or 0
    avg_risk = round(curr['avg_risk'] or 0)
    external = curr['external'] or 0

    ind_counts = [0, 0, 0, 0]
    for row in ind_rows:
        try:
            inds = json.loads(row['indicators'])
            if "Multiple Failed Logins" in inds:  ind_counts[0] += 1
            if "USB Device Connected"   in inds:  ind_counts[1] += 1
            if "Privilege Escalation"   in inds:  ind_counts[2] += 1
            if row['origin'] == 'External':        ind_counts[3] += 1
        except Exception:
            pass

    ext_pct = f"{round(external / total * 100)}%" if total > 0 else "0%"

    return {
        'total': total, 'prev_total': prev_total, 'vs_label': vs_label,
        'critical': critical, 'avg_risk': avg_risk, 'ext_pct': ext_pct,
        'trend_labels': labels, 'trend_actual': actual, 'trend_baseline': baseline,
        'ind_counts': ind_counts,
    }


def get_recent_threats(limit=5):
    c = _conn()
    rows = c.execute(
        "SELECT timestamp, user, risk_score, severity, origin, indicators "
        "FROM threats ORDER BY timestamp DESC LIMIT ?", (limit,)
    ).fetchall()
    c.close()
    result = []
    for r in rows:
        ts = r['timestamp'][:19].replace('T', ' ')
        result.append({
            'time':       ts,
            'user':       r['user'],
            'risk_score': r['risk_score'],
            'severity':   r['severity'],
            'origin':     r['origin'],
            'indicators': json.loads(r['indicators'] or '[]'),
        })
    return result
