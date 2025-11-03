from pathlib import Path
import pandas as pd
import numpy as np

DATA_DIR = Path("data")
OUT_DIR = Path("outputs"); OUT_DIR.mkdir(exist_ok=True)

def safe_div(a,b): return float(a)/float(b) if b else 0.0

def build_user_features():
    users = pd.read_csv(DATA_DIR/"user_directory.csv")

    # Phishing
    if (DATA_DIR/"phishing_simulation.csv").exists():
        ph = pd.read_csv(DATA_DIR/"phishing_simulation.csv")
        ph_agg = (ph.groupby("user_id")
          .agg(attempts=("opened","count"), opens=("opened","sum"), clicks=("clicked","sum"),
               reports=("reported","sum"), creds_submitted=("creds_submitted","sum")).reset_index())
        ph_agg["click_rate"]  = ph_agg.apply(lambda r: safe_div(r["clicks"], r["attempts"]), axis=1)
        ph_agg["report_rate"] = ph_agg.apply(lambda r: safe_div(r["reports"],r["attempts"]), axis=1)
        ph_agg["creds_any"]   = (ph_agg["creds_submitted"]>0).astype(int)
    else:
        ph_agg = users[["user_id"]].copy()
        for c in ["attempts","opens","clicks","reports","creds_submitted","click_rate","report_rate","creds_any"]:
            ph_agg[c]=0

    # Access
    if (DATA_DIR/"access_logs.csv").exists():
        al = pd.read_csv(DATA_DIR/"access_logs.csv")
        al["download_gb"]   = np.where(al["action"].isin(["download","write","modify"]), al["data_gb"], 0.0)
        al["escalate_flag"] = (al["action"]=="escalate").astype(int)
        al["delete_flag"]   = (al["action"]=="delete").astype(int)
        al_agg = (al.groupby("user_id")
          .agg(events=("action","count"), downloads_gb=("download_gb","sum"),
               after_hours_events=("after_hours","sum"), anom_geo_events=("anomalous_geo","sum"),
               escalate_events=("escalate_flag","sum"), delete_events=("delete_flag","sum")).reset_index())
        al_agg["after_hours_rate"] = al_agg.apply(lambda r: safe_div(r["after_hours_events"], r["events"]), axis=1)
        al_agg["anom_geo_rate"]    = al_agg.apply(lambda r: safe_div(r["anom_geo_events"], r["events"]), axis=1)
    else:
        al_agg = users[["user_id"]].copy()
        for c in ["events","downloads_gb","after_hours_events","anom_geo_events","after_hours_rate","anom_geo_rate","escalate_events","delete_events"]:
            al_agg[c]=0

    # Violations
    if (DATA_DIR/"policy_violations.csv").exists():
        pv = pd.read_csv(DATA_DIR/"policy_violations.csv")
        pv["repeat_count"] = pv.get("repeat_count", 0)
        pv_agg = (pv.groupby("user_id")
          .agg(violations=("violation_type","count"),
               viol_low=("severity", lambda s:(s=="low").sum()),
               viol_med=("severity", lambda s:(s=="medium").sum()),
               viol_high=("severity", lambda s:(s=="high").sum()),
               viol_repeat_sum=("repeat_count","sum")).reset_index())
        pv_agg["viol_high_any"] = (pv_agg["viol_high"]>0).astype(int)
    else:
        pv_agg = users[["user_id"]].copy()
        for c in ["violations","viol_low","viol_med","viol_high","viol_repeat_sum","viol_high_any"]:
            pv_agg[c]=0

    df = (users.merge(ph_agg, on="user_id", how="left")
               .merge(al_agg, on="user_id", how="left")
               .merge(pv_agg, on="user_id", how="left")).fillna(0)

    for c in ["click_rate","report_rate","after_hours_rate","anom_geo_rate"]:
        df[c] = df[c].clip(0,1)
    df["downloads_gb"] = df["downloads_gb"].clip(0,500)
    df.to_csv(OUT_DIR/"user_features.csv", index=False)
    return df

if __name__ == "__main__":
    out = build_user_features()
    print(f"✅ Wrote outputs/user_features.csv ({len(out)} rows)")
