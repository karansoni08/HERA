from pathlib import Path

import pandas as pd

OUT = Path("outputs")
OUT.mkdir(exist_ok=True)


def map_origin(row):
    return "contractor" if str(row.get("role", "")).lower() == "contractor" else "employee"


def map_method(row):
    if row.get("click_rate", 0) > 0.2 or row.get("creds_any", 0) == 1:
        return "social-engineering (phishing)"
    if row.get("downloads_gb", 0) > 10 or row.get("escalate_events", 0) > 0:
        return "data-exfiltration / privilege-misuse"
    if row.get("anom_geo_rate", 0) > 0.05 or row.get("after_hours_rate", 0) > 0.4:
        return "anomalous-behavior (time/geo)"
    return "normal-operations"


def map_exposure(row):
    return {
        "Finance": "payment-approval / payroll",
        "HR": "personnel records",
        "Engineering": "source code / build artifacts",
        "Marketing": "brand / social accounts",
        "Operations": "ops / ERP / logistics",
    }.get(str(row.get("department", "")), "business operations")


def map_outcome(row):
    mapping = {
        "Very Low": "negligible impact",
        "Low": "limited operational impact",
        "Medium": "localized business impact",
        "High": "material business impact",
        "Critical": "severe financial/reputational impact",
    }
    return mapping.get(row.get("risk_band", "Low"), "limited operational impact")


if __name__ == "__main__":
    df = pd.read_csv(OUT / "risk_scores.csv")
    df["origin"] = df.apply(map_origin, axis=1)
    df["method"] = df.apply(map_method, axis=1)
    df["exposure"] = df.apply(map_exposure, axis=1)
    df["outcome"] = df.apply(map_outcome, axis=1)
    df.to_csv(OUT / "risk_scores_mapped.csv", index=False)
    print("✅ Wrote outputs/risk_scores_mapped.csv with OMEO labels")
