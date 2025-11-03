from pathlib import Path

import numpy as np
import pandas as pd

OUT = Path("outputs")
OUT.mkdir(exist_ok=True)

W = {
    "likelihood": {
        "click_rate": 0.35,
        "after_hours_rate": 0.25,
        "anom_geo_rate": 0.20,
        "creds_any": 0.20,
    },
    "impact": {"critical_asset_access": 0.7, "privilege_level_elevated_or_admin": 0.3},
    "detectability": {"reports_inverse": 0.6, "violations_inverse": 0.4},
}


def clip01(x):
    return float(np.clip(x, 0.0, 1.0))


def compute_row(r):
    L = (
        clip01(r.get("click_rate", 0)) * W["likelihood"]["click_rate"]
        + clip01(r.get("after_hours_rate", 0)) * W["likelihood"]["after_hours_rate"]
        + clip01(r.get("anom_geo_rate", 0)) * W["likelihood"]["anom_geo_rate"]
        + (1.0 if r.get("creds_any", 0) > 0 else 0.0) * W["likelihood"]["creds_any"]
    ) / sum(W["likelihood"].values())

    elev = 1.0 if str(r.get("privilege_level", "")).lower() in ("elevated", "admin") else 0.0
    I = (
        (
            (1.0 if int(r.get("critical_asset_access", 0)) == 1 else 0.0)
            * W["impact"]["critical_asset_access"]
        )
        + (elev * W["impact"]["privilege_level_elevated_or_admin"])
    ) / sum(W["impact"].values())

    rep_inv = 1.0 - clip01(r.get("report_rate", 0))
    viol_inv = clip01(min(float(r.get("violations", 0)) / 5.0, 1.0))
    D = (
        rep_inv * W["detectability"]["reports_inverse"]
        + viol_inv * W["detectability"]["violations_inverse"]
    ) / sum(W["detectability"].values())

    HTI = 100.0 * L * max(I, 0.1) * (1.0 - 0.5 * D)
    return round(L, 4), round(I, 4), round(D, 4), round(HTI, 2)


if __name__ == "__main__":
    feats = pd.read_csv(OUT / "user_features.csv")
    comps = feats.apply(compute_row, axis=1, result_type="expand")
    comps.columns = ["LIKELIHOOD", "IMPACT", "DETECTABILITY", "HTI"]
    out = pd.concat([feats, comps], axis=1)
    out["risk_band"] = pd.cut(
        out["HTI"],
        bins=[-0.01, 20, 40, 60, 80, 200],
        labels=["Very Low", "Low", "Medium", "High", "Critical"],
    )
    out.to_csv(OUT / "risk_scores.csv", index=False)
    print("✅ Wrote outputs/risk_scores.csv")
