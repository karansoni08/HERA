from pathlib import Path
import pandas as pd

DOCS = Path("docs"); DOCS.mkdir(exist_ok=True)

def read_csv_safe(p: Path):
    return pd.read_csv(p) if p.exists() else None

def md_table(df: pd.DataFrame, n=10) -> str:
    return df.head(n).to_markdown(index=False)

def build_data_preview() -> Path:
    pairs = [
        ("data/user_directory.csv", 8),
        ("data/phishing_simulation.csv", 8),
        ("data/access_logs.csv", 8),
        ("data/policy_violations.csv", 8),
        ("outputs/user_features.csv", 8),
        ("outputs/risk_scores.csv", 8),
        ("outputs/risk_scores_mapped.csv", 8),
    ]
    parts = ["# 📊 Data Preview\n"]
    for path, n in pairs:
        p = Path(path)
        if p.exists():
            df = pd.read_csv(p)
            parts.append(f"## {path}\n")
            parts.append(md_table(df, n))
            parts.append("\n---\n")
    out = DOCS / "data_preview.md"
    out.write_text("\n".join(parts), encoding="utf-8")
    return out

def build_report() -> Path:
    scores_p = Path("outputs/risk_scores.csv")
    mapped_p = Path("outputs/risk_scores_mapped.csv")
    charts = Path("outputs/charts")

    scores = read_csv_safe(scores_p)
    if scores is None:
        raise SystemExit("Missing outputs/risk_scores.csv — run Phases 2–6 first.")

    mapped = read_csv_safe(mapped_p)

    avg_hti = round(scores["HTI"].mean(), 2)
    by_dept = scores.groupby("department")["HTI"].mean().sort_values(ascending=False).round(2)
    top_users = scores.sort_values("HTI", ascending=False)[["user_id","department","role","HTI"]].head(10)

    parts = []
    parts.append("# HERA — OMEO Risk Report\n")
    parts.append("**Objective:** Summarize human-centric risk posture with OMEO context.\n")
    parts.append("## Executive Summary\n")
    parts.append(f"- Average HTI: **{avg_hti}**\n")
    parts.append("- Highest-risk departments (avg HTI):\n")
    parts.append(by_dept.to_frame("avg_HTI").to_markdown())

    parts.append("\n## Top 10 Risky Users\n")
    parts.append(top_users.to_markdown(index=False))

    parts.append("\n## Risk Bands (counts)\n")
    bands = scores["risk_band"].value_counts().reindex(["Very Low","Low","Medium","High","Critical"]).fillna(0).astype(int)
    parts.append(bands.to_frame("count").to_markdown())

    parts.append("\n## OMEO Summary\n")
    if mapped is not None and "method" in mapped.columns:
        parts.append("**Top Methods**\n")
        parts.append(mapped["method"].value_counts().head(10).to_frame("count").to_markdown())
    else:
        parts.append("_OMEO mapping not found — run `src/map_omeo_vectors.py`._")

    parts.append("\n## Visuals\n")
    def img(name): return charts / name
    rows = []
    if img("avg_hti_by_department.png").exists() and img("top_risky_users.png").exists():
        rows += [
            "| Avg HTI by Department | Top 15 Risky Users |",
            "|---|---|",
            f"| ![](../outputs/charts/avg_hti_by_department.png) | ![](../outputs/charts/top_risky_users.png) |",
        ]
    if img("hti_distribution_by_role.png").exists() and img("risk_band_counts.png").exists():
        rows += [
            "| HTI Distribution by Role | Risk Band Counts |",
            "|---|---|",
            f"| ![](../outputs/charts/hti_distribution_by_role.png) | ![](../outputs/charts/risk_band_counts.png) |",
        ]
    if rows:
        parts.append("\n".join(rows))

    out = DOCS / "report.md"
    out.write_text("\n".join(parts), encoding="utf-8")
    return out

if __name__ == "__main__":
    dp = build_data_preview()
    rp = build_report()
    print(f"✅ Wrote {dp}")
    print(f"✅ Wrote {rp}")
