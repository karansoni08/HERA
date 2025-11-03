from pathlib import Path
import pandas as pd
import matplotlib.pyplot as plt

OUT = Path("outputs/charts"); OUT.mkdir(parents=True, exist_ok=True)

def savefig(p): plt.tight_layout(); plt.savefig(p, dpi=160, bbox_inches="tight"); plt.close()

def load_scores():
    df = pd.read_csv("outputs/risk_scores.csv")
    for c in ["user_id","department","role","HTI","risk_band"]:
        if c not in df.columns: raise RuntimeError(f"Missing {c} in risk_scores.csv")
    return df

def load_mapped():
    p = Path("outputs/risk_scores_mapped.csv")
    return pd.read_csv(p) if p.exists() else None

def chart_avg_hti_by_department(df):
    ax = df.groupby("department")["HTI"].mean().sort_values().plot(kind="bar")
    ax.set_title("Average HTI by Department"); ax.set_ylabel("HTI (0–100)")
    savefig(OUT/"avg_hti_by_department.png")

def chart_top_risky_users(df, n=15):
    top = df.sort_values("HTI", ascending=False).head(n)
    ax = top.plot(kind="bar", x="user_id", y="HTI", legend=False)
    ax.set_title(f"Top {n} Risky Users (HTI)"); ax.set_ylabel("HTI (0–100)"); ax.set_xlabel("user_id")
    savefig(OUT/"top_risky_users.png")

def chart_hti_hist_by_role(df):
    roles = list(df["role"].value_counts().index[:6])
    plt.figure()
    for r in roles:
        df[df["role"]==r]["HTI"].plot(kind="kde", label=r)
    plt.title("HTI Distribution by Role (KDE)"); plt.xlabel("HTI"); plt.legend()
    savefig(OUT/"hti_distribution_by_role.png")

def chart_risk_band_counts(df):
    order = ["Very Low","Low","Medium","High","Critical"]
    ax = df["risk_band"].value_counts().reindex(order).fillna(0).plot(kind="bar")
    ax.set_title("Users by Risk Band"); ax.set_ylabel("Count")
    savefig(OUT/"risk_band_counts.png")

if __name__ == "__main__":
    scores = load_scores(); _ = load_mapped()
    chart_avg_hti_by_department(scores)
    chart_top_risky_users(scores)
    chart_hti_hist_by_role(scores)
    chart_risk_band_counts(scores)
    print("✅ Charts saved to outputs/charts")
