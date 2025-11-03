from pathlib import Path
import subprocess, sys, pandas as pd

PY = sys.executable
def run(cmd): subprocess.run(cmd, check=True)

def test_pipeline_end_to_end():
    if not Path("data/user_directory.csv").exists():
        run([PY,"src/generate_synthetic_data.py"])
    run([PY,"src/feature_engineering.py"])
    run([PY,"src/score_risk.py"])
    run([PY,"src/map_omeo_vectors.py"])

    assert Path("outputs/risk_scores.csv").exists()
    df = pd.read_csv("outputs/risk_scores.csv")
    for c in ["LIKELIHOOD","IMPACT","DETECTABILITY","HTI","risk_band"]:
        assert c in df.columns

    assert Path("outputs/risk_scores_mapped.csv").exists()
