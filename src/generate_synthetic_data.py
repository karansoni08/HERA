from pathlib import Path
import pandas as pd
from faker import Faker
import random
from datetime import datetime, timedelta

SEED = 42
NUM_USERS = 100
DAYS_HISTORY = 90
DATA_DIR = Path("data"); DATA_DIR.mkdir(exist_ok=True)
fake = Faker(); random.seed(SEED); Faker.seed(SEED)

def _random_times(n, days_back=DAYS_HISTORY):
    now = datetime.now(); start = now - timedelta(days=days_back)
    span = int((now - start).total_seconds())
    return [(start + timedelta(seconds=random.randint(0, span))).isoformat() for _ in range(n)]

def generate_users(n=NUM_USERS):
    roles = ["Analyst","Manager","Engineer","Finance Officer","HR Specialist","Contractor"]
    depts = ["Finance","HR","Engineering","Marketing","Operations"]
    privs = ["normal","elevated","admin"]
    rows = []
    for i in range(n):
        role = random.choice(roles)
        rows.append({
            "user_id": f"USR{i+1:04d}",
            "name": fake.name(),
            "email": fake.company_email(),
            "department": random.choice(depts),
            "role": role,
            "employment_type": "contractor" if role == "Contractor" else "employee",
            "privilege_level": random.choices(privs, weights=[0.7,0.25,0.05])[0],
            "critical_asset_access": int(random.random() < 0.12),
            "hire_date": fake.date_between(start_date='-5y', end_date='today').isoformat()
        })
    df = pd.DataFrame(rows); df.to_csv(DATA_DIR/"user_directory.csv", index=False); return df

def generate_phishing(users_df):
    base_click = {"Analyst":0.10,"Manager":0.12,"Engineer":0.08,"Finance Officer":0.18,"HR Specialist":0.14,"Contractor":0.20}
    rows=[]
    for _, u in users_df.iterrows():
        for ts in _random_times(random.randint(2,4)):
            b = base_click.get(u["role"], 0.10)
            opened = int(random.random() < min(0.9, b+0.15))
            clicked = int(opened and random.random() < b)
            reported = int(opened and random.random() < 0.25)
            creds = int(clicked and random.random() < 0.02)
            rows.append({"user_id":u["user_id"],"timestamp":ts,"opened":opened,"clicked":clicked,
                         "reported":reported,"creds_submitted":creds,"origin_type":"employee"})
    pd.DataFrame(rows).sort_values("timestamp").to_csv(DATA_DIR/"phishing_simulation.csv", index=False)

def generate_access_logs(users_df):
    actions = ["read","write","delete","escalate","download","modify"]
    rows=[]
    for _, u in users_df.iterrows():
        for ts in _random_times(random.randint(8,25)):
            action = random.choices(actions, weights=[0.5,0.15,0.02,0.03,0.2,0.1])[0]
            data_gb = round(random.uniform(0.01,5.0) if action in ("download","write","modify") else random.uniform(0.0,0.5), 2)
            hour = datetime.fromisoformat(ts).hour
            after_hours = int(hour < 7 or hour > 19)
            anomalous_geo = int(random.random() < 0.02)
            origin_type = "contractor" if u["employment_type"]=="contractor" else "employee"
            rows.append({"user_id":u["user_id"],"timestamp":ts,"action":action,"data_gb":data_gb,
                         "after_hours":after_hours,"anomalous_geo":anomalous_geo,"origin_type":origin_type})
    pd.DataFrame(rows).sort_values("timestamp").to_csv(DATA_DIR/"access_logs.csv", index=False)

def generate_policy_violations(users_df):
    kinds = ["Access Violation","Data Transfer Without Approval","Policy Breach","Phishing Response"]
    rows=[]
    for _, u in users_df.iterrows():
        for ts in _random_times(random.choices([0,1,2,3],[0.7,0.2,0.08,0.02])[0]):
            rows.append({"user_id":u["user_id"],"timestamp":ts,"violation_type":random.choice(kinds),
                         "severity":random.choices(["low","medium","high"],[0.6,0.3,0.1])[0],
                         "repeat_count":random.randint(0,3),"origin_type":"employee"})
    pd.DataFrame(rows).sort_values("timestamp").to_csv(DATA_DIR/"policy_violations.csv", index=False)

if __name__ == "__main__":
    users = generate_users(NUM_USERS)
    generate_phishing(users); generate_access_logs(users); generate_policy_violations(users)
    print("✅ Synthetic data created in ./data/")
