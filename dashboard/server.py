import sys
import os
import threading
import time
from collections import deque
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import uvicorn

from core.collection.log_collector import LogCollector
from core.processing.event_normalizer import EventNormalizer
from core.behavioral_analysis.user_baseline import UserBaselineEngine
from core.threat_detection.anomaly_detector import AnomalyDetector
from core.attribution.threat_classifier import ThreatClassifier
from core.correlation.correlation_engine import CorrelationEngine
from core.response_engine.mitigation_generator import MitigationGenerator
from core.ai_reasoning.autonomous_reasoning import AutonomousReasoning
from core.vicar.vicar_analyzer import VICARAnalyzer

@asynccontextmanager
async def lifespan(app: FastAPI):
    t = threading.Thread(target=hera_loop, daemon=True)
    t.start()
    yield

app = FastAPI(lifespan=lifespan)

# In-memory stores (last 50 events, last 20 alerts)
recent_events = deque(maxlen=50)
recent_alerts = deque(maxlen=20)
stats = {"total_events": 0, "anomalies": 0, "critical": 0, "users": set()}

collector = LogCollector()
normalizer = EventNormalizer()
baseline = UserBaselineEngine()
detector = AnomalyDetector()
classifier = ThreatClassifier()
correlation = CorrelationEngine()
mitigation = MitigationGenerator()
reasoning = AutonomousReasoning()
vicar = VICARAnalyzer()


def hera_loop():
    while True:
        try:
            raw_logs = collector.collect()
            normalized = normalizer.normalize(raw_logs)
            analyzed = baseline.analyze(normalized)

            for item in analyzed:
                event = item["event"]
                stats["total_events"] += 1
                stats["users"].add(event["user"])
                recent_events.appendleft({
                    "timestamp": datetime.now().strftime("%H:%M:%S"),
                    "user": event["user"],
                    "action": event["action"],
                    "location": event["location"],
                    "risk_score": item["risk_score"],
                })

            anomalies = detector.detect(analyzed)
            if anomalies:
                stats["anomalies"] += len(anomalies)
                correlated = correlation.correlate(anomalies)
                threat = classifier.classify(correlated)
                mit = mitigation.generate(threat)

                if threat["severity"] == "Critical":
                    stats["critical"] += 1

                try:
                    ai_reasoning = reasoning.reason(threat)
                except Exception:
                    ai_reasoning = "AI reasoning unavailable (Ollama not running)."

                vicar_analysis = vicar.analyze(threat)

                recent_alerts.appendleft({
                    "timestamp": datetime.now().strftime("%H:%M:%S"),
                    "threat_type": threat["threat_type"],
                    "origin": threat["origin"],
                    "severity": threat["severity"],
                    "confidence": threat["confidence"],
                    "indicators": threat["indicators"],
                    "containment": mit["containment"],
                    "mitigation": mit["mitigation"],
                    "recovery": mit["recovery"],
                    "reasoning": ai_reasoning,
                    "vicar": vicar_analysis,
                })

        except Exception as e:
            print(f"[HERA Loop Error] {e}")

        time.sleep(3)



@app.get("/api/stats")
def get_stats():
    return {
        "total_events": stats["total_events"],
        "anomalies": stats["anomalies"],
        "critical": stats["critical"],
        "users_monitored": len(stats["users"]),
    }


@app.get("/api/events")
def get_events():
    return list(recent_events)


@app.get("/api/alerts")
def get_alerts():
    return list(recent_alerts)


static_dir = os.path.join(os.path.dirname(__file__), "static")
app.mount("/static", StaticFiles(directory=static_dir), name="static")


@app.get("/")
def index():
    return FileResponse(os.path.join(static_dir, "index.html"))


if __name__ == "__main__":
    uvicorn.run("server:app", host="127.0.0.1", port=8000, reload=False)
