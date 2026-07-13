import time

from core.collection.log_collector import LogCollector
from core.processing.event_normalizer import EventNormalizer
from core.behavioral_analysis.user_baseline import UserBaselineEngine
from core.threat_detection.anomaly_detector import AnomalyDetector
from core.attribution.threat_classifier import ThreatClassifier
from core.correlation.correlation_engine import CorrelationEngine
from core.response_engine.mitigation_generator import MitigationGenerator
from core.response_engine.response_engine import ResponseEngine
from core.ai_reasoning.autonomous_reasoning import AutonomousReasoning
from core.trace.trace_analyzer import TRACEAnalyzer
from core.database.db import init_db, log_event, log_threat


class HERA:

    def __init__(self):
        init_db()
        self.collector = LogCollector()
        self.normalizer = EventNormalizer()
        self.baseline = UserBaselineEngine()
        self.detector = AnomalyDetector()
        self.classifier = ThreatClassifier()
        self.correlation = CorrelationEngine()
        self.mitigation = MitigationGenerator()
        self.response_engine = ResponseEngine()
        self.reasoning = AutonomousReasoning()
        self.trace = TRACEAnalyzer()

    def run(self):
        print("[HERA] Monitoring Started...\n")
        while True:
            raw_logs = self.collector.collect()
            normalized_logs = self.normalizer.normalize(raw_logs)
            baseline_results = self.baseline.analyze(normalized_logs)

            for item in baseline_results:
                log_event(item["event"], item["risk_score"], item["risk_score"] >= 50)

            anomalies = self.detector.detect(baseline_results)

            if anomalies:
                correlated = self.correlation.correlate(anomalies)
                threat = self.classifier.classify(correlated)
                trace_result = self.trace.analyze(threat)
                top = max(anomalies, key=lambda x: x["risk_score"])
                log_threat(
                    user=top["event"]["user"],
                    risk_score=top["risk_score"],
                    severity=threat["severity"],
                    origin=threat["origin"],
                    indicators=threat["indicators"],
                    trace_result=trace_result,
                )
                mitigation = self.mitigation.generate(threat)
                reasoning = self.reasoning.reason(threat)
                response = self.response_engine.build_response(threat, mitigation, reasoning)
                print(response)

            time.sleep(3)


if __name__ == "__main__":
    HERA().run()
