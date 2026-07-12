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


class HERA:

    def __init__(self):
        self.collector = LogCollector()
        self.normalizer = EventNormalizer()
        self.baseline = UserBaselineEngine()
        self.detector = AnomalyDetector()
        self.classifier = ThreatClassifier()
        self.correlation = CorrelationEngine()
        self.mitigation = MitigationGenerator()
        self.response_engine = ResponseEngine()
        self.reasoning = AutonomousReasoning()

    def run(self):
        print("[HERA] Monitoring Started...\n")
        while True:
            raw_logs = self.collector.collect()
            normalized_logs = self.normalizer.normalize(raw_logs)
            baseline_results = self.baseline.analyze(normalized_logs)
            anomalies = self.detector.detect(baseline_results)

            if anomalies:
                correlated = self.correlation.correlate(anomalies)
                threat = self.classifier.classify(correlated)
                mitigation = self.mitigation.generate(threat)
                reasoning = self.reasoning.reason(threat)
                response = self.response_engine.build_response(threat, mitigation, reasoning)
                print(response)

            time.sleep(3)


if __name__ == "__main__":
    HERA().run()
