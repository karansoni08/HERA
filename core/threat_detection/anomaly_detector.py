class AnomalyDetector:

    def detect(self, analyzed_logs):
        return [item for item in analyzed_logs if item["risk_score"] >= 50]
