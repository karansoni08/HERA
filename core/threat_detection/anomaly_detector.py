class AnomalyDetector:

    def detect(self, analyzed_logs):

        anomalies = []

        for item in analyzed_logs:

            if item["risk_score"] >= 50:

                anomalies.append(item)

        return anomalies