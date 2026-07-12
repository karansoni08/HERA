class CorrelationEngine:

    def correlate(self, anomalies):
        return [{"timeline": "Login -> Escalation -> USB Access", "data": anomaly} for anomaly in anomalies]
