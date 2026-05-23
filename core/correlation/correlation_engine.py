class CorrelationEngine:

    def correlate(self, anomalies):

        correlated = []

        for anomaly in anomalies:

            correlated.append({

                "timeline":
                "Login -> Escalation -> USB Access",

                "data": anomaly

            })

        return correlated