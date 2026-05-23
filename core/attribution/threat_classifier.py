class ThreatClassifier:

    def classify(self, correlated_data):

        indicators = []

        origin = "Internal"

        severity = "Medium"

        for item in correlated_data:

            event = item["data"]["event"]

            if event["usb_connected"]:
                indicators.append(
                    "USB Device Connected"
                )

            if event["privilege_escalation"]:
                indicators.append(
                    "Privilege Escalation"
                )

            if event["failed_attempts"] > 3:
                indicators.append(
                    "Multiple Failed Logins"
                )

            if event["location"] == "unknown":
                origin = "External"

        if len(indicators) >= 2:
            severity = "Critical"

        return {

            "threat_type": "Suspicious User Activity",

            "origin": origin,

            "severity": severity,

            "confidence": 93,

            "indicators": indicators
        }