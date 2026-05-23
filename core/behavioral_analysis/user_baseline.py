class UserBaselineEngine:

    def analyze(self, logs):

        analyzed = []

        for log in logs:

            risk_score = 0

            if log["failed_attempts"] > 3:
                risk_score += 30

            if log["usb_connected"]:
                risk_score += 30

            if log["privilege_escalation"]:
                risk_score += 40

            analyzed.append({

                "event": log,

                "risk_score": risk_score

            })

        return analyzed