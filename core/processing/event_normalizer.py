class EventNormalizer:

    def normalize(self, logs):
        return [{
            "user": log["user"].lower(),
            "action": log["action"].lower(),
            "location": log["location"].lower(),
            "failed_attempts": int(log["failed_attempts"]),
            "usb_connected": bool(log["usb_connected"]),
            "privilege_escalation": bool(log["privilege_escalation"])
        } for log in logs]
