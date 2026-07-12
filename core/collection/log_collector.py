import random
from datetime import datetime


class LogCollector:

    def collect(self):
        sample_logs = [
            {
                "user": "john",
                "action": "login",
                "location": "canada",
                "failed_attempts": 0,
                "usb_connected": False,
                "privilege_escalation": False,
                "timestamp": str(datetime.now())
            },
            {
                "user": "admin",
                "action": "mass_download",
                "location": "unknown",
                "failed_attempts": 5,
                "usb_connected": True,
                "privilege_escalation": True,
                "timestamp": str(datetime.now())
            }
        ]
        return [random.choice(sample_logs)]
