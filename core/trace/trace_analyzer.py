class TRACEAnalyzer:
    """
    TRACE Framework: Threat → Root Cause → Actor → Containment → Exposure
    Determines how a detected vulnerability was exploited based on threat indicators.
    """

    def analyze(self, threat: dict) -> dict:
        indicators = threat.get("indicators", [])
        origin     = threat.get("origin", "Internal")
        severity   = threat.get("severity", "Medium")

        has_usb     = "USB Device Connected"   in indicators
        has_privesc = "Privilege Escalation"   in indicators
        has_brute   = "Multiple Failed Logins" in indicators

        return {
            "threat":      self._threat(has_usb, has_privesc, has_brute, origin),
            "root_cause":  self._root_cause(has_usb, has_privesc, has_brute),
            "actor":       self._actor(origin, has_privesc),
            "containment": self._containment(has_usb, has_privesc, has_brute),
            "exposure":    self._exposure(has_usb, has_privesc, severity),
        }

    def _threat(self, usb, privesc, brute, origin):
        parts = []
        if brute:
            parts.append("Repeated failed authentication attempts suggest a brute-force or credential-stuffing attack as the initial access vector.")
        if usb:
            parts.append("A USB device was connected, indicating a physical media attack vector for data staging or exfiltration.")
        if privesc:
            parts.append("Privilege escalation was triggered after initial access, elevating the attacker's foothold.")
        if origin == "External" and not brute:
            parts.append("Access originated from an unknown external location, suggesting stolen credentials or VPN compromise.")
        return " ".join(parts) if parts else "Access path unclear; user session was active at time of detection."

    def _exposure(self, usb, privesc, severity):
        impacts = []
        if privesc:
            impacts.append("Elevated privileges may allow full system or domain compromise.")
        if usb:
            impacts.append("Data exfiltration via removable media could result in sensitive data loss.")
        if severity == "Critical":
            impacts.append("Critical severity indicates high likelihood of active exploitation with broad blast radius.")
        else:
            impacts.append("Moderate risk of unauthorized data access or account takeover.")
        return " ".join(impacts)

    def _root_cause(self, usb, privesc, brute):
        causes = []
        if brute:
            causes.append("Weak or absent account lockout policy allowed repeated login attempts.")
        if privesc:
            causes.append("Overly permissive privilege configuration or missing least-privilege enforcement.")
        if usb:
            causes.append("No USB device restriction policy enforced at endpoint level.")
        return " ".join(causes) if causes else "Misconfigured access controls or monitoring gap enabled the activity."

    def _actor(self, origin, privesc):
        if origin == "Internal":
            if privesc:
                return "Insider threat — a credentialed user abused elevated access privileges. Likely a malicious insider or a compromised internal account with active session."
            return "Insider threat — authenticated internal user exhibiting anomalous behavior. Could be a negligent employee or a compromised account."
        return "External threat actor — access originated from an unknown location. Likely involves stolen credentials, phishing, or a previously established backdoor."

    def _containment(self, usb, privesc, brute):
        steps = []
        if brute:
            steps.append("Enforce account lockout after 3 failed attempts and mandate MFA across all accounts.")
        if privesc:
            steps.append("Audit and revoke unnecessary elevated privileges. Implement Privileged Access Management (PAM).")
        if usb:
            steps.append("Deploy endpoint DLP policy to block or audit USB device connections.")
        steps.append("Isolate the affected user session and conduct a full forensic review of accessed resources.")
        steps.append("Review authentication logs for lateral movement or further compromise.")
        return steps
