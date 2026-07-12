class ResponseEngine:

    def build_response(self, threat, mitigation, reasoning):
        lines = [
            "========== HERA ALERT ==========",
            f"Threat Type: {threat['threat_type']}",
            f"Origin:      {threat['origin']}",
            f"Severity:    {threat['severity']}",
            f"Confidence:  {threat['confidence']}%",
            "\nIndicators:",
        ]
        for i in threat["indicators"]:
            lines.append(f"  - {i}")

        lines.append("\nContainment Actions:")
        for c in mitigation["containment"]:
            lines.append(f"  - {c}")

        lines.append("\nMitigation Steps:")
        for m in mitigation["mitigation"]:
            lines.append(f"  - {m}")

        lines.append("\nRecovery Actions:")
        for r in mitigation["recovery"]:
            lines.append(f"  - {r}")

        lines.append(f"\nAI Reasoning:\n{reasoning}")
        lines.append("================================\n")

        return "\n".join(lines)
