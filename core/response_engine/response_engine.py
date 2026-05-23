class ResponseEngine:

    def build_response(
        self,
        threat,
        mitigation,
        reasoning
    ):

        response = f"""

========== HERA ALERT ==========

Threat Type:
{threat['threat_type']}

Origin:
{threat['origin']}

Severity:
{threat['severity']}

Confidence:
{threat['confidence']}%

Indicators:
"""

        for i in threat["indicators"]:

            response += f"\n - {i}"

        response += "\n\nContainment Actions:"

        for c in mitigation["containment"]:

            response += f"\n - {c}"

        response += "\n\nMitigation Steps:"

        for m in mitigation["mitigation"]:

            response += f"\n - {m}"

        response += "\n\nRecovery Actions:"

        for r in mitigation["recovery"]:

            response += f"\n - {r}"

        response += "\n\nAI Reasoning:"

        response += f"\n{reasoning}"

        response += "\n\n===============================\n"

        return response