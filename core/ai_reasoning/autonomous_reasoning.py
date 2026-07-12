import os
import ollama


class AutonomousReasoning:

    def __init__(self):
        self.model = os.getenv("OLLAMA_MODEL", "qwen2.5:7b")

    def reason(self, threat):
        prompt = f"""You are a cybersecurity AI analyst.

Analyze the following threat.

Threat Type: {threat['threat_type']}
Origin: {threat['origin']}
Indicators: {threat['indicators']}

Explain:
1. Why this is dangerous
2. Possible attacker intent
3. Escalation risks
4. Recommended investigation priority
"""
        response = ollama.chat(
            model=self.model,
            messages=[{"role": "user", "content": prompt}]
        )
        return response["message"]["content"]
