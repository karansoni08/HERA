from core.ai_reasoning.ollama_engine import OllamaEngine


class AutonomousReasoning:

    def __init__(self):

        self.llm = OllamaEngine()

    def reason(self, threat):

        prompt = f"""

You are a cybersecurity AI analyst.

Analyze the following threat.

Threat Type:
{threat['threat_type']}

Origin:
{threat['origin']}

Indicators:
{threat['indicators']}

Explain:
1. Why this is dangerous
2. Possible attacker intent
3. Escalation risks
4. Recommended investigation priority

"""

        return self.llm.analyze(prompt)