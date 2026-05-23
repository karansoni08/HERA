import ollama


class OllamaEngine:

    def analyze(self, prompt):

        response = ollama.chat(

            model="qwen2.5:7b",

            messages=[

                {
                    "role": "user",
                    "content": prompt
                }

            ]

        )

        return response["message"]["content"]