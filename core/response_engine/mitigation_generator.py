class MitigationGenerator:

    def generate(self, threat):

        return {

            "containment": [

                "Disable user account",

                "Terminate active sessions",

                "Block connected USB devices"

            ],

            "mitigation": [

                "Rotate credentials",

                "Audit sensitive file access",

                "Enable enhanced monitoring"

            ],

            "recovery": [

                "Restore affected systems",

                "Review system integrity",

                "Re-enable logging services"

            ]
        }