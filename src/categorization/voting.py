class VotingSystem:
    def __init__(self):
        self.weights = {
            'gemini': 1.0,
            'chatgpt': 1.0,
            'llama': 1.0
        }

    def vote(self, responses, field):
        """
        Implement weighted voting for a specific field across AI responses.
        """
        if not responses:
            return "Unknown"

        # Count occurrences with weights
        weighted_votes = {}
        for source, response in responses.items():
            value = str(response.get(field, '')).strip()
            if value:
                weight = self.weights.get(source, 1.0)
                weighted_votes[value] = weighted_votes.get(value, 0) + weight

        # Return the value with highest weighted votes
        if weighted_votes:
            return max(weighted_votes.items(), key=lambda x: x[1])[0]
        return "Unknown"

    def combine_results(self, gemini_result, gpt_result, llama_result):
        """
        Combine results from different AI sources using weighted voting.
        """
        responses = {
            'gemini': gemini_result[0] if gemini_result else {},
            'chatgpt': gpt_result[0] if gpt_result else {},
            'llama': llama_result[0] if llama_result else {}
        }

        return [{
            "cwe_category": self.vote(responses, "cwe_category"),
            "explanation": self.vote(responses, "explanation"),
            "vendor": self.vote(responses, "vendor"),
            "cause": self.vote(responses, "cause"),
            "impact": self.vote(responses, "impact")
        }]