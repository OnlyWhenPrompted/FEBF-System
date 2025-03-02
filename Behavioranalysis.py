import json
import time

class BehaviorAnalysis:
    def __init__(self):
        self.suspicious_users = {}

    def analyze_upload_pattern(self, user_id, timestamp, file_hash):
        """Tracks user upload patterns to identify suspicious behavior."""
        if user_id not in self.suspicious_users:
            self.suspicious_users[user_id] = []
        
        self.suspicious_users[user_id].append({"time": timestamp, "file_hash": file_hash})
        return self.evaluate_risk(user_id)

    def evaluate_risk(self, user_id):
        """Assigns a risk score based on upload behavior."""
        uploads = self.suspicious_users[user_id]
        if len(uploads) > 10:
            return {"user_id": user_id, "risk_score": 90, "status": "HIGH"}
        return {"user_id": user_id, "risk_score": 40, "status": "LOW"}

# Example Usage
if __name__ == "__main__":
    ba = BehaviorAnalysis()
    test_user = "user_12345"
    
    for _ in range(12):
        risk = ba.analyze_upload_pattern(test_user, time.time(), "sample_file_hash")
    
    print(f"Risk assessment: {json.dumps(risk, indent=2)}")
