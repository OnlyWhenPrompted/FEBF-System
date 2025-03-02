from fastapi import FastAPI, UploadFile, File
from modules.event_fingerprinting import EventFingerprinting
from modules.behavior_analysis import BehaviorAnalysis

app = FastAPI()

fingerprinting = EventFingerprinting()
behavior_analysis = BehaviorAnalysis()

@app.post("/upload/")
async def upload_file(file: UploadFile):
    """Receives a file upload and runs forensic fingerprinting."""
    file_hash = fingerprinting.generate_file_hash(file.filename)
    is_flagged = fingerprinting.check_fingerprint(file.filename)
    
    return {"file_hash": file_hash, "flagged": is_flagged}

@app.post("/behavior/")
async def check_behavior(user_id: str, file_hash: str):
    """Runs behavior analysis to check for suspicious activity."""
    risk = behavior_analysis.analyze_upload_pattern(user_id, time.time(), file_hash)
    return risk

# Run server
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000)
