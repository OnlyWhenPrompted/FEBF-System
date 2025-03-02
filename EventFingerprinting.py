import hashlib
import os
import json
import sqlite3

class EventFingerprinting:
    def __init__(self, db_path="data/forensic_hashes.db"):
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path)
        self.cursor = self.conn.cursor()
        self.initialize_db()

    def initialize_db(self):
        """Ensures forensic hash database is structured properly."""
        self.cursor.execute('''CREATE TABLE IF NOT EXISTS forensic_hashes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_hash TEXT UNIQUE,
            event_sequence TEXT,
            last_modified TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''')
        self.conn.commit()

    def generate_file_hash(self, file_path):
        """Creates a SHA-256 hash for forensic tracking."""
        hasher = hashlib.sha256()
        with open(file_path, 'rb') as file:
            while chunk := file.read(8192):
                hasher.update(chunk)
        return hasher.hexdigest()

    def store_fingerprint(self, file_path, event_sequence):
        """Stores a new forensic fingerprint with event sequencing."""
        file_hash = self.generate_file_hash(file_path)
        self.cursor.execute("INSERT OR IGNORE INTO forensic_hashes (file_hash, event_sequence) VALUES (?, ?)", 
                            (file_hash, json.dumps(event_sequence)))
        self.conn.commit()

    def check_fingerprint(self, file_path):
        """Checks if a file is flagged in forensic tracking."""
        file_hash = self.generate_file_hash(file_path)
        self.cursor.execute("SELECT * FROM forensic_hashes WHERE file_hash=?", (file_hash,))
        return self.cursor.fetchone() is not None

# Usage Example
if __name__ == "__main__":
    ef = EventFingerprinting()
    sample_file = "data/sample_video.mp4"
    event_sequence = {"upload_site": "Unknown", "modifications": [], "first_seen": "2025-02-28"}
    
    ef.store_fingerprint(sample_file, event_sequence)
    print("File fingerprinting complete.")
