"""
Progress Tracker - SQLite-based persistence for lab completion.

Tracks:
- Lab completion status and scores
- CTF flags captured
- Capstone project progress
- Session statistics
"""

import json
import os
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional


class ProgressTracker:
    """Track and persist learning progress across sessions."""

    def __init__(self, db_path: Optional[str] = None):
        """
        Initialize progress tracker.

        Args:
            db_path: Path to SQLite database. Defaults to .progress.db in project root.
        """
        if db_path is None:
            db_path = os.environ.get(
                "PROGRESS_DB_PATH",
                str(Path(__file__).parent.parent / ".progress.db")
            )
        self.db_path = Path(db_path)
        self._init_database()

    def _init_database(self) -> None:
        """Create database tables if they don't exist."""
        with sqlite3.connect(self.db_path) as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS labs (
                    lab_id TEXT PRIMARY KEY,
                    completed_at TIMESTAMP,
                    score INTEGER DEFAULT 0,
                    time_spent_minutes INTEGER DEFAULT 0,
                    notes TEXT
                );

                CREATE TABLE IF NOT EXISTS ctf_flags (
                    challenge_id TEXT PRIMARY KEY,
                    captured_at TIMESTAMP,
                    points INTEGER DEFAULT 0,
                    hints_used INTEGER DEFAULT 0
                );

                CREATE TABLE IF NOT EXISTS capstones (
                    project_id TEXT PRIMARY KEY,
                    started_at TIMESTAMP,
                    completed_at TIMESTAMP,
                    status TEXT DEFAULT 'not_started',
                    notes TEXT
                );

                CREATE TABLE IF NOT EXISTS sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    ended_at TIMESTAMP,
                    labs_completed INTEGER DEFAULT 0,
                    flags_captured INTEGER DEFAULT 0
                );

                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value TEXT
                );
            """)

    # === Lab Progress ===

    def mark_lab_complete(
        self,
        lab_id: str,
        score: int = 100,
        time_spent: int = 0,
        notes: str = ""
    ) -> None:
        """Mark a lab as completed."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT OR REPLACE INTO labs (lab_id, completed_at, score, time_spent_minutes, notes)
                VALUES (?, ?, ?, ?, ?)
            """, (lab_id, datetime.now().isoformat(), score, time_spent, notes))

    def get_lab_status(self, lab_id: str) -> Optional[Dict]:
        """Get completion status for a specific lab."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT * FROM labs WHERE lab_id = ?", (lab_id,)
            ).fetchone()
            return dict(row) if row else None

    def get_all_labs(self) -> List[Dict]:
        """Get all lab progress records."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute("SELECT * FROM labs ORDER BY completed_at").fetchall()
            return [dict(row) for row in rows]

    def get_completed_lab_count(self) -> int:
        """Get count of completed labs."""
        with sqlite3.connect(self.db_path) as conn:
            result = conn.execute("SELECT COUNT(*) FROM labs").fetchone()
            return result[0] if result else 0

    # === CTF Progress ===

    def capture_flag(
        self,
        challenge_id: str,
        points: int = 100,
        hints_used: int = 0
    ) -> None:
        """Record a captured CTF flag."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT OR REPLACE INTO ctf_flags (challenge_id, captured_at, points, hints_used)
                VALUES (?, ?, ?, ?)
            """, (challenge_id, datetime.now().isoformat(), points, hints_used))

    def get_ctf_progress(self) -> Dict:
        """Get CTF progress summary."""
        with sqlite3.connect(self.db_path) as conn:
            flags = conn.execute("SELECT COUNT(*) FROM ctf_flags").fetchone()[0]
            points = conn.execute("SELECT COALESCE(SUM(points), 0) FROM ctf_flags").fetchone()[0]
            return {"flags_captured": flags, "total_points": points}

    def get_captured_flags(self) -> List[str]:
        """Get list of captured challenge IDs."""
        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute("SELECT challenge_id FROM ctf_flags").fetchall()
            return [row[0] for row in rows]

    # === Capstone Progress ===

    def start_capstone(self, project_id: str) -> None:
        """Mark a capstone project as started."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT OR REPLACE INTO capstones (project_id, started_at, status)
                VALUES (?, ?, 'in_progress')
            """, (project_id, datetime.now().isoformat()))

    def complete_capstone(self, project_id: str, notes: str = "") -> None:
        """Mark a capstone project as completed."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                UPDATE capstones SET completed_at = ?, status = 'completed', notes = ?
                WHERE project_id = ?
            """, (datetime.now().isoformat(), notes, project_id))

    def get_capstone_status(self) -> List[Dict]:
        """Get all capstone project statuses."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute("SELECT * FROM capstones").fetchall()
            return [dict(row) for row in rows]

    # === Overall Progress ===

    def get_overall_progress(self) -> Dict:
        """Get complete progress summary."""
        labs = self.get_all_labs()
        ctf = self.get_ctf_progress()
        capstones = self.get_capstone_status()

        total_labs = 24  # Labs 00a-00d + 01-20
        total_ctf = 15   # CTF challenges
        total_capstones = 4

        return {
            "labs": {
                "completed": len(labs),
                "total": total_labs,
                "percentage": round(len(labs) / total_labs * 100, 1),
                "details": labs
            },
            "ctf": {
                "flags_captured": ctf["flags_captured"],
                "total": total_ctf,
                "points": ctf["total_points"],
                "percentage": round(ctf["flags_captured"] / total_ctf * 100, 1)
            },
            "capstones": {
                "completed": len([c for c in capstones if c.get("status") == "completed"]),
                "in_progress": len([c for c in capstones if c.get("status") == "in_progress"]),
                "total": total_capstones,
                "details": capstones
            }
        }

    def export_progress(self, filepath: str) -> None:
        """Export progress to JSON file."""
        progress = self.get_overall_progress()
        progress["exported_at"] = datetime.now().isoformat()
        with open(filepath, "w") as f:
            json.dump(progress, f, indent=2)

    def reset_progress(self, confirm: bool = False) -> bool:
        """Reset all progress. Requires confirmation."""
        if not confirm:
            return False
        with sqlite3.connect(self.db_path) as conn:
            conn.executescript("""
                DELETE FROM labs;
                DELETE FROM ctf_flags;
                DELETE FROM capstones;
                DELETE FROM sessions;
            """)
        return True


# Singleton instance for easy import
_tracker: Optional[ProgressTracker] = None


def get_tracker() -> ProgressTracker:
    """Get or create the global progress tracker instance."""
    global _tracker
    if _tracker is None:
        _tracker = ProgressTracker()
    return _tracker


if __name__ == "__main__":
    # Demo usage
    tracker = ProgressTracker()

    print("=== Progress Tracker Demo ===\n")

    # Mark some progress
    tracker.mark_lab_complete("lab01", score=95, time_spent=45)
    tracker.mark_lab_complete("lab02", score=100, time_spent=30)
    tracker.capture_flag("beginner-01", points=100)

    # Show progress
    progress = tracker.get_overall_progress()
    print(f"Labs completed: {progress['labs']['completed']}/{progress['labs']['total']}")
    print(f"CTF flags: {progress['ctf']['flags_captured']}/{progress['ctf']['total']}")
    print(f"Total CTF points: {progress['ctf']['points']}")
