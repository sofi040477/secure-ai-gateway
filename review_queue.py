"""Cola de revisión: HUMANO EN EL CIRCUITO para solicitudes con decisión REVIEW."""
import json
from datetime import datetime
from pathlib import Path
from typing import Optional


class ReviewQueue:
    def __init__(self, log_dir: Path):
        self.path = Path(log_dir) / "review_queue.json"
        Path(log_dir).mkdir(parents=True, exist_ok=True)

    def _load(self) -> dict:
        if not self.path.exists():
            return {}
        return json.loads(self.path.read_text(encoding="utf-8"))

    def _save(self, data: dict) -> None:
        self.path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")

    def add(self, review_id: str, user: str, prompt: str, external: Optional[str], reasons: list) -> None:
        data = self._load()
        data[review_id] = {"user": user, "prompt": prompt, "external": external, "reasons": reasons,
                           "status": "PENDING", "created": datetime.now().isoformat(timespec="seconds"),
                           "reviewer": None}
        self._save(data)

    def pending(self) -> dict:
        return {k: v for k, v in self._load().items() if v["status"] == "PENDING"}

    def get(self, review_id: str) -> Optional[dict]:
        return self._load().get(review_id)

    def resolve(self, review_id: str, approved: bool, reviewer: str) -> None:
        data = self._load()
        data[review_id].update(status="APPROVED" if approved else "REJECTED", reviewer=reviewer,
                               resolved=datetime.now().isoformat(timespec="seconds"))
        self._save(data)
