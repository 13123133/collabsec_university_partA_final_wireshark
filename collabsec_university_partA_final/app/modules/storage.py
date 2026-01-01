from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any, Dict, List


@dataclass(frozen=True)
class DataFiles:
    users: str = "users.json"
    iocs: str = "iocs.json"
    incidents: str = "incidents.json"
    audit: str = "audit.json"
    notifications: str = "notifications.json"


class JsonStore:
    """
    Tiny JSON list storage layer (prototype-level).
    Each file contains a JSON list of dictionaries.
    """

    def __init__(self, data_dir: str) -> None:
        self._data_dir = os.path.normpath(data_dir)
        os.makedirs(self._data_dir, exist_ok=True)

    def _path(self, filename: str) -> str:
        return os.path.join(self._data_dir, filename)

    def ensure_file(self, filename: str) -> None:
        """Ensure the file exists and contains a JSON list."""
        os.makedirs(self._data_dir, exist_ok=True)
        path = self._path(filename)

        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                if not isinstance(data, list):
                    raise ValueError("Not a list")
            except Exception:
                with open(path, "w", encoding="utf-8") as f:
                    f.write("[]\n")
            return

        with open(path, "w", encoding="utf-8") as f:
            f.write("[]\n")

    def read_list(self, filename: str) -> List[Dict[str, Any]]:
        self.ensure_file(filename)
        path = self._path(filename)
        with open(path, "r", encoding="utf-8") as f:
            try:
                data = json.load(f)
            except json.JSONDecodeError:
                return []
        return data if isinstance(data, list) else []

    def write_list(self, filename: str, data: List[Dict[str, Any]]) -> None:
        os.makedirs(self._data_dir, exist_ok=True)
        path = self._path(filename)
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2, default=str)
        os.replace(tmp, path)
