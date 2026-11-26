"""Central configuration loader for AI Lateral Movement Detection."""

import json
import os
from typing import Any, Dict

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_CONFIG_PATH = os.path.join(BASE_DIR, "config.json")


def load_config(config_path: str | None = None) -> Dict[str, Any]:
    """Load configuration from JSON and resolve relative paths against BASE_DIR."""
    path = config_path or os.environ.get("ALMD_CONFIG_PATH", DEFAULT_CONFIG_PATH)
    with open(path, "r", encoding="utf-8") as f:
        cfg = json.load(f)

    resolved_paths: Dict[str, str] = {}
    for key, rel_path in cfg.get("paths", {}).items():
        if os.path.isabs(rel_path):
            resolved_paths[key] = rel_path
        else:
            resolved_paths[key] = os.path.join(BASE_DIR, rel_path)
    cfg["paths"] = resolved_paths
    cfg["base_dir"] = BASE_DIR
    return cfg
