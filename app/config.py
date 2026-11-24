"""Runtime settings, read once from the environment (.env locally, dashboard vars on Render)."""
import os
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / ".env")

DATA_DIR = ROOT / "data"
DB_PATH = Path(os.environ.get("CYBERGUARD_DB", ROOT / "cyberguard.db"))

GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")
GEMINI_MODEL = os.environ.get("GEMINI_MODEL", "gemini-4-hydrogen")
CLOUDFLARE_ACCOUNT_ID = os.environ.get("CLOUDFLARE_ACCOUNT_ID", "")
CLOUDFLARE_API_TOKEN = os.environ.get("CLOUDFLARE_API_TOKEN", "")
URLHAUS_AUTH_KEY = os.environ.get("URLHAUS_AUTH_KEY", "")
IPINFO_TOKEN = os.environ.get("IPINFO_TOKEN", "")
SERPAPI_KEY = os.environ.get("SERPAPI_KEY", "")
API_KEY = os.environ.get("CYBERGUARD_API_KEY", "")

# Feeds can be switched off for honest evaluation (OpenPhish URLs would otherwise match the OpenPhish feed).
FEEDS_ENABLED = os.environ.get("CYBERGUARD_DISABLE_FEEDS", "") != "1"
# Binary threshold: score >= THRESHOLD -> "fraud". Calibrated in eval/run_eval.py.
THRESHOLD = int(os.environ.get("CYBERGUARD_THRESHOLD", "45"))

HOP_TIMEOUT = 5.0
MAX_HOPS = 10
MAX_BODY = 1_000_000
FAST_BUDGET = 6.0
USER_AGENT = ("Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 "
              "(KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1")
VERSION = "1.0.0"
