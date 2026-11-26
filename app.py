"""Single-command GUI launcher for AegisLM (AI Lateral Movement Detection SOC)."""

import argparse
import os
import sys
import threading
import webbrowser

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from src.api.web_server import start_server
from src.utils.logger import get_logger

logger = get_logger("app")


def main() -> int:
    parser = argparse.ArgumentParser(description="Launch the AegisLM SOC Web GUI")
    parser.add_argument("--host", default="127.0.0.1", help="Bind host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8080, help="Port (default: 8080)")
    parser.add_argument("--no-browser", action="store_true", help="Do not auto-open browser")
    args = parser.parse_args()

    url = f"http://{args.host}:{args.port}"
    server = start_server(host=args.host, port=args.port)
    print(f"\n  AegisLM SOC Dashboard running at: {url}")
    print("  Press Ctrl+C to stop the server.\n")

    if not args.no_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Shutting down AegisLM GUI server...")
        server.shutdown()
    return 0


if __name__ == "__main__":
    sys.exit(main())
