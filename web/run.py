"""Entry point for the HexWarden web dashboard.

Usage:
    python3 web/run.py

Starts the Flask dashboard at http://localhost:5000 (or
config.WEB_HOST/config.WEB_PORT, if changed).
"""

import logging
import sys
from pathlib import Path

# Running this file directly (`python3 web/run.py`) puts web/ itself on
# sys.path, not the project root -- `import config` and `from web.app
# import app` both need the root instead, so it's inserted explicitly
# before either import runs. `python3 -m web.run` from the project root
# doesn't need this, but doesn't break from it either.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import config
from web.app import app

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format=config.LOG_FORMAT)
    app.run(host=config.WEB_HOST, port=config.WEB_PORT, debug=False, threaded=True)
