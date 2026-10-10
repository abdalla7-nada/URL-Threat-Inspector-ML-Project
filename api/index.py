"""
Vercel Serverless Function entrypoint for CyberSec URL Threat Assessment API.
Exposes the FastAPI instance for native @vercel/python serverless execution.
"""

import os
import sys

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
BACKEND_DIR = os.path.join(os.path.dirname(CURRENT_DIR), "backend")
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from main import app
