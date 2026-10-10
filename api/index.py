"""
Vercel Serverless Function entrypoint for / (root) and /api.
Exposes the FastAPI instance for native @vercel/python serverless execution.
"""

import os
import sys

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

from main import app
