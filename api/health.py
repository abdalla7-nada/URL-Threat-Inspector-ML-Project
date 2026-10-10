"""
Vercel Serverless Function entrypoint for /api/health and /health.
Direct handler for diagnostic health check invocations.
"""

import os
import sys

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

from main import app
