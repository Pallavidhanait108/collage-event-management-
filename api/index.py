import sys
import os

# Add the subdirectory to the Python path so we can import app.py
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "College Event Management System"))

from app import app  # noqa: E402 — import after path manipulation

# Vercel looks for a variable named `app` in this file.
