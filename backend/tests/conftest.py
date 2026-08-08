"""Ensure the backend package dir is importable when running pytest from ./backend."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))