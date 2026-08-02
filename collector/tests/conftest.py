"""Shared pytest fixtures for the collector agent tests.

Adds the collector root to sys.path so `agent_client` (which does a relative
`sys.path.insert`) imports cleanly under pytest.
"""
import os
import sys

_COLLECTOR_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _COLLECTOR_DIR not in sys.path:
    sys.path.insert(0, _COLLECTOR_DIR)
