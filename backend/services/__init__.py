"""Business-logic layer for the DFIR backend.

Route handlers in main.py / detection_routes.py stay thin and delegate here.
The detection pipeline lives in detection_service so the scheduler and the
HTTP trigger share one implementation.
"""
