"""
Google Calendar Service — Future integration.

Handles Calendar CRUD operations via the Google Calendar API with
a service account key. Every operation requires Telegram approval.

To implement:
  1. Copy the calendar-sa-key.json to the proxy machine
  2. Set services.calendar in config.yaml
  3. Implement validate(), execute(), and approval_text()
"""

# from services import BaseService, service
# from google.oauth2 import service_account
# from googleapiclient.discovery import build

# @service("calendar")
# class CalendarService(BaseService):
#     """Placeholder for Google Calendar integration."""
#
#     @classmethod
#     def validate(cls, action, data):
#         pass
#
#     @classmethod
#     def execute(cls, action, data, config):
#         pass
#
#     @classmethod
#     def approval_text(cls, action, data, request_id):
#         return "..."
