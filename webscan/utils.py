from .models import Log
from django.contrib.contenttypes.models import ContentType

def create_log_entry(user, action):
    Log.objects.create(
        user=user,
        action=action
    )