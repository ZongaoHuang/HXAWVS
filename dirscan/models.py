from django.db import models
from django.contrib.auth.models import User

class DirectoryScan(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    target = models.CharField(max_length=255)
    status = models.CharField(max_length=10, choices=[('process', 'Processing'), ('finish', 'Finished')])
    scan_time = models.DateTimeField(auto_now_add=True)
    result_path = models.CharField(max_length=255, blank=True, null=True)
    pid = models.IntegerField(null=True, blank=True)

    def __str__(self):
        return f"Scan of {self.target} - {self.status}"