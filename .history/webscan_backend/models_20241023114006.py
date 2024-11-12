from django.db import models

# Create your models here.
from django.db import models
from django.contrib.auth.models import User

class PortScan(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    target = models.CharField(max_length=255)
    scan_time = models.DateTimeField(auto_now_add=True)
    result_path = models.CharField(max_length=255, blank=True, null=True)
    status = models.CharField(max_length=10, choices=[('process', 'Processing'), ('finish', 'Finished')])

    def __str__(self):
        return f"{self.target} - {self.scan_time}"
    
    
class PortScan(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    target = models.CharField(max_length=255)
    scan_time = models.DateTimeField(auto_now_add=True)
    result_path = models.CharField(max_length=255, blank=True, null=True)
    status = models.CharField(max_length=10, choices=[('process', 'Processing'), ('finish', 'Finished')])

    def __str__(self):
        return f"{self.target} - {self.scan_time}"
    
    
        