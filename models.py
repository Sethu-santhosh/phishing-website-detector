from django.db import models
from django.contrib.auth.models import User

class URLCheck(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True)
    url = models.URLField(max_length=2048)
    score = models.PositiveIntegerField(default=0)
    result = models.CharField(max_length=20)
    reasons = models.TextField(blank=True)
    checked_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.result}: {self.url}"
