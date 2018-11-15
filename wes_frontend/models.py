from django.db import models


class UserTokens(models.Model):
    user = models.CharField(max_length=256, unique=True)
    access_token = models.TextField()
    refresh_token = models.TextField()
