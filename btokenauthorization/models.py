import datetime
import uuid

from django.db import models
from django.conf import settings


class AccessToken(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    key = models.CharField(max_length=64, null=True, blank=True)
    expire_date = models.DateTimeField(null=True)

    @classmethod
    def generate(cls, user: settings.AUTH_USER_MODEL):
        instance, created = cls.objects.get_or_create(user=user)
        instance.key = f'{uuid.uuid4()}{uuid.uuid4()}'.replace('-', '')
        instance.expire_date = datetime.datetime.now() + datetime.timedelta(days=settings.TOKEN_EXPIRE_DAYS)
        instance.save()
        return instance
