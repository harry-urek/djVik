from django.db import models
from django.contrib.auth.models import AbstractUser
from django.forms import ValidationError

class User(AbstractUser):
    is_ops_user = models.BooleanField(default=False)

class File(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    file = models.FileField(upload_to='uploads/')
    upload_date = models.DateTimeField(auto_now_add=True)
    allowed_types = ['pptx', 'docx', 'xlsx']

    def validate_file_extension(value):
        ext = value.name.split('.')[-1]
        if ext.lower() not in File.allowed_types:
            raise ValidationError('Unsupported file extension.')

class EncryptedURL(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    file = models.ForeignKey(File, on_delete=models.CASCADE)
    url = models.CharField(max_length=255)