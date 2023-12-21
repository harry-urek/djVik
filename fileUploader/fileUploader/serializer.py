import base64
from django import serializers
from .models import CustomUser, EncryptedURL, File

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ['username', 'email', 'password']

class FileSerializer(serializers.ModelSerializer):
    encrypted_url = serializers.SerializerMethodField()
    
    class Meta:
        model = File
        fields = ['file']
        
    def get_encrypted_url(self, obj):
        # For simplicity, using base64 encoding of the file content as the "encrypted" URL
        return base64.b64encode(obj.file.read()).decode('utf-8')

class EncryptedURLSerializer(serializers.ModelSerializer):
    class Meta:
        model = EncryptedURL
        fields = ['url']