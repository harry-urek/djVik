import base64
from django.conf import settings
from django.contrib.auth import authenticate, login
from django.core.exceptions import PermissionDenied
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated

from .token import AccountActivationTokenGenerator, PasswordResetTokenGenerator
from .models import User, File, EncryptedURL
from .serializer import UserSerializer, FileSerializer, EncryptedURLSerializer
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.utils.encoding import force_bytes, force_text
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.core.mail import EmailMessage, send_mail
from django.contrib.auth import login


@api_view(["POST"])
def user_signup(request):
    username = request.data.get("username")
    email = request.data.get("email")
    password = request.data.get("password")

    if User.objects.filter(username=username).exists():
        return Response(
            {"error": "Username already exists"}, status=status.HTTP_400_BAD_REQUEST
        )

    if User.objects.filter(email=email).exists():
        return Response(
            {"error": "Email already registered"}, status=status.HTTP_400_BAD_REQUEST
        )

    user = User(username=username, email=email)
    user.set_password(password)
    user.is_active = False  # User is inactive until email verification
    user.save()

    # Generate a unique token for email verification
    token = AccountActivationTokenGenerator.make_token(user)
    uidb64 = urlsafe_base64_encode(force_bytes(user.id)).decode("utf-8")
    activation_url = f"{settings.BASE_URL}/activate/{uidb64}/{token}"

    # Send email verification
    subject = "Activate Your Account"
    message = render_to_string(
        "email_verification_message.txt",
        {"user": user, "activation_url": activation_url},
    )
    to_email = user.email
    send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [to_email])

    return Response(
        {"message": "Account created. Check your email for activation instructions."},
        status=status.HTTP_201_CREATED,
    )


@api_view(["POST"])
def user_login(request):
    username = request.data.get("username")
    password = request.data.get("password")

    user = authenticate(request, username=username, password=password)

    if user is not None:
        login(request, user)
        serializer = UserSerializer(user)
        return Response(serializer.data)
    else:
        return Response(
            {"error": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED
        )


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def upload_file(request):
    if not request.user.is_ops_user:
        raise PermissionDenied("Only Ops User is allowed to upload files.")

    file_type = request.data.get("file_type")
    if file_type not in ["pptx", "docx", "xlsx"]:
        return Response(
            {"error": "Invalid file type"}, status=status.HTTP_400_BAD_REQUEST
        )

    serializer = FileSerializer(
        data={
            "user": request.user.id,
            "file_type": file_type,
            "file": request.FILES["file"],
        }
    )
    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data, status=status.HTTP_201_CREATED)
    else:
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def list_files(request):
    files = File.objects.filter(user=request.user)
    serializer = FileSerializer(files, many=True)

   
    serialized_data = serializer.data
    for data in serialized_data:
        data['encrypted_url'] = FileSerializer.get_encrypted_url(data['file'])

    return Response(serialized_data, status=status.HTTP_200_OK)


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def download_file(request, file_id):
    file_instance = File.objects.get(pk=file_id)

    # Check if the user is allowed to download the file
    if request.user != file_instance.user:
        raise PermissionDenied('You are not allowed to download this file.')

    # Use the updated serializer to get the "encrypted" URL
    serializer = FileSerializer(file_instance)

    # In this example, I'm using base64 encoding of the file content as a placeholder for the "encrypted" URL
    encrypted_url = serializer.data.get('encrypted_url')

    return Response({'encrypted_url': encrypted_url}, status=status.HTTP_200_OK)
    
