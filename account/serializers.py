from xml.dom import ValidationErr
from django.forms import ValidationError
from rest_framework import serializers

from account.utils import Util
from .models import User
from django.utils.encoding import smart_str, force_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.auth.tokens import PasswordResetTokenGenerator


class UserRegistrationSerializer(serializers.ModelSerializer):
    password2 = serializers.CharField(style={"input_type": "password"}, write_only=True)

    class Meta:
        model = User
        fields = ["email", "name", "password", "password2", "tc"]
        extra_kwargs = {"password": {"write_only": True}}

    def validate(self, data):
        password = data.get("password")
        password2 = data.get("password2")
        if password != password2:
            raise serializers.ValidationError("Passwords must match.")
        return data

    def create(self, validated_data):
        password2 = validated_data.pop("password2", None)
        return User.objects.create_user(**validated_data)


class UserLoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=255)

    class Meta:
        model = User
        fields = ["email", "password"]


class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["id", "email", "name"]


class UserChangePasswordSerializer(serializers.Serializer):
    password = serializers.CharField(
        max_length=255, style={"input_type": "password"}, write_only=True
    )
    password2 = serializers.CharField(
        max_length=255, style={"input_type": "password"}, write_only=True
    )

    class Meta:
        fields = ["password", "password2"]

    def validate(self, data):
        password = data.get("password")
        password2 = data.get("password2")
        user = self.context.get("user")
        if password != password2:
            raise serializers.ValidationError("Passwords must match.")
        user.set_password(password)
        user.save()
        return data


class SendPasswordResetEmailSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=255)

    class Meta:
        fields = ["email"]

    def validate(self, attrs):
        email = attrs.get("email")
        if User.objects.filter(email=email).exists():
            user = User.objects.get(email=email)
            uid = urlsafe_base64_encode(force_bytes(user.id))
            token = PasswordResetTokenGenerator().make_token(user)
            link = f"http://localhost:3000/api/user/reset/{uid}/{token}"
            print(link)
            # send email
            body = f"Click the link below to reset your password\n{link}"
            data = {
                "subject": "Password Reset",
                "body": body,
                "to_email": user.email,
            }
            Util.send_email(data)
            return attrs
        else:
            raise ValidationErr("Email is not registered with us.")


class UserPasswordResetSerializer(serializers.Serializer):
    password = serializers.CharField(
        max_length=255, style={"input_type": "password"}, write_only=True
    )
    password2 = serializers.CharField(
        max_length=255, style={"input_type": "password"}, write_only=True
    )

    class Meta:
        fields = ["password", "password2"]

    def validate(self, data):
        try:
            password = data.get("password")
            password2 = data.get("password2")
            uid = self.context.get("uid")
            token = self.context.get("token")

            if password != password2:
                raise serializers.ValidationError("Passwords must match.")
            id = smart_str(urlsafe_base64_decode(uid))
            user = User.objects.get(id=id)
            if not PasswordResetTokenGenerator().check_token(user, token):
                raise ValidationError("Token is not valid.")
            user.set_password(password)
            user.save()
            return data
        except DjangoUnicodeDecodeError as identifier:
            PasswordResetTokenGenerator().check_token(user, token)
            raise ValidationError("Token is not valid")
