from django.contrib.auth import get_user_model, authenticate
from django.core.mail import send_mail
from rest_framework import serializers as serializers

from applications.account.utils import send_activation_email
from food_onlinestore.settings import EMAIL_HOST_USER

User = get_user_model()


class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(min_length=6, write_only=True)
    password_confirmation = serializers.CharField(min_length=6, write_only=True)

    class Meta:
        model = User
        fields = ('email', 'password', 'password_confirmation')

    def validate_email(self, email):
        if User.objects.filter(email=email).exists():
            raise serializers.ValidationError('User with given email already exists')
        return email

    def validate(self, validated_data):
        password = validated_data.get('password')
        password_confirmation = validated_data.get('password_confirmation')
        if password != password_confirmation:
            raise serializers.ValidationError('Passwords do not match')
        return validated_data

    def create(self, validated_data):
        email = validated_data.get('email')
        password = validated_data.get('password')
        user = User.objects.create_user(email, password)
        send_activation_email(user.email, user.activation_code)
        return user


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(style={'input_type': 'password'}, trim_whitespace=False)

    def validate(self, attrs):
        email = attrs.get('email')
        password = attrs.get('password')

        if email and password:
            user = authenticate(request=self.context.get('request'), username=email, password=password)
            if not user:
                msg = 'Unable to log in with provided credentials.'
                raise serializers.ValidationError(msg, code='authorization')
        else:
            msg = 'Must include "username" and "password".'
            raise serializers.ValidationError(msg, code='authorization')
        attrs['user'] = user
        return attrs

class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(min_length=6, required=True)
    new_password = serializers.CharField(min_length=6, required=True)
    new_password_confirmation = serializers.CharField(min_length=6, required=True)

    def validate_old_password(self, old_password):
        request = self.context.get('request')
        user = request.user
        if not user.check_password(old_password):
            raise serializers.ValidationError('Passwords didn\'t match')
        return old_password

    def validate(self, attrs):
        new_pass1 = attrs.get('new_password')
        new_pass2 = attrs.get('new_password_confirmation')
        if new_pass1 != new_pass2:
            raise serializers.ValidationError('Bad credentials')
        return attrs

    def set_new_password(self):
        new_pass = self.validated_data.get('new_password')
        user = self.context.get('request').user
        user.set_password(new_pass)
        user.save()


# class ForgotPasswordSerializer(serializers.Serializer):
#     email = serializers.EmailField(required=True)
#
#     def validate_email(self, email):
#         if not User.objects.filter(email=email).exists():
#             raise serializers.ValidationError('User not found')
#         return email
#
#     def send_verification_email(self):
#         email = self.validated_data.get('email')
#         user = User.objects.get(email=email)
#         user.create_activation_code()
#         send_mail(
#             'Password recovery',
#             f'Your activation code is: {user.activation_code}',
#             EMAIL_HOST_USER,
#             [user.email, ]
#         )
#
#
# class ForgotPasswordCompleteSerializer(serializers.Serializer):
#     activation_code = serializers.CharField(required=True)
#     password = serializers.CharField(min_length=6, required=True)
#     password_confirmation = serializers.CharField(min_length=6, required=True)
#
#     def validate_activation_code(self, code):
#         if not User.objects.filter(activation_code=code).exists():
#             raise serializers.ValidationError('Activation code seems to be incorrect')
#         return code
#
#     def validate(self, attrs):
#         password = attrs.get('password')
#         password_confirmation = attrs.get('password_confirmation')
#         if password != password_confirmation:
#             raise serializers.ValidationError('Passwords do not match!')
#         return attrs
#
#     def set_new_password(self):
#         print(self.validated_data)
#         code = self.validated_data.get('activation_code')
#         print(code)
#         password = self.validated_data.get('password')
#         print(password)
#         user = User.objects.get(activation_code=code)
#         user.set_password(password)
#         user.save()
#
#
# class CreateNewPasswordSerializer(serializers.Serializer):
#     email = serializers.EmailField()
#     activation_code = serializers.CharField(max_length=60)
#     password = serializers.CharField(min_length=6, required=True)
#     password_confirmation = serializers.CharField(min_length=6, required=True)
#
#     def validate_email(self, email):
#         User = get_user_model()
#         if not User.objects.filter(email=email).exists():
#             raise serializers.ValidationError('User with given email does not exist')
#         return email
#
#     def validate_activation_code(self, activation_code):
#         User = get_user_model()
#         if User.objects.filter(activation_code=activation_code, is_active=False).exists():
#             raise serializers.ValidationError('Wrong activation code')
#         return activation_code
#
#     def validate(self, attrs):
#         password = attrs.get('password')
#         password_confirmation = attrs.get('password_confirmation')
#         if password != password_confirmation:
#             raise serializers.ValidationError('Passwords do not match')
#         return attrs
#
#     def save(self, **kwargs):
#         data = self.validated_data
#         email = data.get('email')
#         activation_code = data.get('activation_code')
#         password = data.get('password')
#
#         try:
#             User = get_user_model()
#             user = User.objects.get(email=email, activation_code=activation_code)
#         except:
#             raise serializers.ValidationError('User not found')
#
#         user.is_active = True
#         user.activation_code = ''
#         user.set_password(password)
#         user.save()
#         return user


