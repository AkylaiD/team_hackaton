# from django.core.mail import send_mail

from django.core.mail import *


def send_activation_email(email, activation_code):
    activation_url = f'http://localhost:8000/account/activate/{activation_code}/'
    message = f'''
                Thank you for registration. 
                Please, activate your account.
                Activation link: {activation_url}
                '''
    send_mail(
        'Activate your account',
        message,
        'test@food_onlinestore.kg',
        [email, ],
        fail_silently=False
    )



def send_code(email, code, operation):
    get_connection()
    if operation == 'reset_password':
        title = 'Password reset'
        _url = f'http://localhost:8000/account/password_reset/confirm/'
        message = f"""
            We received a request to reset the password on your account.
            If you would wish the continue, 
            Use the token and enter new password in the link bellow.
            Token: {code}
            Reset password link: {_url}"""
    send_mail(
        title,
        message,
        'test@food_onlinestore.kg',
        [email, ],
        fail_silently=False
    )