import jwt
import environ
from rest_framework.authentication import BaseAuthentication
from rest_framework import exceptions
from django.contrib.auth import get_user_model

env = environ.Env()

User = get_user_model()

class ExternalJWTAuthentication(BaseAuthentication):
    def authenticate(self, request):
        auth_header = request.headers.get('Authorization')

        if not auth_header or not auth_header.startswith('Bearer '):
            return None
        
        token = auth_header.split(' ')[1]

        try:
            payload = jwt.decode(
                token,
                env.EXTERNAL_JWT_PUBLIC_KEY,
                algorithms=["RS256"],
                audience=env.EXTERNAL_JWT_AUDIENCE,
                issuer=env.EXTERNAL_JWT_ISSUER
            )
        except jwt.ExpiredSignatureError:
            raise exceptions.AuthenticationFailed('Token expired')
        except jwt.InvalidTokenError:
            raise exceptions.AuthenticationFailed('Invalid token')
        
        user, _ = User.objects.get_or_create(username=payload["sub"])
        return (user, token)