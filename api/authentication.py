import os, jwt
from typing import Optional
from jwt import PyJWKClient
from django.utils.functional import cached_property
from rest_framework.authentication import BaseAuthentication, get_authorization_header
from rest_framework import exceptions

SUPABASE_URL = os.getenv("SUPABASE_URL", "").rstrip("/")
JWKS_URL = f"{SUPABASE_URL}/auth/v1/.well-known/jwks.json"
AUDIENCE = os.getenv("SUPABASE_JWT_AUD", "authenticated")

class SupabaseUser:
    def __init__(self, sub: str, email: Optional[str], claims: dict):
        self.id = sub
        self.email = email
        self.claims = claims
    @property
    def is_authenticated(self): return True
    def __str__(self): return self.email or self.id

class SupabaseJWTAuthentication(BaseAuthentication):
    @cached_property
    def jwks_client(self) -> PyJWKClient:
        return PyJWKClient(JWKS_URL)

    def authenticate(self, request):
        token = self._get_token(request)
        if not token: return None

        try:
            signing_key = self.jwks_client.get_signing_key_from_jwt(token)
            claims = jwt.decode(
                token,
                signing_key.key,
                algorithms=["RS256", "ES256", "EdDSA"],  # supabase uses asymmetric keys now
                audience=AUDIENCE,
                options={"verify_exp": True},
            )
        except Exception:
            raise exceptions.AuthenticationFailed("Invalid or expired token")

        user = SupabaseUser(
            sub=claims.get("sub") or claims.get("user_id"),
            email=claims.get("email"),
            claims=claims,
        )
        return (user, token)

    def _get_token(self, request) -> Optional[str]:
        # 1) Authorization: Bearer <jwt>
        auth = get_authorization_header(request).split()
        if auth and auth[0].lower() == b"bearer" and len(auth) == 2:
            return auth[1].decode("utf-8")

        # 2) or from our HttpOnly cookie
        return request.COOKIES.get("sb_access")
