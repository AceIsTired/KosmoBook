from django.shortcuts import render

# Create your views here.
import os
from datetime import timedelta
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.utils.decorators import method_decorator
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response

from .supabase_client import supabase

COOKIE_DOMAIN = os.getenv("COOKIE_DOMAIN") or None  # None for localhost

def _set_auth_cookies(resp: JsonResponse, access: str, refresh: str, max_age=None):
    # NOTE: SameSite=Lax works for most SPA/API flows. Tighten to Strict if pure server-rendered.
    common = dict(
        httponly=True, secure=True, samesite="Lax",
        domain=COOKIE_DOMAIN, max_age=max_age,
    )
    resp.set_cookie("sb_access", access, **common)
    # refresh typically long-lived; adjust to your project session policy
    resp.set_cookie("sb_refresh", refresh, **{**common, "max_age": int(timedelta(days=30).total_seconds())})

def _clear_auth_cookies(resp: JsonResponse):
    for name in ("sb_access", "sb_refresh"):
        resp.delete_cookie(name, domain=COOKIE_DOMAIN, samesite="Lax")

@method_decorator(require_http_methods(["POST"]), name="dispatch")
class RegisterView(APIView):
    permission_classes = [AllowAny]

    def post(self, request: Request) -> Response:
        data = request.data or {}
        email = data.get("email")
        password = data.get("password")
        metadata = data.get("metadata") or {}

        if not email or not password:
            return Response({"error": "email and password required"}, status=400)

        res = supabase.auth.sign_up({
            "email": email,
            "password": password,
            "options": {"data": metadata},
        })
        # If email confirmations are ON, no session is returned until the link is clicked.
        user = getattr(res, "user", None)
        session = getattr(res, "session", None)

        payload = {"user_id": getattr(user, "id", None), "email_sent": session is None}
        resp = Response(payload, status=201)

        if session:
            _set_auth_cookies(resp,
                access=session.access_token,
                refresh=session.refresh_token,
                max_age=session.expires_in if hasattr(session, "expires_in") else None
            )
        return resp

@method_decorator(require_http_methods(["POST"]), name="dispatch")
class LoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request: Request) -> Response:
        data = request.data or {}
        email = data.get("email")
        password = data.get("password")
        if not email or not password:
            return Response({"error": "email and password required"}, status=400)

        auth_res = supabase.auth.sign_in_with_password({"email": email, "password": password})
        session = getattr(auth_res, "session", None)
        if not session:
            return Response({"error": "invalid credentials"}, status=401)

        resp = Response({
            "access_token": session.access_token,
            "expires_in": getattr(session, "expires_in", None),
            "token_type": "bearer",
        })
        _set_auth_cookies(resp, session.access_token, session.refresh_token,
                          max_age=session.expires_in if hasattr(session, "expires_in") else None)
        return resp

@method_decorator(require_http_methods(["POST"]), name="dispatch")
class LogoutView(APIView):
    permission_classes = [AllowAny]  # we allow even if already logged out

    def post(self, request: Request) -> Response:
        # Optional: if you want to revoke the session in Supabase, attempt to call sign_out()
        # by first setting the session on the client (needs both tokens).
        access = request.COOKIES.get("sb_access")
        refresh = request.COOKIES.get("sb_refresh")
        try:
            if access and refresh:
                supabase.auth.set_session(access_token=access, refresh_token=refresh)
                supabase.auth.sign_out()  # revokes refresh token (access stays valid until expiry)
        except Exception:
            pass  # even if revoke fails, clear local cookies

        resp = Response({"ok": True})
        _clear_auth_cookies(resp)
        return resp

class MeView(APIView):
    permission_classes = [IsAuthenticated]  # uses our SupabaseJWTAuthentication

    def get(self, request: Request) -> Response:
        # You can trust request.user from the verified JWT, or fetch a server-validated user:
        from .authentication import SupabaseJWTAuthentication
        token = getattr(request, "auth", None)
        # Optionally, ask Supabase to validate the token & return user:
        user_res = None
        if token:
            try:
                user_res = supabase.auth.get_user(token)  # validates JWT server-side
            except Exception:
                user_res = None

        return Response({
            "claims": getattr(request.user, "claims", {}),
            "user": getattr(user_res, "user", None).model_dump() if user_res and getattr(user_res, "user", None) else None,
        })
