from django.conf import settings
from mozilla_django_oidc.auth import OIDCAuthenticationBackend

import json
import requests

from django.core.exceptions import SuspiciousOperation
try:
    from django.urls import reverse
except ImportError:
    # Django < 2.0.0
    from django.core.urlresolvers import reverse

from mozilla_django_oidc.utils import absolutify, import_from_settings
from .models import UserTokens


def provider_logout(request):
    redirect_url = '{}?redirect_uri={}'.format(
        settings.OIDC_OP_LOGOUT,
        request.build_absolute_uri('/oidc/callback/'))
    return redirect_url


class OIDCAuth(OIDCAuthenticationBackend):

    def get_token(self, payload):
        """Return token object as a dictionary."""

        response = requests.post(
            self.OIDC_OP_TOKEN_ENDPOINT,
            data=payload,
            verify=import_from_settings('OIDC_VERIFY_SSL', True))
        response.raise_for_status()
        return response.json()

    def authenticate(self, request, **kwargs):
        """Authenticates a user based on the OIDC code flow."""

        self.request = request
        if not self.request:
            return None

        state = self.request.GET.get('state')
        code = self.request.GET.get('code')
        nonce = kwargs.pop('nonce', None)

        if not code or not state:
            return None

        reverse_url = import_from_settings('OIDC_AUTHENTICATION_CALLBACK_URL',
                                           'oidc_authentication_callback')

        token_payload = {
            'client_id': self.OIDC_RP_CLIENT_ID,
            'client_secret': self.OIDC_RP_CLIENT_SECRET,
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': absolutify(
                self.request,
                reverse(reverse_url)
            ),
        }

        # Get the token
        token_info = self.get_token(token_payload)
        id_token = token_info.get('id_token')
        access_token = token_info.get('access_token')
        refresh_token = token_info.get('refresh_token')

        # Validate the token
        payload = self.verify_token(id_token, nonce=nonce)

        # Store users tokens
        usertokens, created = UserTokens.objects.update_or_create(
            user=payload['sub'],
            defaults={'access_token': access_token,
                      'refresh_token': refresh_token}
        )

        if payload:
            self.store_tokens(access_token, id_token)
            try:
                return self.get_or_create_user(access_token, id_token, payload)
            except SuspiciousOperation as exc:
                LOGGER.warning('failed to get or create user: %s', exc)
                return None

        return None
