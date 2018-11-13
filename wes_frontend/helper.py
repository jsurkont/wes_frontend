from django.conf import settings


def provider_logout(request):
    redirect_url = '{}?continue={}'.format(
        settings.OIDC_OP_LOGOUT,
        request.build_absolute_uri('/oidc/callback/'))
    return redirect_url
