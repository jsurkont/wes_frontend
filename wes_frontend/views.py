import requests
from django.shortcuts import render
from django.http import JsonResponse, HttpResponseForbidden
from django.views.decorators.csrf import csrf_exempt
from mozilla_django_oidc.utils import import_from_settings

from .models import UserTokens

def home(request):
    return render(request, 'base.html')


@csrf_exempt
def token(request):
    OIDC_OP_TOKEN_ENDPOINT = import_from_settings('OIDC_OP_TOKEN_ENDPOINT')
    OIDC_RP_CLIENT_ID = import_from_settings('OIDC_RP_CLIENT_ID')
    OIDC_RP_CLIENT_SECRET = import_from_settings('OIDC_RP_CLIENT_SECRET')
    user = request.POST.get('user_id', '')
    try:
        refresh_token = UserTokens.objects.get(user=user).refresh_token
    except UserTokens.DoesNotExist:
        return HttpResponseForbidden()

    data = {'grant_type': 'refresh_token', 'client_id': OIDC_RP_CLIENT_ID,
            'client_secret': OIDC_RP_CLIENT_SECRET,
            'refresh_token': refresh_token}
    r = requests.post(
        OIDC_OP_TOKEN_ENDPOINT, data=data,
        verify=import_from_settings('OIDC_VERIFY_SSL', True))
    if r.ok:
        d = r.json()
        access_token = d['access_token']
        refresh_token = d['refresh_token']
        usertokens, created = UserTokens.objects.update_or_create(
            user=user,
            defaults={'access_token': access_token,
                      'refresh_token': refresh_token}
        )
        return JsonResponse({'access_token': access_token})
    else:
        return HttpResponseForbidden()
