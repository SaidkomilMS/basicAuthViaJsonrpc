import datetime
from re import compile as re_compile

import ujson as ujson
from django.conf import settings
from django.http import JsonResponse

from btokenauthorization.models import AccessToken


def authorization_error(id, method):
    return {
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            'code': -32001,
            'message': "Not authorized",
            'data': "Use '<AuthType> <token>' in your headers"
        },
        "status": False,
        "origin": method,
        "host": {
            'host': '<hostname>',
            'timestamp': str(datetime.datetime.now())
        }
    }


def authorization(view):
    def main(request):
        if request.method != 'POST':
            return JsonResponse({'ok': True})
        try:
            body = ujson.loads(request.body.decode())
        except Exception as e:
            print(request.body.decode())
            return JsonResponse(
                {"jsonrpc": "2.0", "error": {"code": -32700, "message": "Parse error"}, "id": None, "status": False})
        id_ = body.get('id')
        method_ = body['method']
        headers = request.headers
        context = {}
        auth_header = headers.get('Authorization', '')

        if method_ not in settings.NO_AUTH_METHODS:
            pattern = re_compile(r'Bearer (.+)')
            try:
                if not pattern.match(auth_header):
                    data = authorization_error(id_, "auth")
                    return JsonResponse(data)
            except Exception:
                data = authorization_error(id_, "auth")
                return JsonResponse(data)
            input_token = pattern.findall(auth_header)[0]

            try:
                token = AccessToken.objects.get(key=input_token, expire_date__gt=datetime.datetime.now())
                context['user'] = token.user
            except AccessToken.DoesNotExist:
                if AccessToken.objects.filter(key=input_token).exists():
                    return JsonResponse({
                        "id": id_,
                        "origin": "auth",
                        "error": {
                            "code": -42001,
                            "message": "Token is expired"
                        }
                    })
                data = authorization_error(id_, "auth")
                return JsonResponse(data)
        return view(request, context)

    return main
