import datetime

from django.contrib.auth.models import User
from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt

from jsonrpcserver import method, Result, Error, Success, dispatch

from btokenauthorization.decorators import authorization
from btokenauthorization.models import AccessToken


@method
def register(context, username: str, password: str) -> Result:
    user: User = context['user']
    if not user.is_superuser:
        return Error(code=555, message="Permission denied")
    partners = User.objects.filter(username=username)
    if not partners.exists():
        partner = User(username=username)
        partner.set_password(password)
        partner.save()
        return Success(
            {"message": "User created successfully!"}
        )
    partner = partners.first()
    partner.set_password(password)
    partner.save()
    return Success(
        {"message": "User password changed successfully!"}
    )


@method
def login(context, username, password) -> Result:
    partners = User.objects.filter(username=username)
    if not partners.exists():
        return Error(code=500, message="1")
    partner = partners.first()
    if not partner.check_password(password):
        return Error(code=500, message="2")

    tokens = AccessToken.objects.filter(user=partner, expire_date__gt=datetime.datetime.now())
    if tokens.exists():
        return Success({
            "access_token_key": tokens.first().key
        })
    token = AccessToken.generate(user=partner)
    return Success({
        "access_token_key": token.key
    })


@csrf_exempt
@authorization
def jsonrpc(request, context) -> HttpResponse:
    return HttpResponse(
        dispatch(request.body.decode(), context=context), content_type="application/json"
    )
