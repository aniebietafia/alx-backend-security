from django.http import HttpResponse
from django_ratelimit.decorators import ratelimit

def get_ratelimit_group(request):
    """
    Returns the rate limit group based on authentication.
    """
    if request.user.is_authenticated:
        return 'auth'
    return 'anon'

@ratelimit(
    key='user_or_ip',
    group=get_ratelimit_group,
    rate='5/m',
    block=True
)
def sensitive_login_view(request):
    """
    A sensitive view protected by rate limiting.
    """
    return HttpResponse("This is a sensitive view")