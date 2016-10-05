"""CSRF protection without cookies."""
from __future__ import unicode_literals
import functools
import hashlib

from django.conf import settings
from django import VERSION as DJANGO_VERSION
from django.core.cache import cache
from django.middleware import csrf as django_csrf
try:
    from django.middleware.csrf import _get_new_csrf_key as django_get_new_csrf_string
except ImportError:
    from django.middleware.csrf import _get_new_csrf_string as django_get_new_csrf_string
from django.utils import crypto, deprecation
from django.utils.cache import patch_vary_headers


ANON_COOKIE = getattr(settings, 'ANON_COOKIE', 'anoncsrf')
ANON_TIMEOUT = getattr(settings, 'ANON_TIMEOUT', 60 * 60 * 2)  # 2 hours.
ANON_ALWAYS = getattr(settings, 'ANON_ALWAYS', False)
PREFIX = b'sessioncsrf:'


# This overrides django.core.context_processors.csrf to dump our csrf_token
# into the template context.
def context_processor(request):
    # Django warns about an empty token unless you call it NOTPROVIDED.
    return {'csrf_token': getattr(request, 'csrf_token', 'NOTPROVIDED')}


def prep_key(key):
    """
    In case a bogus request comes in with a large or wrongly formatted
    massive anoncsrf cookie value, memcache will raise a
    MemcachedKeyLengthError or MemcachedKeyCharacterError. We hash the
    key here in order to have a predictable length and character set.
    """
    key = key.encode("utf8")
    prefixed = PREFIX + key
    return hashlib.md5(prefixed).hexdigest()


def is_user_authenticated(request):
    user = getattr(request, 'user', None)
    if not user:
        return False
    if DJANGO_VERSION < (1, 10, 0):
        return user.is_authenticated()
    else:
        return user.is_authenticated

# Inherit from deprecation.MiddlewareMixin to ensure it works
# with the new style middleware in Django 1.10 - see
# https://docs.djangoproject.com/en/1.10/topics/http/middleware/#django.utils.deprecation.MiddlewareMixin
class CsrfMiddleware(deprecation.MiddlewareMixin if DJANGO_VERSION >= (1, 10, 0) else object):

    # csrf_processing_done prevents checking CSRF more than once. That could
    # happen if the requires_csrf_token decorator is used.
    def _accept(self, request):
        request.csrf_processing_done = True

    def _reject(self, request, reason):
        return django_csrf._get_failure_view()(request, reason)

    def process_request(self, request):
        """
        Add a CSRF token to the session for logged-in users.

        The token is available at request.csrf_token.
        """
        if hasattr(request, 'csrf_token'):
            return
        if is_user_authenticated(request):
            if 'csrf_token' not in request.session:
                token = django_get_new_csrf_string()
                request.csrf_token = request.session['csrf_token'] = token
            else:
                request.csrf_token = request.session['csrf_token']
        else:
            key = None
            token = ''
            if ANON_COOKIE in request.COOKIES:
                key = request.COOKIES[ANON_COOKIE]
                token = cache.get(prep_key(key), '')
            if ANON_ALWAYS:
                if not key:
                    key = django_get_new_csrf_string()
                if not token:
                    token = django_get_new_csrf_string()
                request._anon_csrf_key = key
                cache.set(prep_key(key), token, ANON_TIMEOUT)
            request.csrf_token = token

    def process_view(self, request, view_func, args, kwargs):
        """Check the CSRF token if this is a POST."""
        if getattr(request, 'csrf_processing_done', False):
            return

        # Allow @csrf_exempt views.
        if getattr(view_func, 'csrf_exempt', False):
            return

        if (getattr(view_func, 'anonymous_csrf_exempt', False)
            and not is_user_authenticated(request)):
            return

        # Bail if this is a safe method.
        if request.method in ('GET', 'HEAD', 'OPTIONS', 'TRACE'):
            return self._accept(request)

        # The test client uses this to get around CSRF processing.
        if getattr(request, '_dont_enforce_csrf_checks', False):
            return self._accept(request)

        # Try to get the token from the POST and fall back to looking at the
        # X-CSRFTOKEN header.
        user_token = request.POST.get('csrfmiddlewaretoken', '')
        if user_token == '':
            user_token = request.META.get('HTTP_X_CSRFTOKEN', '')

        request_token = getattr(request, 'csrf_token', '')

        # Check that both strings aren't empty and then check for a match.
        if not ((user_token or request_token)
                and crypto.constant_time_compare(user_token, request_token)):
            reason = django_csrf.REASON_BAD_TOKEN
            django_csrf.logger.warning(
                'Forbidden (%s): %s' % (reason, request.path),
                extra=dict(status_code=403, request=request))
            return self._reject(request, reason)
        else:
            return self._accept(request)

    def process_response(self, request, response):
        if hasattr(request, '_anon_csrf_key'):
            # Set or reset the cache and cookie timeouts.
            response.set_cookie(ANON_COOKIE, request._anon_csrf_key,
                                max_age=ANON_TIMEOUT, httponly=True,
                                secure=request.is_secure())
            patch_vary_headers(response, ['Cookie'])
        return response


def anonymous_csrf(f):
    """Decorator that assigns a CSRF token to an anonymous user."""
    @functools.wraps(f)
    def wrapper(request, *args, **kw):
        use_anon_cookie = not (is_user_authenticated(request) or ANON_ALWAYS)
        if use_anon_cookie:
            if ANON_COOKIE in request.COOKIES:
                key = request.COOKIES[ANON_COOKIE]
                token = cache.get(prep_key(key)) or django_get_new_csrf_string()
            else:
                key = django_get_new_csrf_string()
                token = django_get_new_csrf_string()
            cache.set(prep_key(key), token, ANON_TIMEOUT)
            request.csrf_token = token
        response = f(request, *args, **kw)
        if use_anon_cookie:
            # Set or reset the cache and cookie timeouts.
            response.set_cookie(ANON_COOKIE, key, max_age=ANON_TIMEOUT,
                                httponly=True, secure=request.is_secure())
            patch_vary_headers(response, ['Cookie'])
        return response
    return wrapper


def anonymous_csrf_exempt(f):
    """Like @csrf_exempt but only for anonymous requests."""
    f.anonymous_csrf_exempt = True
    return f


# Replace Django's middleware with our own.
def monkeypatch():
    from django.views.decorators import csrf as csrf_dec
    django_csrf.CsrfViewMiddleware = CsrfMiddleware
    csrf_dec.csrf_protect = csrf_dec.decorator_from_middleware(CsrfMiddleware)
