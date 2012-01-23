"""CSRF protection without cookies."""
import functools

from django.conf import settings
from django.core.cache import cache
from django.middleware import csrf as django_csrf
from django.utils import crypto
from django.utils.cache import patch_vary_headers


ANON_COOKIE = getattr(settings, 'ANON_COOKIE', 'anoncsrf')
ANON_TIMEOUT = getattr(settings, 'ANON_TIMEOUT', 60 * 60 * 2)  # 2 hours.
ANON_ALWAYS = getattr(settings, 'ANON_ALWAYS', False)


class CsrfMiddleware(object):

    # csrf_processing_done prevents checking CSRF more than once. That could
    # happen if the requires_csrf_token decorator is used.
    def _accept(self, request):
        request.csrf_processing_done = True

    def _reject(self, request, reason):
        return django_csrf._get_failure_view()(request, reason)

    def process_request(self, request):
        """
        Add a CSRF token to the session for logged-in users.

        The token is available at request.META['CSRF_COOKIE'].
        """
        if 'CSRF_COOKIE' in request.META:
            return
        if request.user.is_authenticated():
            if 'csrf_token' not in request.session:
                token = django_csrf._get_new_csrf_key()
                request.session['csrf_token'] = token
            request.META['CSRF_COOKIE'] = request.session['csrf_token']
        else:
            key = None
            token = ''
            if ANON_COOKIE in request.COOKIES:
                key = request.COOKIES[ANON_COOKIE]
                token = cache.get(key, '')
            if ANON_ALWAYS:
                if not key:
                    key = django_csrf._get_new_csrf_key()
                if not token:
                    token = django_csrf._get_new_csrf_key()
                request._anon_csrf_key = key
                cache.set(key, token, ANON_TIMEOUT)
            request.META['CSRF_COOKIE'] = token

    def process_view(self, request, view_func, args, kwargs):
        """Check the CSRF token if this is a POST."""
        if getattr(request, 'csrf_processing_done', False):
            return

        # Allow @csrf_exempt views.
        if getattr(view_func, 'csrf_exempt', False):
            return

        if (getattr(view_func, 'anonymous_csrf_exempt', False)
            and not request.user.is_authenticated()):
            return

        # Bail if this isn't a POST.
        if request.method != 'POST':
            return self._accept(request)

        # The test client uses this to get around CSRF processing.
        if getattr(request, '_dont_enforce_csrf_checks', False):
            return self._accept(request)

        # Try to get the token from the POST and fall back to looking at the
        # X-CSRFTOKEN header.
        user_token = request.POST.get('csrfmiddlewaretoken', '')
        if user_token == '':
            user_token = request.META.get('HTTP_X_CSRFTOKEN', '')

        request_token = request.META.get('CSRF_COOKIE', '')

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
        if ('CSRF_COOKIE' in request.META and
            request.META.get('CSRF_COOKIE_USED', False)):
            response.set_cookie(settings.CSRF_COOKIE_NAME,
                                request.META['CSRF_COOKIE'],
                                max_age=60 * 60 * 24 * 7 * 52,
                                domain=settings.CSRF_COOKIE_DOMAIN)
            patch_vary_headers(response, ['Cookie'])

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
        use_anon_cookie = not (request.user.is_authenticated() or ANON_ALWAYS)
        if use_anon_cookie:
            if ANON_COOKIE in request.COOKIES:
                key = request.COOKIES[ANON_COOKIE]
                token = cache.get(key) or django_csrf._get_new_csrf_key()
            else:
                key = django_csrf._get_new_csrf_key()
                token = django_csrf._get_new_csrf_key()
            cache.set(key, token, ANON_TIMEOUT)
            request.META['CSRF_COOKIE'] = token
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
