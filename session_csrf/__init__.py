"""CSRF protection without cookies."""
import django.core.context_processors
from django.middleware import csrf as django_csrf
from django.utils import crypto


# This overrides django.core.context_processors.csrf to dump our csrf_token
# into the template context.
def context_processor(request):
    # Django warns about an empty token unless you call it NOTPROVIDED.
    return {'csrf_token': getattr(request, 'csrf_token', 'NOTPROVIDED')}


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

        The token is available at request.csrf_token.
        """
        if request.user.is_authenticated():
            if 'csrf_token' not in request.session:
                token = django_csrf._get_new_csrf_key()
                request.csrf_token = request.session['csrf_token'] = token
            else:
                request.csrf_token = request.session['csrf_token']
        else:
            request.csrf_token = ''

    def process_view(self, request, view_func, args, kwargs):
        """Check the CSRF token if this is a POST."""
        if getattr(request, 'csrf_processing_done', False):
            return

        # Allow @csrf_exempt views.
        if getattr(view_func, 'csrf_exempt', False):
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
