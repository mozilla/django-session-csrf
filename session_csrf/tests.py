from __future__ import unicode_literals

import django.test
from django import http
from django.conf.urls import url
from django.contrib.auth import logout
from django.contrib.auth.middleware import AuthenticationMiddleware
from django.contrib.auth.models import User
from django.contrib.sessions.middleware import SessionMiddleware
from django.contrib.sessions.models import Session
from django.core import signals
from django.core.cache import cache
from django.core.handlers.wsgi import WSGIRequest
from django.core.exceptions import ImproperlyConfigured

import session_csrf
from session_csrf import (anonymous_csrf, anonymous_csrf_exempt,
                          CsrfMiddleware, prep_key)
try:
    from unittest import mock
except ImportError:
    # Python 2.7 doesn't have unittest.mock, but it is available on PyPi
    import mock


urlpatterns = [
    url('^$', lambda r: http.HttpResponse()),
    url('^anon$', anonymous_csrf(lambda r: http.HttpResponse())),
    url('^no-anon-csrf$', anonymous_csrf_exempt(lambda r: http.HttpResponse())),
    url('^logout$', anonymous_csrf(lambda r: logout(r) or http.HttpResponse())),
]


class TestCsrfToken(django.test.TestCase):

    def setUp(self):
        self.client.handler = ClientHandler()
        User.objects.create_user('jbalogh', 'j@moz.com', 'password')
        self.save_ANON_ALWAYS = session_csrf.ANON_ALWAYS
        session_csrf.ANON_ALWAYS = False

    def tearDown(self):
        session_csrf.ANON_ALWAYS = self.save_ANON_ALWAYS

    def login(self):
        assert self.client.login(username='jbalogh', password='password')

    def test_csrftoken_unauthenticated(self):
        # request.csrf_token is '' for anonymous users.
        response = self.client.get('/', follow=True)
        self.assertEqual(response.wsgi_request.csrf_token, '')

    def test_csrftoken_authenticated(self):
        # request.csrf_token is a random non-empty string for authed users.
        self.login()
        response = self.client.get('/', follow=True)
        # The CSRF token is a 32-character MD5 string.
        self.assertEqual(len(response.wsgi_request.csrf_token), 32)

    def test_csrftoken_new_session(self):
        # The csrf_token is added to request.session the first time.
        self.login()
        response = self.client.get('/', follow=True)
        # The CSRF token is a 32-character MD5 string.
        token = response.wsgi_request.session['csrf_token']
        self.assertEqual(len(token), 32)
        self.assertEqual(token, response.wsgi_request.csrf_token)

    def test_csrftoken_existing_session(self):
        # The csrf_token in request.session is reused on subsequent requests.
        self.login()
        r1 = self.client.get('/', follow=True)
        token = r1.wsgi_request.session['csrf_token']

        r2 = self.client.get('/', follow=True)
        self.assertEqual(r1.wsgi_request.csrf_token, r2.wsgi_request.csrf_token)
        self.assertEqual(token, r2.wsgi_request.csrf_token)


class TestCsrfMiddleware(django.test.TestCase):

    def setUp(self):
        self.token = 'a' * 32
        self.rf = django.test.RequestFactory()
        self.mw = CsrfMiddleware()

    def process_view(self, request, view=None):
        return self.mw.process_view(request, view, None, None)

    def test_anon_token_from_cookie(self):
        rf = django.test.RequestFactory()
        rf.cookies['anoncsrf'] = self.token
        cache.set(prep_key(self.token), 'woo')
        request = rf.get('/')
        SessionMiddleware().process_request(request)
        AuthenticationMiddleware().process_request(request)
        self.mw.process_request(request)
        self.assertEqual(request.csrf_token, 'woo')

    def test_set_csrftoken_once(self):
        # Make sure process_request only sets request.csrf_token once.
        request = self.rf.get('/')
        request.csrf_token = 'woo'
        self.mw.process_request(request)
        self.assertEqual(request.csrf_token, 'woo')

    def test_reject_view(self):
        # Check that the reject view returns a 403.
        response = self.process_view(self.rf.post('/'))
        self.assertEqual(response.status_code, 403)

    def test_csrf_exempt(self):
        # Make sure @csrf_exempt still works.
        view = type(str(""), (), {'csrf_exempt': True})()
        self.assertEqual(self.process_view(self.rf.post('/'), view), None)

    def test_safe_whitelist(self):
        # CSRF should not get checked on these methods.
        self.assertEqual(self.process_view(self.rf.get('/')), None)
        self.assertEqual(self.process_view(self.rf.head('/')), None)
        self.assertEqual(self.process_view(self.rf.options('/')), None)

    def test_unsafe_methods(self):
        self.assertEqual(self.process_view(self.rf.post('/')).status_code,
                         403)
        self.assertEqual(self.process_view(self.rf.put('/')).status_code,
                         403)
        self.assertEqual(self.process_view(self.rf.delete('/')).status_code,
                         403)

    def test_csrfmiddlewaretoken(self):
        # The user token should be found in POST['csrfmiddlewaretoken'].
        request = self.rf.post('/', {'csrfmiddlewaretoken': self.token})
        self.assertEqual(self.process_view(request).status_code, 403)

        request.csrf_token = self.token
        self.assertEqual(self.process_view(request), None)

    def test_x_csrftoken(self):
        # The user token can be found in the X-CSRFTOKEN header.
        request = self.rf.post('/', HTTP_X_CSRFTOKEN=self.token)
        self.assertEqual(self.process_view(request).status_code, 403)

        request.csrf_token = self.token
        self.assertEqual(self.process_view(request), None)

    def test_require_request_token_or_user_token(self):
        # Blank request and user tokens raise an error on POST.
        request = self.rf.post('/', HTTP_X_CSRFTOKEN='')
        request.csrf_token = ''
        self.assertEqual(self.process_view(request).status_code, 403)

    def test_token_no_match(self):
        # A 403 is returned when the tokens don't match.
        request = self.rf.post('/', HTTP_X_CSRFTOKEN='woo')
        request.csrf_token = ''
        self.assertEqual(self.process_view(request).status_code, 403)

    def test_csrf_token_context_processor(self):
        # Our CSRF token should be available in the template context.
        request = mock.Mock()
        request.csrf_token = self.token
        request.groups = []
        ctx = {}
        for processor in get_context_processors():
            ctx.update(processor(request))
        self.assertEqual(ctx['csrf_token'], self.token)

    def test_process_view_without_authentication_middleware(self):
        # No request.user
        # Same as would happen if you never use the built-in
        # AuthenticationMiddleware.
        request = self.rf.get('/')
        self.assertEqual(self.mw.process_request(request), None)


class TestAnonymousCsrf(django.test.TestCase):
    urls = 'session_csrf.tests'

    def setUp(self):
        self.token = 'a' * 32
        self.rf = django.test.RequestFactory()
        User.objects.create_user('jbalogh', 'j@moz.com', 'password')
        self.client.handler = ClientHandler(enforce_csrf_checks=True)
        self.save_ANON_ALWAYS = session_csrf.ANON_ALWAYS
        session_csrf.ANON_ALWAYS = False

    def tearDown(self):
        session_csrf.ANON_ALWAYS = self.save_ANON_ALWAYS

    def login(self):
        assert self.client.login(username='jbalogh', password='password')

    def test_authenticated_request(self):
        # Nothing special happens, nothing breaks.
        # Find the CSRF token in the session.
        self.login()
        response = self.client.get('/anon')
        sessionid = response.cookies['sessionid'].value
        session = Session.objects.get(session_key=sessionid)
        token = session.get_decoded()['csrf_token']

        response = self.client.post('/anon', HTTP_X_CSRFTOKEN=token)
        self.assertEqual(response.status_code, 200)

    def test_unauthenticated_request(self):
        # We get a 403 since we're not sending a token.
        response = self.client.post('/anon')
        self.assertEqual(response.status_code, 403)

    def test_no_anon_cookie(self):
        # We don't get an anon cookie on non-@anonymous_csrf views.
        response = self.client.get('/')
        self.assertEqual(response.cookies, {})

    def test_new_anon_token_on_request(self):
        # A new anon user gets a key+token on the request and response.
        response = self.client.get('/anon')
        # Get the key from the cookie and find the token in the cache.
        key = response.cookies['anoncsrf'].value
        self.assertEqual(response.wsgi_request.csrf_token, cache.get(prep_key(key)))

    def test_existing_anon_cookie_on_request(self):
        # We reuse an existing anon cookie key+token.
        response = self.client.get('/anon')
        key = response.cookies['anoncsrf'].value
        # Now check that subsequent requests use that cookie.
        response = self.client.get('/anon')
        self.assertEqual(response.cookies['anoncsrf'].value, key)
        self.assertEqual(response.wsgi_request.csrf_token, cache.get(prep_key(key)))

    def test_new_anon_token_on_response(self):
        # The anon cookie is sent and we vary on Cookie.
        response = self.client.get('/anon')
        self.assertIn('anoncsrf', response.cookies)
        self.assertEqual(response['Vary'], 'Cookie')

    def test_existing_anon_token_on_response(self):
        # The anon cookie is sent and we vary on Cookie, reusing the old value.
        response = self.client.get('/anon')
        key = response.cookies['anoncsrf'].value

        response = self.client.get('/anon')
        self.assertEqual(response.cookies['anoncsrf'].value, key)
        self.assertIn('anoncsrf', response.cookies)
        self.assertEqual(response['Vary'], 'Cookie')

    def test_anon_csrf_logout(self):
        # Beware of views that logout the user.
        self.login()
        response = self.client.get('/logout')
        self.assertEqual(response.status_code, 200)

    def test_existing_anon_cookie_not_in_cache(self):
        response = self.client.get('/anon')
        self.assertEqual(len(response.wsgi_request.csrf_token), 32)

        # Clear cache and make sure we still get a token
        cache.clear()
        response = self.client.get('/anon')
        self.assertEqual(len(response.wsgi_request.csrf_token), 32)

    def test_anonymous_csrf_exempt(self):
        response = self.client.post('/no-anon-csrf')
        self.assertEqual(response.status_code, 200)

        self.login()
        response = self.client.post('/no-anon-csrf')
        self.assertEqual(response.status_code, 403)


class TestAnonAlways(django.test.TestCase):
    # Repeats some tests with ANON_ALWAYS = True
    urls = 'session_csrf.tests'

    def setUp(self):
        self.token = 'a' * 32
        self.rf = django.test.RequestFactory()
        User.objects.create_user('jbalogh', 'j@moz.com', 'password')
        self.client.handler = ClientHandler(enforce_csrf_checks=True)
        self.save_ANON_ALWAYS = session_csrf.ANON_ALWAYS
        session_csrf.ANON_ALWAYS = True

    def tearDown(self):
        session_csrf.ANON_ALWAYS = self.save_ANON_ALWAYS

    def login(self):
        assert self.client.login(username='jbalogh', password='password')

    def test_csrftoken_unauthenticated(self):
        # request.csrf_token is set for anonymous users
        # when ANON_ALWAYS is enabled.
        response = self.client.get('/', follow=True)
        # The CSRF token is a 32-character MD5 string.
        self.assertEqual(len(response.wsgi_request.csrf_token), 32)

    def test_authenticated_request(self):
        # Nothing special happens, nothing breaks.
        # Find the CSRF token in the session.
        self.login()
        response = self.client.get('/', follow=True)
        sessionid = response.cookies['sessionid'].value
        session = Session.objects.get(session_key=sessionid)
        token = session.get_decoded()['csrf_token']

        response = self.client.post('/', follow=True, HTTP_X_CSRFTOKEN=token)
        self.assertEqual(response.status_code, 200)

    def test_unauthenticated_request(self):
        # We get a 403 since we're not sending a token.
        response = self.client.post('/')
        self.assertEqual(response.status_code, 403)

    def test_new_anon_token_on_request(self):
        # A new anon user gets a key+token on the request and response.
        response = self.client.get('/')
        # Get the key from the cookie and find the token in the cache.
        key = response.cookies['anoncsrf'].value
        self.assertEqual(response.wsgi_request.csrf_token, cache.get(prep_key(key)))

    def test_existing_anon_cookie_on_request(self):
        # We reuse an existing anon cookie key+token.
        response = self.client.get('/')
        key = response.cookies['anoncsrf'].value

        # Now check that subsequent requests use that cookie.
        response = self.client.get('/')
        self.assertEqual(response.cookies['anoncsrf'].value, key)
        self.assertEqual(response.wsgi_request.csrf_token, cache.get(prep_key(key)))
        self.assertEqual(response['Vary'], 'Cookie')

    def test_anon_csrf_logout(self):
        # Beware of views that logout the user.
        self.login()
        response = self.client.get('/logout')
        self.assertEqual(response.status_code, 200)

    def test_existing_anon_cookie_not_in_cache(self):
        response = self.client.get('/')
        self.assertEqual(len(response.wsgi_request.csrf_token), 32)

        # Clear cache and make sure we still get a token
        cache.clear()
        response = self.client.get('/')
        self.assertEqual(len(response.wsgi_request.csrf_token), 32)

    def test_massive_anon_cookie(self):
        # if the key + PREFIX + setting prefix is greater than 250
        # memcache will cry and you get a warning if you use LocMemCache
        junk = 'x' * 300
        with mock.patch('warnings.warn') as warner:
            response = self.client.get('/', HTTP_COOKIE='anoncsrf=%s' % junk)
            self.assertEqual(response.status_code, 200)
            self.assertEqual(warner.call_count, 0)

    def test_surprising_characters(self):
        c = 'anoncsrf="|dir; multidb_pin_writes=y; sessionid="gAJ9cQFVC'
        with mock.patch('warnings.warn') as warner:
            response = self.client.get('/', HTTP_COOKIE=c)
            self.assertEqual(response.status_code, 200)
            self.assertEqual(warner.call_count, 0)


def get_context_processors():
    """Get context processors in a way that works for Django 1.7 and 1.8+"""
    try:
        # 1.7
        from django.template.context import get_standard_processors
        return get_standard_processors()
    except ImportError:
        # 1.8+
        try:
            from django.template.engine import Engine
            engine = Engine.get_default()
        except ImproperlyConfigured:
            return []
        return engine.template_context_processors


# for 1.7 support
class ClientHandler(django.test.client.ClientHandler):
    @property
    def wsgi_request_middleware(self):
        return self._request_middleware
