What is this?
-------------

``django-session-csrf`` is an alternative implementation of Django's CSRF
protection that does not use cookies. Instead, it maintains the CSRF token on
the server using Django's session backend. The csrf token must still be
included in all POST requests (either with `csrfmiddlewaretoken` in the form or
with the `X-CSRFTOKEN` header).


Installation
------------

From PyPI::

    pip install django-session-csrf

From github::

    git clone git://github.com/mozilla/django-session-csrf.git

Replace ``django.core.context_processors.csrf`` with
``session_csrf.context_processor`` in your ``TEMPLATE_CONTEXT_PROCESSORS``::

    TEMPLATE_CONTEXT_PROCESSORS = (
        ...
        'session_csrf.context_processor',
        ...
    )

Replace ``django.middleware.csrf.CsrfViewMiddleware`` with
``session_csrf.CsrfMiddleware`` in your ``MIDDLEWARE_CLASSES``::

    MIDDLEWARE_CLASSES = (
        ...
        'session_csrf.CsrfMiddleware',
        ...
    )

Then we have to monkeypatch Django to fix the ``@csrf_protect`` decorator::

    import session_csrf
    session_csrf.monkeypatch()

Make sure that's in something like ``manage.py`` so the patch gets applied
before your views are imported.


Differences from Django
-----------------------

``django-session-csrf`` does not assign CSRF tokens to anonymous users because
we don't want to support a session for every anonymous user. Instead, views
that need anonymous forms can be decorated with ``@anonymous_csrf``::

    from session_csrf import anonymous_csrf

    @anonymous_csrf
    def login(request):
        ...

``anonymous_csrf`` uses the cache to give anonymous users a lightweight
session. It sends a cookie to uniquely identify the user and stores the CSRF
token in the cache.  It can be controlled through these settings:

    ``ANON_COOKIE``
        the name used for the anonymous user's cookie

        Default: ``anoncsrf``

    ``ANON_TIMEOUT``
        the cache timeout (in seconds) to use for the anonymous CSRF tokens

        Default: ``60 * 60 * 2  # 2 hours``


Why do I want this?
-------------------

1. Your site is on a subdomain with other sites that are not under your
   control, so cookies could come from anywhere.
2. You're worried about attackers using Flash to forge HTTP headers.
3. You're tired of requiring a Referer header.


Why don't I want this?
----------------------

1. Storing tokens in sessions means you have to hit your session store more
   often.
2. It's a little bit more work to CSRF-protect forms for anonymous users.
