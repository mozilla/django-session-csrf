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

Everything else should be identical to the built-in CSRF protection.


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
2. You want CSRF protection for anonymous users. ``django-session-csrf`` does
   not create CSRF tokens for anonymous users since we're worried about the
   scalability of that.
