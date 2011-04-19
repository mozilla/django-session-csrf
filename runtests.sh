#!/bin/sh

SETTINGS='settings.py'

cat > $SETTINGS <<EOF
DATABASES = {
    'default': {
            'ENGINE': 'django.db.backends.sqlite3',
            'NAME': 'test.db',
    },
}

MIDDLEWARE_CLASSES = (
    'django.middleware.common.CommonMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'session_csrf.CsrfMiddleware',
)

TEMPLATE_CONTEXT_PROCESSORS = (
    'django.contrib.auth.context_processors.auth',
    'django.core.context_processors.debug',
    'django.core.context_processors.i18n',
    'django.core.context_processors.media',
    'django.core.context_processors.static',
    'django.contrib.messages.context_processors.messages',
    'session_csrf.context_processor',
)

ROOT_URLCONF = 'session_csrf.tests'

INSTALLED_APPS = (
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'session_csrf',
)
EOF

export PYTHONPATH=.
export DJANGO_SETTINGS_MODULE=settings

django-admin.py test session_csrf

rm -f $SETTINGS*
rm -f test.db
