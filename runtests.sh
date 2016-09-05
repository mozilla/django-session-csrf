#!/bin/sh

SETTINGS='settings.py'

cat > $SETTINGS <<EOF
DATABASES = {
    'default': {
            'ENGINE': 'django.db.backends.sqlite3',
            'NAME': ':memory:',
    },
}

MIDDLEWARE_CLASSES = MIDDLEWARE = (
    'django.middleware.common.CommonMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'session_csrf.CsrfMiddleware',
)

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'OPTIONS': {
            'context_processors': [
                'django.contrib.auth.context_processors.auth',
                'django.template.context_processors.debug',
                'django.template.context_processors.i18n',
                'django.template.context_processors.media',
                'django.template.context_processors.static',
                'django.contrib.messages.context_processors.messages',
                'session_csrf.context_processor',
            ],
        },
    },
]

ROOT_URLCONF = 'session_csrf.tests'

INSTALLED_APPS = (
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'session_csrf',
)
SECRET_KEY = 'asdf'
EOF

export PYTHONPATH=.
export DJANGO_SETTINGS_MODULE=settings

django-admin.py test session_csrf $@
return_code=$?

rm -f $SETTINGS*

exit $return_code
