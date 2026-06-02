DEBUG = False
SECRET_KEY = "token_should_never_render"
ALLOWED_HOSTS = ["example.com", "example.test"]

DATABASE_URL = "postgres://user:pass@example.com/db"

SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
CSRF_COOKIE_SECURE = True
SESSION_COOKIE_SECURE = True
SECURE_SSL_REDIRECT = True
