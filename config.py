import os
from dotenv import load_dotenv

basedir = os.path.abspath(os.path.dirname(__file__))
load_dotenv(os.path.join(basedir,'.flaskenv'))

class Config(object):
	SECRET_KEY = os.urandom(12)
	WTF_CSRF_SECRET_KEY = os.urandom(12)
	LOG_TO_STDOUT = os.environ.get("LOG_TO_STDOUT")
	SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL") or 'sqlite:///' + os.path.join(basedir, 'app.db')
	SQLALCHEMY_TRACK_MODIFICATIONS = False
	MAIL_SERVER = os.environ.get("MAIL_SERVER")
	MAIL_PORT = os.environ.get("MAIL_PORT") or 25
	MAIL_USE_TLS = os.environ.get("MAIL_USE_TLS") or True
	MAIL_USERNAME = os.environ.get("MAIL_USERNAME")
	MAIL_PASSWORD = os.environ.get("MAIL_PASSWORD")
	ADMINS        = ["ritrat1998@gmail.com", "rita.merhej@live.com"]
	SESSION_COOKIE_SECURE = True
	SESSION_COOKIE_HTTP_ONLY = True
	SEND_FILE_MAX_AGE_DEFAULT = 0
