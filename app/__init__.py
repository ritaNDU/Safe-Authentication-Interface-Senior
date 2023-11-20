import logging
import os

from logging.handlers import SMTPHandler, RotatingFileHandler

from app.app_logs import RequestFormatter 

from config import Config
from datetime import timedelta

from flask            import Flask, Response, session
from flask_sqlalchemy import SQLAlchemy
from flask_migrate    import Migrate
from flask_login      import LoginManager
from flask_talisman   import Talisman
from flask_principal  import Principal
from flask_mail       import Mail
from flask_paranoid   import Paranoid
from flask_limiter    import Limiter
from flask_limiter.util import get_remote_address

#All libraries used are initialized here...
mail       = Mail()
principals = Principal()
talisman   = Talisman()
db         = SQLAlchemy()
migrate    = Migrate()
login      = LoginManager()
paranoid   = Paranoid() 
limiter    = Limiter(key_func=get_remote_address, default_limits = ["200 per day","50 per hour"])

login.login_view         = "auth.login"
login.refresh_view       = "auth.login"
login.needs_refresh_message = u"Your session has timed out! Please re-login!"
login.needs_refresh_message_category = "info"
login.session_protection = None
paranoid.redirect_view = '/'

def create_app(config_class = Config):
	'''This function takes care of creating the application and configuring it according to either the default or a custom configuration set. '''
	app = Flask(__name__)
	app.config.from_object(config_class)
	
	@app.before_request
	def before_request():
		#A session is set to expire after 5 minutes here. This is specified before a request is sent.
		session.permanent = True
		app.permanent_session_lifetime = timedelta(minutes=5)
	@app.after_request
	def set_headers_after_request(response):
		#Headers are set here after a request is sent.
		response.headers.add('Cache-Control','no-cache, no-store, must-revalidate, post-check=0, precheck=0')
		return response
	#...and configured here
	mail.init_app(app)
	principals.init_app(app)
	talisman.init_app(app)
	db.init_app(app)
	migrate.init_app(app,db)
	login.init_app(app)
	paranoid.init_app(app)
	limiter.init_app(app)
	
	'''Here anything related to email sending and logging is configured.'''
	if not app.debug and not app.testing:
		if app.config["MAIL_SERVER"]:
			auth = None
			if app.config["MAIL_USERNAME"] or app.config["MAIL_PASSWORD"]:
				auth = (app.config["MAIL_USERNAME"], app.config["MAIL_PASSWORD"])
			secure = None
			if app.config["MAIL_USE_TLS"]:
				secure = ()
			mail_handler = SMTPHandler(
				mailhost=(app.config["MAIL_SERVER"], app.config["MAIL_PORT"]),
				fromaddr='noreply@'+ app.config["MAIL_SERVER"],
				toaddrs=app.config["ADMINS"],
				subject="Safe Interface Failure",
				credentials=auth,
				secure=secure)
			mail_handler.setLevel(logging.ERROR)
			app.logger.addHandler(mail_handler)

		if app.config["LOG_TO_STDOUT"]:
				stream_handler = logging.StreamHandler()
				stream_handler.setLevel(logging.INFO)
				app.logger.addHandler(stream_handler)
		else:
			if not os.path.exists("logs"):
				os.mkdir("logs")

			formatter = RequestFormatter('[%(asctime)s] %(remote_addr)s requested %(url)s\n %(levelname)s in %(module)s: %(message)s [in %(pathname)s:%(lineno)d]')

			file_handler = RotatingFileHandler("logs/app_logs.log", maxBytes = 10240, backupCount = 10)
			file_handler.setFormatter(formatter)
			file_handler.setLevel(logging.INFO)
			app.logger.addHandler(file_handler)

		app.logger.setLevel(logging.INFO)
		app.logger.info("Safe Interface Startup")

	#Blueprints registrations
	from app.errors import bp as errors_bp
	app.register_blueprint(errors_bp)
		
	from app.auth import bp as auth_bp
	app.register_blueprint(auth_bp, url_prefix="/auth")
	
	from app.main import bp as main_bp
	app.register_blueprint(main_bp)

	#End Blueprints registration
	return app
	
from app import models
