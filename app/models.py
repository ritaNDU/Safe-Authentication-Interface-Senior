from app import db
from app import login
from app.passwords import set_password

from flask import current_app
from flask_login import UserMixin

from time import time
import os
import base64
import onetimepass
import jwt

class Onetimepassword(db.Model):
	'''This is where one time passwords are stored and managed.'''
	id         = db.Column(db.Integer, primary_key = True)
	otp_secret = db.Column(db.String(16))
	token      = db.Column(db.String(8), unique = True)
	is_used    = db.Column(db.Boolean, nullable=False)
	admin_relation = db.relation('Admin', backref = "otp", lazy = 'dynamic')
	user_relation = db.relation('User', backref = "otp", lazy = 'dynamic')


	def generate_totp(self):
		''' This function generates a token, stores it in the database, marks it as new by setting the is_used property to False, and returns it.'''
		return onetimepass.get_totp(self.otp_secret,interval_length=60) 
	def set_otp(self):
		self.token = self.generate_totp()
		self.is_used = False
		db.session().commit()

	def verify_totp(self,token):
		'''This function checks if the totp that is passed to it is valid. To be valid, the totp has to be brand new, meaning that its is_used property must be False, and should be validated by the function provided by onetimepass. '''
		if not self.is_used:
			return onetimepass.valid_totp(token,self.otp_secret,interval_length=60)
		return False

		
	def __init__(self,**kwargs):
		'''This constructor constructs the new OTP.'''
		super(Onetimepassword,self).__init__(**kwargs)
		if self.otp_secret is None:
			self.otp_secret = base64.b32encode(os.urandom(10)).decode("utf-8")
		self.token = self.generate_totp() 
		self.is_used = True

class UserLockedOut(UserMixin, db.Model):
	id	          = db.Column(db.Integer, primary_key=True) 
	username      = db.Column(db.String(64), index = True, unique = True, nullable=False)

	'''This is where all users of any kind are locked out. '''
	def __repr__(self):
		return "<User {}>".format(self.username)

class Abstract_User(UserMixin, db.Model):
	'''Admin and User will inherit this Abstract_user, therefore it defienes common fields to both.'''
	__abstract__ = True

	name	      = db.Column(db.String(64), nullable=False)
	username      = db.Column(db.String(64), index = True, unique = True, nullable=False)
	email 	      = db.Column(db.String(120) , index = True, unique = True, nullable=False)
	login_attempt_number  = db.Column(db.Integer, default = 0, nullable=False)

	def increase_login_attempt(self):
		self.login_attempt_number += 1
		db.session.commit()

	def initialize_login_attempt(self):
		self.login_attempt_number = 0
		db.session().commit()


class User(Abstract_User):
	'''This class defines regular users. It is used to generate users and admins, whenever is_admin is set to True'''
	id	           = db.Column(db.Integer, primary_key=True)
	is_admin       = db.Column(db.Boolean, nullable=False, default=False)
	sent_email     = db.Column(db.Integer, nullable = False, default = 0)
	password_hash  = db.Column(db.String(128), nullable=False)

	otp_id    = db.Column(db.Integer, db.ForeignKey("onetimepassword.id")) 


	def increase_sent_email(self):
		self.sent_email += 1
		db.session().commit()
	def initialize_sent_email(self):
		self.sent_email = 0
		db.session().commit()
	def get_sent_email(self):
		return self.sent_email

	def set_user_password(self,password):
		self.password_hash = set_password(password)
	def generate_page_token(self, expires_in = 600):
		return jwt.encode({'reset_password' : self.id, 'exp' : time() + expires_in}, current_app.config['SECRET_KEY'],algorithm='HS256')

	@staticmethod	
	def verify_reset_token(token):
		'''This function is used to make sure the token generated for the page is right. If it is the user's id is returned. '''
		try:
			id = jwt.decode(token, current_app.config['SECRET_KEY'],algorithms=['HS256'])['reset_password']
		except:
			return 
		return User.query.get(id)

	def __repr__(self):
		return "<User {}>".format(self.username)

	def __init__(self,**kwargs):
		'''This constructor is useful for generating a new inexisting admin when is_admin is True. If an admin with the user's username already exists, is_admin will be set to false. This shouldn't happen because usernames are unique.'''
		super(User,self).__init__(**kwargs)
		self.otp = Onetimepassword()

class Admin(Abstract_User):
	'''This class defines and manages Admins.'''
	id = db.Column(db.Integer, primary_key = True)
	admin_password_hash = db.Column(db.String(128), nullable=False)
	admin_mode     = db.Column(db.Boolean, nullable=False, default = False)
	otp_id    = db.Column(db.Integer, db.ForeignKey("onetimepassword.id")) 

	def set_admin_password(self,password):
		self.admin_password_hash = set_password(password)
		db.session().commit()
	def set_admin_mode(self,mode):
		self.admin_mode = mode
		db.session().commit()
	def get_admin_mode(self):
		return self.admin_mode

	def __init__(self,**kwargs):
		'''This constructor constructs the new Admin and links an OTP to it. '''
		super(Admin,self).__init__(**kwargs)
		self.otp = Onetimepassword()

	def __repr__(self):
		return "<Admin {}>".format(self.username)

@login.user_loader
def load_user(id):
	'''This is a user loader function. Its main task is to load the user from the database using its id, to the flask-login module. '''
	return User.query.get(int(id))

