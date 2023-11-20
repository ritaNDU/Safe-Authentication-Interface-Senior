from flask import flash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField,SubmitField
from wtforms.validators import DataRequired, ValidationError

class AdminLoginForm(FlaskForm):
	username = StringField("Username", validators=[DataRequired()], render_kw={"placeholder" : "Please enter your username here..."})
	password = PasswordField("Password", validators=[DataRequired()], render_kw={"placeholder" : "Please enter your password here..."})
	otp = PasswordField("OTP", validators=[DataRequired()], render_kw={"placeholder" : "Please enter your OTP here..."})
	submit   = SubmitField("LOGIN")
	
	'''Those are the validators for the forms. Only certain characters are allowed to be entered by the users in the forms. '''
	def validate_username(self, username):
		included_chars = "abcdefghigklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890_"
		for char in self.username.data:
			if char not in included_chars:
				raise ValidationError("You entered an invalid character")

	def validate_password(self, password):
		included_chars = "abcdefghigklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890_!@$^*"
		for char in self.password.data:
			if char not in included_chars:
				raise ValidationError("You entered an invalid character")
				
	def validate_otp(self, otp):
		included_chars = "1234567890"
		for char in self.otp.data:
			if char not in included_chars:
				raise ValidationError("You entered an invalid character")
