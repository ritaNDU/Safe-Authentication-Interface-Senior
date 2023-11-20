from flask import flash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField,SubmitField
from wtforms.validators import DataRequired, ValidationError, Email, EqualTo
from app.passwords import validate_password_content

class LoginForm(FlaskForm):
	username = StringField("Username", validators=[DataRequired()], render_kw={"placeholder" : "Please enter your username here..."})
	password = PasswordField("Password", validators=[DataRequired()], render_kw={"placeholder" : "Please enter your password here..."})
	submit   = SubmitField("LOGIN")
	'''Those are the validators for the forms. Only certain characters are allowed to be entered by the users in the forms. '''
	def validate_username(self, username):
		included_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890_-."
		for char in self.username.data:
			if char not in included_chars:
				raise ValidationError("You entered an invalid character")
				
	def validate_password(self, password):
		included_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890_.-!@$^*"
		for char in self.password.data:
			if char not in included_chars:
				raise ValidationError("You entered an invalid character")

class ResendOtpForm(FlaskForm):
	'''This is the second form on the user otp login interface. It is used to resend an otp. '''
	send_otp_submit   = SubmitField("Send OTP")


class SendResetPasswordForm(FlaskForm):
	email = StringField("Email", validators=[DataRequired(), Email()], render_kw={"placeholder" : "Please enter your email here..."})
	submit   = SubmitField("Send Password Reset Request")

	def validate_email(self, email):
		included_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890_-!@.$^*"
		for char in self.email.data:
			if char not in included_chars:
				raise ValidationError("You entered an invalid character")

class ResetPasswordForm(FlaskForm):
	'''This form is used to create a new password. The password policy is enforced here, and at the view. '''
	password = PasswordField("Password", validators=[DataRequired()], render_kw={"placeholder" : "Please enter your password here..."})
	password_repeat = PasswordField("Repeat Password", validators=[DataRequired(), EqualTo('password')], render_kw={"placeholder" : "Please enter your password here..."})
	submit   = SubmitField("Request Password Reset")

	def validate_password_repeat(self, password_repeat):
		included_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890_-!@.$^*"
		for char in self.password_repeat.data:
			if char not in included_chars:
				raise ValidationError("You entered an invalid character")
	def validate_password(self, password):
		included_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890_-!@.$^*"
		for char in self.password.data:
			if char not in included_chars:
				raise ValidationError("You entered an invalid character")
		if not validate_password_content(self.password.data):
			flash("The password you chose is weak. Please enter a stronger password. Please check the criterias for a strong password above.")
			raise ValidationError()
class UserOtpLoginForm(FlaskForm):
	username = StringField("Username", validators=[DataRequired()], render_kw={"placeholder" : "Please enter your username here..."})
	password = PasswordField("Password", validators=[DataRequired()], render_kw={"placeholder" : "Please enter your password here..."})
	otp = PasswordField("OTP", validators=[DataRequired()], render_kw={"placeholder" : "Please enter your OTP here..."})
	submit   = SubmitField("LOGIN")
	
	'''Those are the validators for the forms. Only certain characters are allowed to be entered by the users in the forms. '''
	def validate_username(self, username):
		included_chars = "abcdefghigklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890_-."
		for char in self.username.data:
			if char not in included_chars:
				raise ValidationError("You entered an invalid character")

	def validate_password(self, password):
		included_chars = "abcdefghigklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890.-_!@$^*"
		for char in self.password.data:
			if char not in included_chars:
				raise ValidationError("You entered an invalid character")
				
	def validate_otp(self, otp):
		included_chars = "1234567890"
		for char in self.otp.data:
			if char not in included_chars:
				raise ValidationError("You entered an invalid character")
