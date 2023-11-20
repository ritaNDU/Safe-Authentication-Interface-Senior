import unittest
import random

from app import create_app,db
from app.models import User, Admin, Onetimepassword, UserLockedOut
from app.passwords import check_password, password_has_credentials, password_same_as_previous, validate_password_content
from app.auth.lock_user_out import  add_to_lockout_admin, add_to_lockout_user, remove_from_lockout_user
from app.auth.forms import LoginForm, SendResetPasswordForm, ResetPasswordForm, UserOtpLoginForm
from app.auth.admin_forms import AdminLoginForm

from flask import Flask
from flask_login import current_user
from flask_testing import TestCase

from config import Config

class TestConfig(Config):
	TESTING = True 
	DEBUG = True
	SQLALCHEMY_DATABASE_URI = "sqlite://"
	MAIL_SERVER = "smtp.googlemail.com"
	SERVER_NAME = "127.0.0.1"


class MyTest(unittest.TestCase):	
	def setUp(self):
		app = create_app(TestConfig)
		self.app = app.test_client()
		self.app_context = app.app_context()
		self.app_context.push()
		db.create_all()

	def tearDown(self):
		db.session.remove()
		db.drop_all()
		self.app_context.pop()

	def test_login_form_validation(self):
		user = User(username = "x", name = "y", email = "z", is_admin = False)
		self.add_user(user)
		right_password = "random"
		wrong_password = "r"

		'''Right Login '''
		response = self.login_user(user.username, right_password)
		self.assertEqual(response.status_code, 200)
		response = self.logout_user()
		self.assertEqual(response.status_code, 200)

		'''Wrong Login Username '''
		wrong_username = "y"
		response = self.login_user(wrong_username, right_password)
		self.assertEqual(current_user, None)

		'''Wrong Login password'''
		response = self.login_user(user.username, wrong_password)
		self.assertEqual(current_user, None)

		'''Login with username containing an invalid character.'''
		username_with_invalid_character = "@"
		response = self.login_user(username_with_invalid_character, wrong_password)
		self.assertIn(b"You entered an invalid character",response.data)

		'''Login with password containing an invalid character.'''
		password_with_invalid_character = "'"
		response = self.login_user(user.username, password_with_invalid_character)
		self.assertIn(b"You entered an invalid character",response.data)

		self.remove_user(user)

	def test_loginotp_form_validation(self):
		user = User(username = "x", name = "y", email = "z", is_admin = False)
		self.add_user(user)
		username = "ritr@t"
		password = "rand'm"
		otp = "ab"

		'''Test entering invalid character in all the fields. '''
		response = self.otp_login_user(user, username, password,otp)
		self.assertIn(b"You entered an invalid character",response.data)
		
		'''Test a valid form. '''
		password = "random"
		user.otp.set_otp()
		response = self.otp_login_user(user, user.username, password,user.otp.token)
		self.assertNotIn(b"You entered an invalid character",response.data)

		self.remove_user(user)

	def test_reset_password_request_form_validation(self):
		right_email = "ritrat@email.com"
		wrong_format_email = "ritratemail.com"
		invalid_character_email = "'ritrat@email.com"

		'''Test for invalid email format. '''
		response =  self.app.post("/auth/reset_password_request", data = dict(email = wrong_format_email),follow_redirects = True)
		self.assertIn(b"Invalid email address.",response.data)
		'''Test for email containing an invalid character. '''
		response =  self.app.post("/auth/reset_password_request",data = dict(email = invalid_character_email),follow_redirects = True)
		self.assertIn(b"You entered an invalid character",response.data)
		'''Test for a correct email. '''
		response =  self.app.post("/auth/reset_password_request",data = dict(email = right_email),follow_redirects = True)
		self.assertNotIn(b"You entered an invalid character",response.data)
		self.assertNotIn(b"Invalid email address.",response.data)


	def test_reset_password_form_validation(self):
		user = User(username = "x", name = "y", email = "z", is_admin = False)
		self.add_user(user)

		correct_password = "H3l!oOoOo"
		correct_password_repeat = "H3l!oOoOo"
		invalid_character_password= "ritr't"
		wrong_password_repeat = "hello"

		token = user.generate_page_token()
		'''Test entering not matching passwords. '''
		response =  self.app.post("/auth/reset_password/{token}".format(token = token), data = dict(password = correct_password, password_repeat = wrong_password_repeat),follow_redirects = True)
		self.assertIn(b"Field must be equal to password.",response.data)
		'''Test entering invalid character in all the fields. '''
		response =  self.app.post("/auth/reset_password/{token}".format(token = token), data = dict(password = invalid_character_password, password_repeat = invalid_character_password),follow_redirects = True)
		self.assertIn(b"You entered an invalid character",response.data)
		'''Test a valid form. '''
		response =  self.app.post("/auth/reset_password/{token}".format(token = token), data = dict(password = correct_password, password_repeat = correct_password_repeat),follow_redirects = True)
		self.assertNotIn(b"You entered an invalid character",response.data)
		self.assertNotIn(b"Field must be equal to password.",response.data)

		self.remove_user(user)

	#Start testing lock out user 
	def test_manage_lockout_user(self):
		user = User(username = "x", name = "y", email = "z", is_admin = False)
		self.add_user(user)
		'''Test lockiing out a user. '''
		add_to_lockout_user(user)

		locked_out_user_test = UserLockedOut(username = user.username)
		user_locked_out = UserLockedOut.query.filter_by(username = user.username).first()

		self.assertEqual(locked_out_user_test.username,user_locked_out.username)

		'''Test removing a user from lockout. '''
		remove_from_lockout_user(user)
		user_locked_out = UserLockedOut.query.filter_by(username = user.username).first()

		self.assertEqual(None,user_locked_out)


		self.remove_user(user)

	def test_add_to_lockout_admin(self):
		user = User(username = "x", name = "y", email = "z", is_admin = True)
		self.add_user(user)
		admin = Admin(username = "x", name = "y", email = "z")
		self.add_admin(admin)
		'''Test locking out an admin.... '''
		add_to_lockout_admin(admin)
		admin_locked_out = UserLockedOut(username = user.username)
		locked_out_admin_test = UserLockedOut.query.filter_by(username = admin.username).first()
		admin_account = Admin.query.filter_by(username = user.username).first()
		self.assertEqual(locked_out_admin_test.username,admin_locked_out.username)
		'''...and removing all its priviledges.'''
		self.assertEqual(None,admin_account)

		self.remove_user(user)
	#End testing lock out user 

	#Start testing Passwords 
	def test_password_hashing(self):
		'''Testing password hashing.'''
		'''The same function is used for admins and users, therefore it will be tested for just one of them.'''
		u =  User(username = "susan")
		u.set_user_password("cat")
		self.assertFalse(check_password("dog",u.password_hash))
		self.assertTrue(check_password("cat", u.password_hash))

	def test_password_has_credentials(self):
		user = User(username = "ritrat", name = "rita", email = "email@email.com", is_admin = False)
		self.add_user(user)

		password_with_username = user.username
		password_with_name = user.name
		password_with_mail = user.email
		right_password = "abcdefghijklmnop"

		'''Test entering the right password. '''
		self.assertFalse(password_has_credentials(user,right_password))
		'''Test entering a password with the user's username. '''
		self.assertTrue(password_has_credentials(user,password_with_username))
		'''Test entering a password with the user's name. '''
		self.assertTrue(password_has_credentials(user,password_with_name))
		'''Test entering a password with the user's email. '''
		self.assertTrue(password_has_credentials(user,password_with_mail))


		self.remove_user(user)	

	def test_password_same_as_previous(self):
		user = User(username = "x", name = "y", email = "z", is_admin = False)
		self.add_user(user)
		''' Testing setting a new password, using the previous password.'''
		new_password_different = "hello"
		new_password_same = "random"

		self.assertTrue(password_same_as_previous(user,new_password_same))
		self.assertFalse(password_same_as_previous(user,new_password_different))

		self.remove_user(user)

	def test_validate_password_content(self):
		'''Testing valid passwords entries by generating many good and bad passwords. Bad passwords all miss a certain property of the strong password. '''
		good_passwords = []
		bad_passwords   = []
		
		number_of_good_passwords = 5
		number_of_bad_passwords  = 10

		length_less_than_8 = 1
		length_more_than_8 = 9
		passwords_without_numbers            = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-!@.$^*"
		passwords_without_special_characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
		passwords_without_uppercase_letters  = "abcdefghijklmnopqrstuvwxyz1234567890_-!@.$^*"
		passwords_without_lowercase_letters  = "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890_-!@.$^*"
		correct_password_set    			 = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890_-!@.$^*"
		for i in range(number_of_good_passwords):
			length_more_than_8 = random.randint(8,20)
			password_to_add = self.generate_password_from_set(length_more_than_8, correct_password_set)
			password_to_add += "1Aa*"
			good_passwords += [password_to_add]

		for i in range(number_of_bad_passwords):
			length_less_than_8 = random.randint(0,3)
			length_more_than_8 = random.randint(8,20)
			#Password with bad length
			password_to_add = self.generate_password_from_set(length_less_than_8,correct_password_set)
			password_to_add += "1Aa*"
			bad_passwords += [password_to_add]
			i += 1

			#Passwords each  missing a set of characters
			password_to_add = self.generate_password_from_set(length_more_than_8,passwords_without_special_characters)
			password_to_add += "aA1"
			bad_passwords += [password_to_add]
			i += 1

			password_to_add = self.generate_password_from_set(length_more_than_8,passwords_without_numbers)
			password_to_add += "aA*"
			bad_passwords += [password_to_add]
			i += 1

			password_to_add = self.generate_password_from_set(length_more_than_8,passwords_without_uppercase_letters)
			password_to_add += "a*1"
			bad_passwords += [password_to_add]
			i += 1

			password_to_add = self.generate_password_from_set(length_more_than_8,passwords_without_lowercase_letters)
			password_to_add += "*A1"
			bad_passwords += [password_to_add]

		for password in good_passwords:
			self.assertTrue(validate_password_content(password))
		for password in bad_passwords:
			self.assertFalse(validate_password_content(password))

	#End Testing Passwords

	#Start tesing Models module.
	def test_one_time_password_generation(self):
		'''Testing the validation process of an otp token is tested. Whenever a token is marked as used, it should be rejected.'''
		
		otp = Onetimepassword()
		otp.set_otp()
		self.assertTrue(otp.verify_totp(otp.token))

		otp.set_otp()
		otp.is_used = True
		self.assertFalse(otp.verify_totp(otp.token))

	def test_increase_login_attempt_number_user(self):
		user = User(username = "x", name = "y", email = "z", is_admin = False)
		self.add_user(user)
		
		'''Testing whether the increase_login_attempt actually increases the login attempts of the user.'''
		increased_login_attempt_number = user.login_attempt_number + 1
		user.increase_login_attempt()	
		self.assertEqual(user.login_attempt_number, increased_login_attempt_number)
		
		self.remove_user(user)
	def test_increase_login_attempt_number_admin(self):
		admin = Admin(username = "x", name = "y", email = "z")
		self.add_admin(admin)
		
		'''Testing whether the increase_login_attempt actually increases the login attempts of the admin.'''
		increased_login_attempt_number = admin.login_attempt_number + 1
		admin.increase_login_attempt()

		self.assertEqual(admin.login_attempt_number, increased_login_attempt_number)
		
		self.remove_admin(admin)
	
	def test_initialize_login_attempt_number_user(self):
		user = User(username = "x", name = "y", email = "z", is_admin = False)
		self.add_user(user)

		'''Testing whether the initialize_login_attempt actually initializes the login attempts of the user.'''
		initialized_login_attempt_number = 0
		user.initialize_login_attempt()	
		self.assertEqual(user.login_attempt_number, initialized_login_attempt_number)
		self.remove_user(user)
	def test_initialize_login_attempt_number_admin(self):
		admin = Admin(username = "x", name = "y", email = "z")
		self.add_admin(admin)

		'''Testing whether the initialize_login_attempt actually initializes the login attempts of the admin.'''
		initialized_login_attempt_number = 0
		admin.initialize_login_attempt()
		self.assertEqual(admin.login_attempt_number, initialized_login_attempt_number)
		self.remove_admin(admin)

	def test_increase_sent_email_user(self):
		user = User(username = "x", name = "y", email = "z", is_admin = False)
		self.add_user(user)

		'''Testing whether the increase_sent_email actually increases the number of emails sent to the user.'''
		increased_sent_email = user.sent_email + 1
		user.increase_sent_email()	
		self.assertEqual(user.sent_email, increased_sent_email)
		
		self.remove_user(user)
	
	def test_initialize_sent_email(self):
		user = User(username = "x", name = "y", email = "z", is_admin = False)
		self.add_user(user)

		'''Testing whether the initialize_sent_email actually initializes the number of emails sent to the user.'''
		initialized_sent_email = 0
		user.initialize_sent_email()	
		self.assertEqual(user.sent_email, initialized_sent_email)
		
		self.remove_user(user)
	
	def test_get_sent_email(self):
		user = User(username = "x", name = "y", email = "z", is_admin = False)
		self.add_user(user)

		'''Testing whether the get_sent_email actually gets the number of emails sent to the user.'''

		number_sent_email = user.get_sent_email()	
		self.assertEqual(user.sent_email, number_sent_email)
		
		self.remove_user(user)
	
	def test_set_user_password(self):
		'''Testing the setting of a user's password, withoout ny validation. '''
		password = "random"
		wrong_password = "rand"

		user = User(username = "x", name = "y", email = "z", is_admin = False)
		user.set_user_password(password)
		db.session().add(user)
		db.session().commit()

		self.assertTrue(check_password(password,user.password_hash))
		self.assertFalse(check_password(wrong_password,user.password_hash))
		
		self.remove_user(user)

	def test_generate_and_verify_page_token(self):
		'''Testing the generation process of page tokens. The verification and the generation are both tackled.'''
		wrong_password = "rand"

		user = User(username = "x", name = "y", email = "z", is_admin = False)
		self.add_user(user)
		token = user.generate_page_token()
		user_from_token = User.verify_reset_token(token)

		self.assertEqual(user,user_from_token)
		
		self.remove_user(user)

	def test_set_admin_mode(self):
		'''Testing whether the set_admin_mmode function correctly enables and disables admin mode.'''
		admin = Admin(username = "x", name = "y", email = "z")
		self.add_admin(admin)

		admin_mode_set_true = True
		admin_mode_set_false =  False

		admin.set_admin_mode(admin_mode_set_true)
		self.assertTrue(admin.admin_mode)

		admin.set_admin_mode(admin_mode_set_false)
		self.assertFalse(admin.admin_mode)

		self.remove_admin(admin)

	def test_get_admin_mode(self):
		'''Testing whether get_admin_mode correctly returns the current admin mode. '''
		admin = Admin(username = "x", name = "y", email = "z")
		self.add_admin(admin)

		admin_mode_retrieved = admin.get_admin_mode()

		self.assertEqual(admin_mode_retrieved ,admin.admin_mode)

		self.remove_admin(admin)
	#End tesing Models module.
	

	#Helper methods
	def add_user(self,user):
		'''Helper methode to add a user to the database. '''
		user.set_user_password("random")
		db.session().add(user)
		db.session().commit()
	def remove_user(self,user):
		'''Helper method to remove a user from the database. '''
		db.session().delete(user)
		db.session().commit()

	def add_admin(self,admin):
		'''Helper methode to add a admin to the database. '''
		admin.set_admin_password("random")
		db.session().add(admin)
		db.session().commit()
	def remove_admin(self,admin):
		'''Helper method to remove a admin from the database. '''
		db.session().delete(admin)
		db.session().commit()

	def generate_password_from_set(self,length, password_set):
		'''Helper method to  generate password strings from a set. '''
		password = ""
		index = random.randint(0,length)
		for i in range(length):
			password += password_set[index] 
			index = random.randint(0,length)
		return password

	def login_user(self,username, password):
		'''Helper method to redirect and send data to the login page.'''
		return self.app.post("/auth/login", data = dict(username=username, password = password),follow_redirects = True)
	def logout_user(self):
		'''Helper method to logout.'''
		return self.app.get("/auth/logout", follow_redirects = True)
	def otp_login_user(self, user, username, password,otp):
		'''Helper method to redirect and send data to the user otp login page.'''
		token = user.generate_page_token()
		return self.app.post("/auth/userotplogin/{token}".format(token = token), data = dict(username=username, password = password, otp = otp),follow_redirects = True)

if __name__ == '__main__':
	unittest.main(verbosity=2)
