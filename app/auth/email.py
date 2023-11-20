from threading import Thread

from app import mail

from flask import render_template, current_app
from flask_mail import Message

def send_async_email(app,msg):
	with app.app_context():
		mail.send(msg)

def send_email(subject,sender,recipients, text_body, html_body):
	'''This function takes information regarding the email that will be sent, creates a thread and uses the send_async_email function to send emails asynchronously.'''
	msg = Message(subject,sender=sender,recipients=recipients)
	msg.body = text_body
	msg.html = html_body
	Thread(target=send_async_email,args=(current_app._get_current_object(),msg)).start()
	current_app.logger.info("An email has been sent.")


def send_otp_email(admin):
	'''This function takes care of sending an email with a one time password to an admin.'''
	send_email("[Safe User Interface] One Time Password", sender = current_app.config["ADMINS"][0], recipients =[admin.email], text_body = render_template("email/get_otp.txt",admin=admin), html_body = render_template("email/get_otp.html",admin = admin))
	current_app.logger.info("A one time password has been sent to admin {} at {}.".format(admin.username, admin.email))

def send_user_otp_email(user):
	'''This function takes care of sending an email with a one time password to a user, if emails can still be sent to that user. If no emails can be sent, a recovery email is sent instead'''
	if can_send_email(user):
		user.increase_sent_email()
		send_email("[Safe User Interface] One Time Password", sender = current_app.config["ADMINS"][0], recipients =[user.email], text_body = render_template("email/get_otp.txt",admin=user), html_body = render_template("email/get_otp.html",admin = user))
		current_app.logger.info("A one time password has been sent to {} at {} for {} times.".format(user.username, user.email, user.sent_email))
	else:
		send_last_recovery_email(user)
		
def send_password_reset_email(user):
	'''This function takes care of sending a password reset email to a user, if emails can still be sent to that user. If no emails can be sent, a recovery email is sent instead'''
	if can_send_email(user):
		token = user.generate_page_token()
		user.increase_sent_email()
		send_email("[Safe User Interface] Reset Your Password", sender = current_app.config["ADMINS"][0], recipients =[user.email], text_body = render_template("email/reset_password.txt",user=user,token = token, sent_email = user.sent_email), html_body = render_template("email/reset_password.html",user = user, token = token, sent_email = user.sent_email))
		current_app.logger.warning("A password reset email has been sent to {} at {} for {} times.".format(user.username, user.email, user.sent_email))
	else:
		send_last_recovery_email(user)
		
def can_send_email(user):
	'''This function determines if an email can be sent to a user.'''
	if user.sent_email >= 10:
		return False
	return True

def send_last_recovery_email(user):
	'''This function is called to send the last recovery email to the user!'''
	if not can_send_email(user) and user.sent_email == 10:
		token = user.generate_page_token()
		user.increase_sent_email()
		send_email("[Safe User Interface] Reset Your Password", sender = current_app.config["ADMINS"][0], recipients =[user.email], text_body = render_template("email/reset_password.txt",user=user,token = token, sent_email = user.sent_email), html_body = render_template("email/reset_password.html",user = user, token = token, sent_email = user.sent_email))
		current_app.logger.error("The last recovery email has been sent to {} at {} after {} times.".format(user.username, user.email, user.sent_email))