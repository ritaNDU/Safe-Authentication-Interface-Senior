from datetime import timedelta

from app import db
from app.models import UserLockedOut, User, Admin
from app.auth.email import send_password_reset_email

def add_to_lockout_user(user):
	'''This function adds the user to lockout to the UserLockedOut table in the database and sends the recovery message to the user.
		If the user is already locked out, '''
	user_to_lockout = UserLockedOut.query.filter_by(username = user.username).first()
	if user_to_lockout is None:
		user_to_lockout = UserLockedOut(username = user.username)
		db.session().add(user_to_lockout)
		db.session().commit()
		send_password_reset_email(user)

def add_to_lockout_admin(admin):
	'''This function adds the user to lockout to the UserLockedOut table in the database and sends the recovery message to the user.
		If the user is already locked out, '''
	admin_to_lockout = UserLockedOut.query.filter_by(username = admin.username).first()
	if admin_to_lockout is None:
		admin_to_lockout = UserLockedOut(username = admin.username)
		user = User.query.filter_by(username = admin.username).first()
		user.is_admin = False
		db.session().add(admin_to_lockout)
		db.session().delete(admin)
		db.session().commit()
		send_password_reset_email(user)

def remove_from_lockout_user(user):
	'''This function removes the locked out user from the UserLockedOut table in the database.'''
	user_to_lockout = UserLockedOut.query.filter_by(username = user.username).first()
	if user_to_lockout is None:
		db.session().delete(user_to_lockout)
		db.session().commit()
