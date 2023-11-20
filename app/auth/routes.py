from datetime import timedelta

from app import limiter, db
from app.auth import bp
from app.auth.permissions import logged_in_admin_permission, logged_out_admin_permission,logged_in_admin_role, logged_out_admin_role
from app.auth.forms import ResendOtpForm,LoginForm, SendResetPasswordForm, ResetPasswordForm, UserOtpLoginForm
from app.auth.admin_forms import AdminLoginForm
from app.models import User, Admin, UserLockedOut
from app.passwords import * 
from app.auth.email import can_send_email, send_otp_email, send_user_otp_email, send_password_reset_email
from app.auth.lock_user_out import add_to_lockout_admin,add_to_lockout_user, remove_from_lockout_user

from flask import render_template, flash, redirect, url_for, request, session, current_app
from flask_login import current_user, login_user,fresh_login_required, login_required, logout_user
from flask_principal import Identity, identity_changed, AnonymousIdentity
from werkzeug.urls import url_parse
from wtforms.validators import ValidationError

account_access_limit = limiter.shared_limit("15/minute;3/second", scope="user_admin_profiles")

@bp.route("/userprofile")
@account_access_limit
@login_required
def userprofile():
	'''This is the route to the user's profile. If a logged in admin accesses it, the admin is immediatelly degradded. '''
	if logged_in_admin_permission.can():
		return redirect(url_for("auth.degrade"))
	user_locked_out = UserLockedOut.query.filter_by(username = current_user.username).first()
	if user_locked_out is None:
		return render_template("auth/user_profile.html", user=current_user,admin=current_user.is_admin, status = "User", admin_mode = False)
	flash("You have been locked out. Instructions have been sent to your email address.")
	return redirect(url_for("auth.logout"))
@bp.route("/adminprofile")
@account_access_limit
@login_required
@logged_in_admin_permission.require()
def adminprofile():
	admin = Admin.query.filter_by(username = current_user.username).first()
	return render_template("auth/user_profile.html", user=current_user,admin=current_user.is_admin, status = "Admin", admin_mode = admin.get_admin_mode())

@bp.route("/login", methods=['GET','POST'])
@limiter.limit("10/minute")
@limiter.limit("2/second")
def login():
	'''All the login process is crammed into this function. 
	When the user clicks on the submit field on the interface, the login process is triggered. 
	The username is first fetched, and checked. Then the password is hashed and compared to the password hash of the user. 
	If there is a problem with either the username or the password, the login process is aborted, and the user is redirected to the login template, and a warning is displayed. 
	If the user tries to login for more than a certain amount of times, he is either redirected to an otp login page or is locked out, depending on how many times the user has tried. 
	If the user has been locked out, he/she can no longer login, and has to recover the account first.
	Otherwise the user is directed to his/her profile page.
	If the user is already authenticated, and has a valid session, he/she doesn't have to pass through he whole process
	and is directly redirected to his/her profile page.'''
	if current_user.is_authenticated:
		return redirect(url_for("auth.userprofile"))

	form = LoginForm()
	if form.validate_on_submit():
		user = User.query.filter_by(username = form.username.data).first()
		if user is not None:
			user_locked_out = UserLockedOut.query.filter_by(username = user.username).first()
			if user_locked_out is not None:
				flash("You have been locked out. Instructions have been sent to your email address.")
				return redirect(url_for("auth.login"))
		
		if user is None or not check_password(form.password.data,user.password_hash):
			if user is not None:
				if user.login_attempt_number >= 3:
					token = user.generate_page_token()
					return redirect(url_for("auth.userotplogin",token=token))
				if user.login_attempt_number >= 5:
					add_to_lockout_user(user)
					current_app.logger.info("{} has been locked out.".format(user.username))

			user.increase_login_attempt()
			current_app.logger.info("{} tried to log in {} times.".format(user.username, user.login_attempt_number))
			flash("Invalid username or password.")
			return redirect(url_for("auth.login"))
		
		if user.login_attempt_number < 3:
			login_user(user)
			user.initialize_login_attempt()
			identity_changed.send(current_app._get_current_object(),identity = Identity(user.id))
			current_app.logger.info("{} logged in.".format(user.username))
			next_page = request.args.get("next")
			if not next_page or url_parse(next_page).netloc != "":
				next_page = url_for("auth.userprofile")
			return redirect(url_for("auth.userprofile"))
		else:
			token = user.generate_page_token()
			return redirect(url_for("auth.userotplogin",token=token))
	
	return render_template("auth/login.html", form=form)

@bp.route("/userotplogin/<token>",  methods=['GET','POST'])
@limiter.limit("10/minute")
@limiter.limit("2/second")
def userotplogin(token):
	'''The user is redirected here after a certain amount of failed logins. The process is the same
	as the regular user login, except that the user has to retreive and enter an otp.
	After a certain amount of failed login attempts the user is locked out. '''
	if current_user.is_authenticated:
		return redirect(url_for("auth.userprofile"))

	form = UserOtpLoginForm()
	resend_otp_form = ResendOtpForm() 

	user = User.verify_reset_token(token)

	if not user:
		flash("The link you followed is invalid, please try again!")
		return redirect(url_for("auth.login"))
	current_app.logger.info("{} accessed the otp login screen.".format(user.username))
	user_locked_out = UserLockedOut.query.filter_by(username = user.username).first()
	if user_locked_out is not None:
		flash("You have been locked out. Instructions have been sent to your email address.")
		return redirect(url_for("auth.login"))

	if resend_otp_form.validate_on_submit() and resend_otp_form.send_otp_submit.data:
		if user.sent_email <= 10:
			if user.sent_email < 10:
				user.otp.set_otp()
		send_user_otp_email(user)
		flash("A new one time password has been sent to your email.")
		flash("You can now login below.")
		return redirect(url_for("auth.userotplogin",token=token))
	
	if form.validate_on_submit() and form.submit.data:
		if user.username != form.username.data or not check_password(form.password.data,user.password_hash) or not user.otp.verify_totp(form.otp.data):
			user.increase_login_attempt()
			current_app.logger.info("{} tried to log in {} times.".format(user.username, user.login_attempt_number))

			if user.login_attempt_number >= 5:
				add_to_lockout_user(user)
				current_app.logger.info("{} has been locked out.".format(user.username))

			flash("Invalid username or password or token.")
			return redirect(url_for("auth.userotplogin",token=token))

		login_user(user)
		user.initialize_login_attempt()
		identity_changed.send(current_app._get_current_object(),identity = Identity(user.id))
				
		next_page = request.args.get("next")
		if not next_page or url_parse(next_page).netloc != "":
			next_page = url_for("auth.userprofile")
		return redirect(url_for("auth.userprofile"))
	
	return render_template("auth/user_otp_login.html",form=form, send_otp_form = resend_otp_form)


@bp.route("/transition")
@fresh_login_required
@logged_out_admin_permission.require()
@limiter.limit("2/minute")
@limiter.limit("1/second")
def transition():
	'''This page can only be accessed by un-logged in admins. This is just to remind them to login to their emails in order to get an otp as it cannot be resent manually. '''
	return render_template("email/transition_email.html")

@bp.route("/reset_password/<token>",  methods=['GET','POST'])
def reset_password(token):
	'''This page is where the user changes his/her password. A password policy is enforced in order to guarantee that a user has a good password.'''
	if current_user.is_authenticated:
		return redirect(url_for("auth.userprofile"))
	form = ResetPasswordForm()
	user = User.verify_reset_token(token)
	if not user:
		flash("The link you followed is invalid, please try again!")
		return redirect(url_for("auth.login"))

	if form.validate_on_submit() and form.submit.data:
		if password_has_credentials(user, form.password.data) or password_same_as_previous(user, form.password.data):
			flash("The password you chose is weak. Please enter a stronger password. Please check the criterias for a strong password above.")
			return redirect(url_for("auth.reset_password", token))
		
		user.set_user_password(form.password.data)
		current_app.logger.info("{}'s password has been changed.".format(user.username))
		db.session().commit()
		''' Whenever the locked out user resets his/her password, the account is unlocked. '''
		locked_out_user = UserLockedOut.query.filter_by(username = user.username).first()
		if locked_out_user:
			remove_from_lockout_user(locked_out_user)
			current_app.logger.info("{}'s account has been unlocked.".format(user.username))

			flash("Your account has been reset!")
		if not can_send_email(user):
			user.initialize_sent_email()

		flash("Your password has been reset!")
		return redirect(url_for("auth.login"))
	return render_template("auth/reset_password.html", form = form)

@bp.route("/reset_password_request",  methods=['GET','POST'])
def reset_password_request():
	'''The user requests here a password reset request. He/she has to enter a valid, registered email address, and wait for the recovery email to be sent. '''
	if current_user.is_authenticated:
		return redirect(url_for("auth.userprofile"))
	form = SendResetPasswordForm()
	if form.validate_on_submit():
		user = User.query.filter_by(email = form.email.data).first()
		if user:
			send_password_reset_email(user)
			current_app.logger.info("A password reset request has been requested for the following email address: {}.".format(user.email))
		else:
			current_app.logger.info("A password reset email has been requested to an invalid email address.")
		flash("Check your email for instructions!")
		return redirect(url_for("auth.login"))
	return render_template("auth/reset_password_request.html", form = form)

@bp.route("/adminlogin", methods=["GET","POST"])
@limiter.limit("10/minute")
@limiter.limit("1/second")
@fresh_login_required
@logged_out_admin_permission.require()
def adminlogin():
	'''The process here is pretty similar to the regular login process, except that a one time password token is generated and sent to the admin via email, and is then checked. When the admin logs in successfully, logged_in_admin role is granted. '''
	if not current_user.is_admin:
		'''This is specified just in case. '''
		redirect(url_for("auth.logout"))
		flash("Access to that page is resticted!")

	admin_form = AdminLoginForm()
	admin = Admin.query.filter_by(username = current_user.username).first()
	admin.otp.set_otp()
	'''This line will be removed, it is there for testing purpose.'''
	send_otp_email(admin)
	print(admin.otp.token)

	if admin_form.validate_on_submit():
		admin = Admin.query.filter_by(username = admin_form.username.data).first()
		if admin is not None:
			admin_locked_out = UserLockedOut.query.filter_by(username = admin.username).first()
			if admin_locked_out is not None:
				flash("You have been locked out. Instructions have been sent to your email address.")
				return redirect(url_for("auth.logout"))
		if admin is None or admin.username != admin_form.username.data or not check_password(admin_form.password.data,admin.admin_password_hash) or not admin.otp.verify_totp(admin_form.otp.data):
			admin.increase_login_attempt()
			if admin.login_attempt_number >= 3:
				add_to_lockout_admin(admin)
				current_app.logger.info("Admin {} has been locked out.".format(admin.username))

			current_app.logger.info("Admin {} tried to log in {} times.".format(admin.username, admin.login_attempt_number))
			flash("Invalid username or password or token.")
			return redirect(url_for("auth.adminlogin"))
			
		admin.set_admin_mode(True)	
		identity_changed.send(current_app._get_current_object(),identity = Identity(current_user.id))
		current_app.logger.info("Admin {} has logged in.".format(admin.username))

		next_page = request.args.get("next")
		if not next_page or url_parse(next_page).netloc != "":
			next_page = url_for("auth.adminprofile")
		return redirect(url_for("auth.adminprofile"))
	return render_template("auth/admin_login.html",form=admin_form)

@login_required
@bp.route("/logout")
def logout():
	if not current_user.is_anonymous:
		current_app.logger.info("{} has logged out.".format(current_user.username))
	logout_user()
	for key in ("identity.name","identity_type"):
		'''This process is necessary to get rid of all permissions granted to the user.'''
		session.pop(key,None)
	identity_changed.send(current_app._get_current_object(),identity=AnonymousIdentity())
	return redirect(url_for("auth.login"))

@fresh_login_required
@bp.route('/degrade')
def degrade():
	'''This function's purpose is to degrade an admin from an logged_in_admin role, to an logged_out_admin_role'''
	if not current_user.is_anonymous:
		admin = Admin.query.filter_by(username = current_user.username).first()
		for key in ("identity.name","identity_type"):
			session.pop(key,None)
		admin.set_admin_mode(False)
		identity_changed.send(current_app._get_current_object(),identity=Identity(current_user.id))
		current_app.logger.info("Admin {} has degraded.".format(admin.username))
	return redirect(url_for("auth.userprofile"))

