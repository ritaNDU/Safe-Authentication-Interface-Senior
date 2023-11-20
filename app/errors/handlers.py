from flask import render_template
from app import db
from app.errors import bp
from flask_wtf.csrf import CSRFError
from wtforms.validators import ValidationError
from flask_principal import PermissionDenied

@bp.app_errorhandler(404)
def not_found_error(error):
	return render_template("errors/404.html"),404

@bp.app_errorhandler(429)
def too_many_requests_error(error):
	return render_template("errors/429.html", number_of_requests = error.description),429

@bp.app_errorhandler(500)
def internal_error(error):
	db.session.rollback()
	return render_template("errors/500.html"),500

@bp.app_errorhandler(CSRFError)
def handle_csrf_error(e):
	return render_template("errors/csrf_error.html",reason=e.description),400

@bp.app_errorhandler(PermissionDenied)
def handle_permission_denied_error(e):
	return render_template("errors/permission_denied_error.html"),400
