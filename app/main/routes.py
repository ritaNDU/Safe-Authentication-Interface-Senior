from app import limiter
from app.main import bp

from flask import redirect, url_for

@limiter.limit("10/minute")
@limiter.limit("2/second")
@bp.route("/", methods=["GET","POST"])
def home():
	return redirect(url_for("auth.login"))
