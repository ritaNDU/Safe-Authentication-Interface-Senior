from flask_principal import UserNeed, Permission, RoleNeed, identity_loaded
from flask_login import current_user

from app.models import Admin
'''This module is used to define permissions.'''
logged_out_admin_role  = RoleNeed("logged_out_admin")  
logged_in_admin_role = RoleNeed("logged_in_admin")


logged_out_admin_permission = Permission(logged_out_admin_role)
logged_in_admin_permission  = Permission(logged_in_admin_role)

def register(app):
	@identity_loaded.connect_via(app)
	def on_identity_loaded(sender,identity):
		identity.user = current_user
		if hasattr(current_user, 'id'):
			identity.provides.add(UserNeed(current_user.id))
			
		if hasattr(current_user, 'is_admin'):
			admin = Admin.query.filter_by(username = current_user.username).first()
			if admin is not None:
				if admin.get_admin_mode():
					identity.provides.add(logged_in_admin_role)
					return
			if current_user.is_admin:
				identity.provides.add(logged_out_admin_role)


