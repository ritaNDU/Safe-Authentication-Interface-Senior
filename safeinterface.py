from app import create_app,db
from app.auth import permissions
from app.models import User, Admin, Onetimepassword
'''This is the main application that should be ran on the server.'''

app = create_app()
permissions.register(app)

@app.shell_context_processor
def make_shell_context():
	app.logger.info("A shell session has started.")
	return {"db" : db, "User" : User, "Admin" : Admin, "Onetimepassword": Onetimepassword }

if __name__ == "__main__":
	app.run(ssl_context=("cert.pem","key.pem"))
