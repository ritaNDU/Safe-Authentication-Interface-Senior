from werkzeug.security import generate_password_hash, check_password_hash

def set_password(password):
	return generate_password_hash(password) 

def check_password(password,password_to_check):
	return check_password_hash(password_to_check,password)

def password_has_credentials(user, password):
	'''This function's purpose is to check if any user credential has been entered in the password. '''
	password = str(password)
	if (user.username.lower() in password.lower()) or (user.name.lower() in password.lower()) or (user.email.lower() in password.lower()) :
		return True
	return False
def password_same_as_previous(user, tentative_password):
	'''This function's purpose is to make sure that the user entered a password that is different from its previous password. '''
	tentative_password = str(tentative_password)
	if check_password(tentative_password, user.password_hash) :
		return True
	return False
def validate_password_content(password):
	'''This function's purpose is to make sure that the user entered a password taht is at least 8 characters long and that has at least one special character, an upper case and a lower case letter and a number. This is essential to create a strong password. '''
	has_special_character = False
	has_number_character = False
	has_uppercase_letter = False
	has_lowercase_letter = False

	for character in password:
		if character.islower():
			has_lowercase_letter = True
		if character.isupper():
			has_uppercase_letter = True
		if character in "_-!@.$^*":
			has_special_character = True
		if character.isdecimal():
			has_number_character = True

	if len(password) < 8 or not has_special_character or not has_number_character or not has_uppercase_letter or not has_lowercase_letter :
		return False
	return True