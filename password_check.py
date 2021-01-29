import configparser

import pyhibp
from pyhibp import pwnedpasswords as pw
import bcrypt, re
import datetime
import pandas as pd
from utils.helper import save_to_file_mode_append, save_to_file_without_header

# accessing the config file
config = configparser.ConfigParser(interpolation=None)
config.read('./utils/config.ini')


'''
This will validate the password against mentioned criteria
config.ini file contains the criteria for creating passwords.
We can also change the configuration at one place if required in future.
'''
def validate_password(password):
    password_min_chars = int(config.get('PASSWORD', 'CHAR_COUNT'))
    required_chars = config.get('PASSWORD', 'REQUIRED_CHARS').split(',')
    if len(password) < password_min_chars or re.search('\s', password):
        return False
    for each_required_chars in required_chars:
        if not re.search(each_required_chars, password):
            return False
    return True


'''
This function is used to check if the password is pawned by calling pawned password site.
Also, it returns us the number of times this password is used before.
'''
def check_pawned_password(password):
    pyhibp.set_user_agent(ua="HIBP Application/0.0.1")
    return pw.is_password_breached(password=password)


'''
This method is used to hash the password
This will accept the plain text password and hash it using bcrypt hashing algorithm.
'''
def hash_password(password):
    # encrypt user entered password
    raw_password = bytes(password, 'utf-8')
    salt = bcrypt.gensalt(12)
    hashed_password = bcrypt.hashpw(raw_password, salt)
    return hashed_password, salt


'''
This function is used to save the password in database i.e. password.csv file
'''
def save_password(hashed_password, salt, username, system):
    file_name = "password.csv"
    date = datetime.datetime.now()
    df2 = pd.DataFrame({'Username':[username],'System':[system], 'Salt':[salt],'Hashed_Password':[hashed_password],'Date':[date]})
    with open(file_name, 'rb') as file:
        if len(file.read()) == 0:
            # insert new record in empty csv file
            save_to_file_mode_append(df2, file_name)
        else:
            # append the record in csv file which already contains data
            save_to_file_without_header(df2, file_name)


'''
This method is used to check if the password matches the hashed password or not.
'''
def match_password(hashed_password, password):
    hashed_password = hashed_password.replace('b\'', '').replace('\'', '')
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))


'''
This method is used to check the password against defined password criteria
'''
def all_checks(password, confirm_password):
    error=""
    pawned_pass_limit = int(config.get('PASSWORD', 'PAWNED_PASSWORD_LIMIT'))
    if password != confirm_password:
        error = "Passwords do not match"
    if not validate_password(password):
        error = "Password did not mach with the criteria, please try with new password"
    if check_pawned_password(password) > pawned_pass_limit:
        error = "This password is very common, please try with new password"
    return error

