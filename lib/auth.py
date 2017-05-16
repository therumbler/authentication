import json
import random
import hashlib
import binascii
import os
import re
import platform
import time

from urllib import quote
from email_server import Email

from ConfigParser import ConfigParser

class Auth():
    '''
    my first attempt as a VERY UNSAFE username/password library
    saves user details in plain text JSON in /users/ directory

    Using recommendations from
    https://nakedsecurity.sophos.com/2016/08/18/nists-new-password-rules-what-you-need-to-know/
    https://nakedsecurity.sophos.com/2013/11/20/serious-security-how-to-store-your-users-passwords-safely/
    '''
    def __init__(self):
        #as at July 2016 20,000 iterations for the
        #PBKDF2 algorithm are recommended
        if 'lib' in os.getcwd():
            os.chdir('..')
        self.config = {}
        self.load_config()
        self.iterations = 20000
        
        #prevent DoS attacks by limiting maximum password length
        self.password_max_length = 128

    def load_config(self):
        config = ConfigParser()
        path = 'etc/config.conf'
        with open(path) as f:
            config.readfp(f)

        for section in ('email', 'server', 'app'):
            items = config.items(section)
            self.config[section] = {item[0]: item[1] for item in items}

    def get_filename(self, email):
        m = hashlib.md5()
        m.update(email)
        filename = 'etc/users/%s.json' % m.hexdigest()
        return filename

    def get_password_hash(self, password, iterations, salt_hex = None):
        if not salt_hex:
            #must be for a new hash
            #this is a pretty weak random number generator
            salt = os.urandom(32)
            salt_hex = binascii.b2a_hex(salt)
        else:
            salt = binascii.a2b_hex(salt_hex)

        dk = hashlib.pbkdf2_hmac('sha256', password, salt, iterations)
        password_hash = binascii.hexlify(dk)

        return {
            'password_hash' : password_hash,
            'salt_hex': salt_hex,
            'iterations': iterations
        }

    def mask_email(self, email):
        username = re.search(r'.*(?=\@)', email).group(0)
        server = re.search(r'(?=\@).*', email).group(0)
        masked = '*'
        if len(username) > 3:
            masked = username[0] + '*' * (len(username) -2) + username[-1]
        return masked + server

    def create_user(self, email, password1, password2):
        user = self.get_user(email)

        if user:
            #user already exists
            return {
                'success': False,
                'response_code': 401,
                'response_text': 'user already exists'
            }

        if password1 != password2:
            return {
                'success': False,
                'response_code': 400,
                'response_text': 'Passwords don\'t match'
            }
        password = password1
        if len(password) > self.password_max_length:
            return {
                'success': False,
                'response_code': 403,
                'response_text': 'Your password is %s characters too long. Passwords may not be longer than %s characters' % ((len(password) - self.password_max_length), self.password_max_length)
            }

        response = self.get_password_hash(password, self.iterations, False)

        random_value = os.urandom(32)
        verification_token = binascii.b2a_hex(random_value)
        user = {
            'email': email,
            'password': response['password_hash'],
            'salt': response['salt_hex'],
            'iterations': response['iterations'],
            'verified': False,
            'verification_token': verification_token
        }

        email_sent = self.send_verification_email(email, verification_token)
        if email_sent:
            self.save_user(user)
        else:
            return {
                'success': False,
                'response_code': 400,
                'response_text': 'email error'
            }

        return {
            'success': True,
            'response_code': 201,
            'response_text': 'Please verify this request. Check email at %s to verify account' % self.mask_email(user['email'])
        }

    def send_verification_email(self, email, verification_token):
        if self.config['server']['port'] in ["80", "443"]:
            url = '%s/verify?email=%s&token=%s' % (self.config['server']['hostname'], quote(email), verification_token)
        else:
            url = '%s:%s/verify?email=%s&token=%s' % (self.config['server']['hostname'], self.config['server']['port'], quote(email), verification_token)
        
        message_string = '''
        A request has been made to create an account.

        click the link to verify this request.

        %s
        ''' % (url)

        try:
            email_conn = Email(host = self.config['email']['host'], port = self.config['email']['port'], username = self.config['email']['username'], password = self.config['email']['password'])
            email_conn.send_email(message_string = message_string, from_email = self.config['email']['username'], recipients = [email,], subject = 'Account Creation')
            return True
        except Exception as e:
            return False

    def verify(self, email, verification_token):
        user = self.get_user(email)
        if not user:
            return {
                'success': False,
                'response_code': 401,
                'response_text': 'unknown user',
            }
        elif user['verification_token'] != verification_token or user['verified']:
            return {
                'success': False,
                'response_code': 401,
                'response_text': 'invalid token'
            }

        user['verified'] = True
        user['verification_token'] = ''
        self.save_user(user)

        return {
            'success': True,
            'response_code': 200,
            'response_text': 'Account verified'
        }

    def save_user(self, user):
        filename = self.get_filename(user['email'])

        with open(filename, 'w') as f:
            f.write(json.dumps(user, indent = 4))

    def login(self, email, password):
        user = self.get_user(email)
        if not user:
            print 'no user'
            return {
                'success': False,
                'response_code': 401,
                'response_text': 'unknown user',
            }

        if not user.get('verified'):
            print 'not verified'
            return {
                'success': False,
                'response_code': 401,
                'response_text': 'user not verified. Check email at %s' % self.mask_email(user['email'])
            }

        password_hash = self.get_password_hash(password, user['iterations'], user['salt'])

        if password_hash['password_hash'] == user['password']:
            return {
                'success': True,
                'response_code': 200,
                'response_text': 'success'
            }
        else:
            return {
                'success': False,
                'response_code': 401,
                'response_text': 'email or password incorrect'
            }

    def get_user(self, email):
        filename = self.get_filename(email)
        response = {}

        try:
            with open(filename) as f:
                response = json.load(f)
        except IOError, e:
            return None

        return response

    def get_creation_date(self, path_to_file):
        '''
        Try to get the date that a file was created, falling back to when it was
        last modified if that isn't possible.
        See http://stackoverflow.com/a/39501288/1709587 for explanation.
        '''
        if platform.system() == 'Windows':
            return os.path.getctime(path_to_file)
        else:
            stat = os.stat(path_to_file)
            try:
                return stat.st_birthtime
            except AttributeError:
                # We're probably on Linux. No easy way to get creation dates here,
                # so we'll settle for when its content was last modified.
                return stat.st_mtime

    def expire_tokens(self):
        '''
        run this method every hour to clear old un-verified users.
        this avoids verification tokens from being valid
        '''
        directory_name = 'etc/users'
        for dirpath, dirnames, filenames in os.walk(directory_name):
            #print dirpath, dirnames, filenames
            for filename in [f for f in filenames if not f.startswith('.')]:
                filepath = '%s/%s' % (directory_name, filename)

                with open(filepath) as f:
                    user = json.load(f)

                if user['verified']:
                    #User is already verified
                    # no need to do anything
                    continue

                creation_time = self.get_creation_date(filepath)

                one_hour = (60 * 60)
                if (time.time() - creation_time) > one_hour:
                    print 'removing %s' % filepath
                    os.remove(filepath)

def main():
    #Test code
    auth = Auth()
    auth.expire_tokens()
    return
    email = u'user@example.com'
    password = u'p@ssw0rd'
    response = auth.create_user(email, password1 = password, password2 = password)
    
    print response

if __name__ == '__main__':
    main()
