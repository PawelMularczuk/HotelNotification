from flask import Flask, render_template, request, url_for, flash, g, redirect, session
from datetime import datetime
import sqlite3
from datetime import date

import random
import string
import hashlib
import binascii

DATABASE = {
    'db_file': 'C:/Users/pawel/OneDrive/Pulpit/Python - Flask/Hotel/data/notifications.db'}

app = Flask(__name__)

app.config['SECRET_KEY'] = 'xd'


def get_db():

    if not hasattr(g, 'sqlite_db'):
        conn = sqlite3.connect(DATABASE['db_file'])
        conn.row_factory = sqlite3.Row
        g.sqlite_db = conn
    return g.sqlite_db


@app.teardown_appcontext
def close_db(error):
    if hasattr(g, 'sqlite3_db'):
        g.sqlite_db.close()


class PriorityType:
    def __init__(self, code, description, selected):
        self.code = code
        self.description = description
        self.selected = selected


class NotificationPriority:
    def __init__(self):
        self.list_of_priorites = []

    def load_priorities(self):
        self.list_of_priorites.append(
            PriorityType('High', 'HIGH PRIORITY', False))
        self.list_of_priorites.append(
            PriorityType('Medium', 'MEDIUM PRIORITY', False))
        self.list_of_priorites.append(
            PriorityType('Normal', 'NOT URGENT', True))
        self.list_of_priorites.append(PriorityType('Low', 'REMARK', False))

    def get_priority_by_code(self, code):
        for priority in self.list_of_priorites:
            if priority.code == code:
                return priority
        return PriorityType('Normal', 'NOT URGENT', True)


class UserPass:
    def __init__(self, user='', password=''):
        self.user = user
        self.password = password
        self.email = ''
        self.is_valid = False
        self.is_admin = False

    def hash_password(self):
        """Hash a password for storing."""
        # the value generated using os.urandom(60)
        os_urandom_static = b"ID_\x12p:\x8d\xe7&\xcb\xf0=H1\xc1\x16\xac\xe5BX\xd7\xd6j\xe3i\x11\xbe\xaa\x05\xccc\xc2\xe8K\xcf\xf1\xac\x9bFy(\xfbn.`\xe9\xcd\xdd'\xdf`~vm\xae\xf2\x93WD\x04"
        salt = hashlib.sha256(os_urandom_static).hexdigest().encode('ascii')
        pwdhash = hashlib.pbkdf2_hmac(
            'sha512', self.password.encode('utf-8'), salt, 100000)
        pwdhash = binascii.hexlify(pwdhash)
        return (salt + pwdhash).decode('ascii')

    def verify_password(self, stored_password, provided_password):
        """Verify a stored password against one provided by user"""
        salt = stored_password[:64]
        stored_password = stored_password[64:]
        pwdhash = hashlib.pbkdf2_hmac('sha512', provided_password.encode('utf-8'),
                                      salt.encode('ascii'), 100000)
        pwdhash = binascii.hexlify(pwdhash).decode('ascii')
        return pwdhash == stored_password

    def get_random_user_password(self):
        random_user = ''.join(random.choice(
            string.ascii_lowercase)for i in range(3))
        self.user = random_user

        password_characters = string.ascii_lowercase
        random_password = ''.join(random.choice(
            password_characters)for i in range(3))
        self.password = random_password
        return random_password

    def login_user(self):
        db = get_db()
        sql_statement = 'select id, name, email, password, is_active, is_admin from users where name=?;'
        cur = db.execute(sql_statement, [self.user])
        user_record = cur.fetchone()

        if user_record != None and self.verify_password(user_record['password'], self.password):
            return user_record
        else:
            self.user = None
            self.password = None

            return None

    def get_user_info(self):
        db = get_db()
        sql_statement = 'select name, email, is_active, is_admin from users where name=?'
        cur = db.execute(sql_statement, [self.user])
        db_user = cur.fetchone()

        if db_user == None:
            self.is_valid = False
            self.is_admin = False
            self.email = ''

        elif db_user['is_active']!=1:
            self.is_valid = False
            self.is_admin = False
            self.email = db_user['email']    

        else:
            self.is_valid = True
            self.is_admin = db_user['is_admin']
            self.email = db_user['email']

@app.route('/init_app')
def init_app():

    db = get_db()
    sql_statement = 'select count(*) as cnt from users where is_active and is_admin;'
    cur = db.execute(sql_statement)
    active_admins = cur.fetchone()

    if active_admins != None and active_admins['cnt'] > 0:
        flash('Application is already set-up. Nothing to do')
        return redirect(url_for('index'))

    user_pass = UserPass()
    user_pass.get_random_user_password()
    db.execute('''insert into users(name, email, password, is_active, is_admin)
    values(?,?,?,True,True);''', [user_pass.user, 'papcio@gmail.pl', user_pass.hash_password()])
    db.commit()
    flash('User {} with password {} has been created'.format(
        user_pass.user, user_pass.password))
    return redirect(url_for('index'))


@app.route('/login', methods=['GET', 'POST'])
def login():

    login = UserPass(session.get('user'))
    login.get_user_info()

    if request.method == 'GET':
        return render_template('login.html', active_menu='login', login=login)

    else:
        user_name = '' if 'user_name' not in request.form else request.form['user_name']
        user_pass = '' if 'user_pass' not in request.form else request.form['user_pass']

        login = UserPass(user_name, user_pass)
        login_record = login.login_user()

        if login_record != None:
            session['user'] = user_name
            flash('Logon succesful, wellcome {}'.format(user_name))
            return redirect(url_for('index'))

        else:
            flash('Logon failed, try again')
            return render_template('login.html', active_menu='login', login=login)


@app.route('/logout')
def logout():

    if 'user' in session:
        session.pop('user', None)
        flash('You are logged out')
    return redirect(url_for('login'))


@app.route('/')
def index():

    login = UserPass(session.get('user'))
    login.get_user_info()

    return render_template('index.html', active_menu='home', login=login)


@app.route('/about')
def about():
    login = UserPass(session.get('user'))
    login.get_user_info()

    return render_template('about.html', active_menu='about', login=login)


@app.route('/notification', methods=['GET', 'POST'])
def notification():

    login = UserPass(session.get('user'))
    login.get_user_info()
    if not login.is_valid:
        return redirect(url_for('login'))

    notification_priorites = NotificationPriority()
    notification_priorites.load_priorities()

    if request.method == 'GET':
        return render_template('notification.html', notification_priorites=notification_priorites, active_menu='notification', login=login)
    else:
        room_number = request.form['room_number']

        if 'room_number' in request.form:
            room_number = request.form['room_number']

        guest_name = request.form['guest_name']

        if 'guest_name' in request.form:
            guest_name = request.form['guest_name']

        notification_text = request.form['notification_text']

        if 'notification_text' in request.form:
            notification_text = request.form['notification_text']

        priority = request.form['priority']

        if 'priority' in request.form:
            priority = request.form['priority']
        else:
            'normal'

        priority_type = notification_priorites.get_priority_by_code(priority)
        flash('Notification has been send')

        the_hour = datetime.now().hour
        rise_prority = (the_hour >= 16 or the_hour <=
                        6) and priority == 'Medium'

        if rise_prority:
            priority = 'High'
            flash('Rising priority from medium to high')

        db = get_db()
        sql_command = "insert into notifications(room_number, quest_name, notification_text, priority)values(?, ?, ?, ?);"
        db.execute(sql_command, [room_number,
                   guest_name, notification_text, priority])
        db.commit()

        return render_template('notification_content.html', room_number=room_number, guest_name=guest_name, notification_text=notification_text, priority=priority, priority_type=priority_type, login=login)


@app.route('/history_notifications')
def history_notifications():

    login = UserPass(session.get('user'))
    login.get_user_info()
    if not login.is_valid:
        return redirect(url_for('login'))

    db = get_db()
    sql_command = 'select id, room_number, quest_name, notification_text, priority from notifications;'
    cur = db.execute(sql_command)
    transactions = cur.fetchall()

    return render_template('history_notification.html', transactions=transactions, active_menu='history_notifications', login=login)


@app.route('/delete_notifiaction/<int:transaction_id>')
def delete_notifiaction(transaction_id):

    login = UserPass(session.get('user'))
    login.get_user_info()
    if not login.is_valid:
        return redirect(url_for('login'))

    db = get_db()
    sql_statment = 'delete from notifications  where id = ?;'
    db.execute(sql_statment, [transaction_id])
    db.commit()
    flash('Notification has been delete')

    return redirect(url_for('history_notifications'))


@app.route('/edit_notifiaction/<int:transaction_id>', methods=['GET', 'POST'])
def edit_notifiaction(transaction_id):

    login = UserPass(session.get('user'))
    login.get_user_info()
    if not login.is_valid:
        return redirect(url_for('login'))

    db = get_db()
    notification_priorites = NotificationPriority()
    notification_priorites.load_priorities()

    if request.method == 'GET':
        sql_statement = 'select id, room_number, quest_name, notification_text, priority from notifications where id=?;'
        cur = db.execute(sql_statement, [transaction_id])
        transaction = cur.fetchone()

        if transaction == None:
            flash('no such notification!')
            return redirect('notifications')
        else:
            return render_template('edit_notification.html', active_menu='notifications', transaction=transaction, list_of_priorites=notification_priorites.list_of_priorites, login=login)
    else:
        room_number = request.form['room_number']

        if 'room_number' in request.form:
            room_number = request.form['room_number']

        guest_name = request.form['guest_name']

        if 'guest_name' in request.form:
            guest_name = request.form['guest_name']

        notification_text = request.form['notification_text']

        if 'notification_text' in request.form:
            notification_text = request.form['notification_text']

        priority = request.form['priority']

        if 'priority' in request.form:
            priority = request.form['priority']
        else:
            'normal'

        priority_type = notification_priorites.get_priority_by_code(priority)

        the_hour = datetime.now().hour
        rise_prority = (the_hour >= 20 or the_hour <=
                        6) and priority == 'Medium'

        if rise_prority:
            priority = 'High'
            flash('Rising priority from medium to high')

        sql_command = '''update notifications set room_number=?, quest_name=?, notification_text=?, priority=? where id=?;'''
        db.execute(sql_command, [room_number, guest_name,
                   notification_text, priority, transaction_id])
        db.commit()
        flash('Notification has been updated')
        return redirect(url_for('history_notifications'))


@app.route('/users')
def users():

    login = UserPass(session.get('user'))
    login.get_user_info()
    if not login.is_valid or not login.is_admin:
        return redirect(url_for('login'))

    db = get_db()
    sql_comand = 'select id, name, email, is_admin, is_active from users;'
    cur = db.execute(sql_comand)
    users = cur.fetchall()

    return render_template('users.html', active_menu='users', users=users, login=login)


@app.route('/user_status_change/<action>/<user_name>')
def user_status_change(action, user_name):

    login = UserPass(session.get('user'))
    login.get_user_info()
    if not login.is_valid or not login.is_admin:
        return redirect(url_for('login'))

    db = get_db()

    if action == 'active':
        db.execute("""update users set is_active = (is_active + 1) % 2 where name = ? and name <> ?""", [user_name, login.user])
        db.commit()

    elif action == 'admin':
        db.execute("""update users set is_admin = (is_admin + 1) % 2 where name = ? and  name <> ?""", [user_name, login.user])
        db.commit()    

    return redirect(url_for('users'))

@app.route('/edit_user/<user_name>', methods=['GET', 'POST'])
def edit_user(user_name):

    login = UserPass(session.get('user'))
    login.get_user_info()
    if not login.is_valid or not login.is_admin:
        return redirect(url_for('login'))
    
    db = get_db()
    cur = db.execute('select name, email from users where name = ?', [user_name])
    user = cur. fetchone()
    message = None

    if user == None:
        flash('No such user')
        return redirect(url_for('users'))
    
    if request.method == 'GET':
        return render_template('edit_user.html', active_menu = 'users', user = user, login=login)
    else:
        new_name = '' if 'user_name' not in request.form else request.form['user_name']
        new_email = '' if 'email' not in request.form else request.form['email']
        new_password = '' if 'user_pass' not in request.form else request.form['user_pass']

    if new_name != user['name']:
        sql_statement = 'update users set name = ? where name = ?'
        db.execute(sql_statement, [new_name, user_name])
        db.commit()
        flash('Name was changed')

    if new_email != user['email']:
        sql_statement = 'update users set email = ? where name =?'
        db.execute(sql_statement, [new_email, user_name])
        db.commit()
        flash('Email was changed')

    if new_password != '':
        user_pass = UserPass(user_name, new_password)
        sql_statement = 'update users set password = ? where name = ?'
        db.execute(sql_statement, [user_pass.hash_password(), user_name])
        db.commit()
        flash('Password was changed')

    return redirect(url_for('users'))  

@app.route('/delete_user/<user_name>')
def delete_user(user_name):
     
     login = UserPass(session.get('user'))
     login.get_user_info()
     if not login.is_valid or not login.is_admin:
         return redirect(url_for('login'))
     
     db = get_db()
     sql_statement = "delete from users where name = ? and name <> ?"
     db.execute(sql_statement, [user_name, login.user])
     db.commit()

     return redirect(url_for('users'))


@app.route('/new_user', methods=['GET', 'POST'])
def new_user():

    login = UserPass(session.get('user'))
    login.get_user_info()
    if not login.is_valid or not login.is_admin:
        return redirect(url_for('login'))

    db = get_db()
    message = None
    user = {}

    if request.method == 'GET':
        return render_template('new_user.html', active_menu='users', user=user, login=login)

    else:
        user['user_name'] = '' if not 'user_name' in request.form else request.form['user_name']
        user['email'] = '' if not 'email' in request.form else request.form['email']
        user['user_pass'] = '' if not 'user_pass' in request.form else request.form['user_pass']

    cursor = db.execute(
        'select count(*) as cnt from users where name = ?', [user['user_name']])
    record = cursor.fetchone()
    is_user_name_unique = (record['cnt'] == 0)

    cursor = db.execute(
        'select count(*) as cnt from users where email = ?', [user['email']])
    record = cursor.fetchone()
    is_user_email_unique = (record['cnt'] == 0)

    if user['user_name'] == '':
        message = 'Name cannot be empty'
    elif user['email'] == '':
        message = 'Email cannot be empty'
    elif user['user_pass'] == '':
        message = 'Password cannot be empty'
    elif not is_user_name_unique:
        message = 'User with the name {} already exists'.format(
            user['user_name'])
    elif not is_user_email_unique:
        message = 'User with the email {} already exists'.format(user['email'])

    if not message:
        user_pass = UserPass(user['user_name'], user['user_pass'])
        password_hash = user_pass.hash_password()
        sql_statement = '''insert into users(name, email, password, is_active, is_admin) values(?, ?, ?, True, False);'''
        db.execute(sql_statement, [user['user_name'],
                   user['email'], password_hash])
        db.commit()
        flash('User {} created'.format(user['user_name']))
        return redirect(url_for('users'))
    else:
        flash('Correct error {}'.format(message))
        return render_template('new_user.html', active_menu=users, user=user, login=login)


if __name__ == '__main__':
    app.run()
