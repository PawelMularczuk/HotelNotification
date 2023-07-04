from flask import Flask, render_template, request, url_for, flash, g, redirect, session
from datetime import datetime
from datetime import date
from user import UserPass
from Notification_prority import NotificationPriority, PriorityType
from databes_link import get_db

# Obiekt g służy do przechowywania zmiennych globalnych na skalę pojedynczego requestu (Żądania przychodzącego od przeglądarki do serwera), Dzięki temu łączymy się z bazą dancych tylko raz bez konieczności łączenie się za każdym razem, kiedy wykonywany jest request.


app = Flask(__name__)

app.config['SECRET_KEY'] = 'xd'


@app.teardown_appcontext
def close_db(error):

    if hasattr(g, 'sqlite3_db'):  # Jeśli w zmiennej globalnej g znajduje się połączenie 'sqlite3_db'
        g.sqlite_db.close()  # zostaje wywołane polecenie


@app.route('/init_app')
def init_app():  # Funkjca która przy pierwszym podejsciu stworzy jednego administratora z domyślnym hasłem

    # Sprawdzamy czy taki użytkownik już istnieje
    db = get_db()  # łączenie z bazą danych
    # Sprawdzamy czy jest już zdediniowany jeden aktywny administrator
    sql_statement = 'select count(*) as cnt from users where is_active and is_admin;'
    cur = db.execute(sql_statement)  # uruchomienie polecenia
    # Wynik(liczba użytkowinków którzy sa administratorami i są aktywni)
    active_admins = cur.fetchone()

    # Jeśli tych użytkowników było więcej
    if active_admins != None and active_admins['cnt'] > 0:
        # Wyświelta się informacja o aktywnym adminisitratorze
        flash('Application is already set-up. Nothing to do')
        # Użytkownik jest przekierowany na stronę index
        return redirect(url_for('index'))

    # W innym przypadku tworzymy admina
    user_pass = UserPass()  # Tworze obiekt UserPass
    # Dla tego obietku wywołuję metodę dzięki której powstanie nowa nazwa uzytkownika i hasło
    user_pass.get_random_user_password()
    db.execute('''insert into users(name, email, password, is_active, is_admin)
    values(?,?,?,True,True);''', [user_pass.user, 'papcio@gmail.pl', user_pass.hash_password()])  # Wstawianie do tabeli użytkownika z podanymi parametrami
    db.commit()  # Wysyłamy do bazy danych
    flash('User {} with password {} has been created'.format(
        user_pass.user, user_pass.password))  # Wyświetlamy infomracje
    return redirect(url_for('index'))


# Funkcja jest zbindowana do endpointa login i obsługuje metodę GET i POST.
@app.route('/login', methods=['GET', 'POST'])
def login():

    # Użytkownik który jest "aktualny"(zalogowany) w sesji
    login = UserPass(session.get('user'))
    # Wywołuję metodę by sprawdzić, czy użytkownik jest administratorem, czy jest aktywny i sprawdzi e-mail.
    login.get_user_info()

    # Jesli pracujemy w metodzie GET, formularz został wywołany poraz pierwszy:
    if request.method == 'GET':
        return render_template('login.html', active_menu='login', login=login)

    else:  # Jesli funkcja pracuje w metodzie POST odbieramy dane
        # pobieram wartośći z formularza
        user_name = '' if 'user_name' not in request.form else request.form['user_name']
        user_pass = '' if 'user_pass' not in request.form else request.form['user_pass']

        # Tworze obiekt klasy UserPass wykorzystując user_name, user_pass
        login = UserPass(user_name, user_pass)
        # Wywołuję metodę by sprawdzić czy wszystkie dane są poprawne
        login_record = login.login_user()

        if login_record != None:  # Logowanie się powiodło
            # W zmiennej session w kluczu ['user'] zapamiętujemy user_name
            session['user'] = user_name
            flash('Logon succesful, wellcome {}'.format(
                user_name))  # Wyświetlamy komunikat
            return redirect(url_for('index'))

        else:  # Jeśli logowanie się nie powiodło
            flash('Logon failed, try again')  # Wyświetlamy komunikat
            # Przekierowujemy użytkownika na strone 'login.html'
            return render_template('login.html', active_menu='login', login=login)


@app.route('/logout')  # Funckja jest zbindowana do endpointa logout
def logout():

    if 'user' in session:  # Jeśli klucz 'user' jest w sesji
        # Z obiektem session pracujemy jak z słownikiem Więc użyjemy metody pop do usunięcia użytkownika z sesji.
        session.pop('user', None)
        flash('You are logged out')  # Wyświetlamy komunikat
    # Użytkownik jest przekierowany na strone login
    return redirect(url_for('login'))


@app.route('/')
def index():

    # Użytkownik który jest "aktualny"(zalogowany) w sesji
    login = UserPass(session.get('user'))
    # Wywołuję metodę by sprawdzić, czy użytkownik jest administratorem, czy jest aktywny i sprawdzi e-mail.
    login.get_user_info()

    return render_template('index.html', active_menu='home', login=login)


@app.route('/about')
def about():
    # Użytkownik który jest "aktualny"(zalogowany) w sesji
    login = UserPass(session.get('user'))
    # Wywołuję metodę by sprawdzić, czy użytkownik jest administratorem, czy jest aktywny i sprawdzi e-mail.
    login.get_user_info()

    return render_template('about.html', active_menu='about', login=login)


@app.route('/notification', methods=['GET', 'POST'])
def notification():

    # Użytkownik który jest "aktualny"(zalogowany) w sesji
    login = UserPass(session.get('user'))
    # Wywołuję metodę by sprawdzić, czy użytkownik jest administratorem, czy jest aktywny i sprawdzi e-mail.
    login.get_user_info()

    if not login.is_valid:  # Jeśli użytkownik nie jest zalogowany zostanie przekierowany na stronę logowania aby mogł korzystać z tej strony
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

        # Zapisuje informacje do bazy danych
        db = get_db()  # Obieky który wskazuje na połączenie z baza danych
        # Polecenie odpowiedzialne za wstawienie nowego rekordu
        sql_command = "insert into notifications(room_number, quest_name, notification_text, priority)values(?, ?, ?, ?);"
        db.execute(sql_command, [room_number,
                   guest_name, notification_text, priority])  # Przesyłanie polecenia
        db.commit()  # utrwalenie polecenia

        return render_template('notification_content.html', room_number=room_number, guest_name=guest_name, notification_text=notification_text, priority=priority, priority_type=priority_type, login=login)


@app.route('/history_notifications')
def history_notifications():

    # Użytkownik który jest "aktualny"(zalogowany) w sesji
    login = UserPass(session.get('user'))
    # Wywołuję metodę by sprawdzić, czy użytkownik jest administratorem, czy jest aktywny i sprawdzi e-mail.
    login.get_user_info()

    if not login.is_valid:  # Jeśli użytkownik nie jest zalogowany zostanie przekierowany na stronę logowania aby mogł korzystać z tej strony
        return redirect(url_for('login'))

    db = get_db()  # Obieky który wskazuje na połączenie z baza danych
    # Zapytanie do bazy danych które zwróci podane infomracje
    sql_command = 'select id, room_number, quest_name, notification_text, priority from notifications;'
    cur = db.execute(sql_command)  # Wykonujemy polecenie
    transactions = cur.fetchall()  # Pobiera wszystkie zwrócone rekordy

    return render_template('history_notification.html', transactions=transactions, active_menu='history_notifications', login=login)


# routa przyjmuje konkrety parametr do usuniecia
@app.route('/delete_notifiaction/<int:transaction_id>')
# Funkcja przyjmuje parametr(transaction_id)
def delete_notifiaction(transaction_id):

    # Użytkownik który jest "aktualny"(zalogowany) w sesji
    login = UserPass(session.get('user'))
    # Wywołuję metodę by sprawdzić, czy użytkownik jest administratorem, czy jest aktywny i sprawdzi e-mail.
    login.get_user_info()

    if not login.is_valid:  # Jeśli użytkownik nie jest zalogowany zostanie przekierowany na stronę logowania aby mogł korzystać z tej strony
        return redirect(url_for('login'))

    db = get_db()  # Obieky który wskazuje na połączenie z baza danych
    # Polecenie odpowiedzialne za usuniecie konkretnego rekordu(id)
    sql_statment = 'delete from notifications  where id = ?;'
    db.execute(sql_statment, [transaction_id])  # Wykonanie polecenia
    db.commit()  # Zapisuje zmiane do bazy danych
    flash('Notification has been delete')  # Informacja dla użytkownika

    # Przekierowanie użytkownika
    return redirect(url_for('history_notifications'))


@app.route('/edit_notifiaction/<int:transaction_id>', methods=['GET', 'POST'])
def edit_notifiaction(transaction_id):

    # Użytkownik który jest "aktualny"(zalogowany) w sesji
    login = UserPass(session.get('user'))
    # Wywołuję metodę by sprawdzić, czy użytkownik jest administratorem, czy jest aktywny i sprawdzi e-mail.
    login.get_user_info()

    if not login.is_valid:  # Jeśli użytkownik nie jest zalogowany zostanie przekierowany na stronę logowania aby mogł korzystać z tej strony
        return redirect(url_for('login'))

    db = get_db()  # Obieky który wskazuje na połączenie z baza danych
    # Tworzymy obiekt przechowujący listę Priority dla Notification
    notification_priorites = NotificationPriority()
    # Dla utworzonego obiektu stosujemy specjalną metodę
    notification_priorites.load_priorities()

    if request.method == 'GET':  # Jeśli korzystamy z metody POST wyciągniemy aktualne dane
        sql_statement = 'select id, room_number, quest_name, notification_text, priority from notifications where id=?;'
        # Przesyłanie polecenia
        cur = db.execute(sql_statement, [transaction_id])
        transaction = cur.fetchone()  # Pobieramy jeden konkretny rekord

        if transaction == None:  # Jeśli transaction jest równe None wyświetli się odpowiedni komunikat
            flash('no such notification!')
            return redirect('notifications')
        else:  # W innym przypadku zostanie wyświetlony odpowiedni formularz
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

        # Jeśli zgłoszenie zostanie przesłane po 20 automatycznie prority bedzie miało status High
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

    # Użytkownik który jest "aktualny"(zalogowany) w sesji
    login = UserPass(session.get('user'))
    # Wywołuję metodę by sprawdzić, czy użytkownik jest administratorem, czy jest aktywny i sprawdzi e-mail.
    login.get_user_info()

    if not login.is_valid or not login.is_admin:  # Jeśli użytkownik nie jest zalogowany, bądz nie jest administratorem zostanie przekierowany na stronę logowania aby mogł korzystać z tej strony
        return redirect(url_for('login'))

    db = get_db()  # Tworzę obiekt db i łączę się z bazą danych.
    # Wyciągamy z bazy danych wszystkie potrzebne informacje o uzytkownikach.
    sql_comand = 'select id, name, email, is_admin, is_active from users;'
    cur = db.execute(sql_comand)  # Wykonujemy zapytanie.
    users = cur.fetchall()  # pobieramy listę wszystkich użytkowników.

    return render_template('users.html', active_menu='users', users=users, login=login)


@app.route('/user_status_change/<action>/<user_name>')
def user_status_change(action, user_name):

    # Użytkownik który jest "aktualny"(zalogowany) w sesji
    login = UserPass(session.get('user'))
    # Wywołuję metodę by sprawdzić, czy użytkownik jest administratorem, czy jest aktywny i sprawdzi e-mail.
    login.get_user_info()

    if not login.is_valid or not login.is_admin:  # Jeśli użytkownik nie jest zalogowany, bądz nie jest administratorem zostanie przekierowany na stronę logowania aby mogł korzystać z tej strony
        return redirect(url_for('login'))

    db = get_db()  # Dostęp do bazy danych

    # Jeśli użytkownik jest aktywny zmieniamy go na nieaktywnego, jeśli jest nieaktywny zmieniamy go na aktywnego.
    if action == 'active':

        db.execute("""update users set is_active = (is_active + 1) % 2 where name = ? and name <> ?""",
                   [user_name, login.user])  # Jeśli is_active = 0 (False) teraz jest równe jeden (True) Jeśli is_active = 1 (True) dzielimy przez modulo 2 to teraz będzie równe 0 (False).
        db.commit()

    # Jeśli użytkownik jest adminem zmieniamy go na 0 (False), jeśli nie jset adminem zmienimy na 1 (True).
    elif action == 'admin':
        db.execute("""update users set is_admin = (is_admin + 1) % 2 where name = ? and  name <> ?""",
                   [user_name, login.user])  # Jeśli is_admine = 0 (False) teraz jest równe jeden (True) Jeśli is_admin = 1 (True) dzielimy przez modulo 2 to teraz będzie równe 0 (False).
        db.commit()

    return redirect(url_for('users'))


@app.route('/edit_user/<user_name>', methods=['GET', 'POST'])
def edit_user(user_name):

    # Użytkownik który jest "aktualny"(zalogowany) w sesji
    login = UserPass(session.get('user'))
    # Wywołuję metodę by sprawdzić, czy użytkownik jest administratorem, czy jest aktywny i sprawdzi e-mail.
    login.get_user_info()

    if not login.is_valid or not login.is_admin:  # Jeśli użytkownik nie jest zalogowany, bądz nie jest administratorem zostanie przekierowany na stronę logowania aby mogł korzystać z tej strony
        return redirect(url_for('login'))

    db = get_db()
    cur = db.execute(
        'select name, email from users where name = ?', [user_name])
    user = cur. fetchone()
    message = None

    if user == None:
        flash('No such user')
        return redirect(url_for('users'))

    if request.method == 'GET':
        return render_template('edit_user.html', active_menu='users', user=user, login=login)
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

    # Użytkownik który jest "aktualny"(zalogowany) w sesji
    login = UserPass(session.get('user'))
    # Wywołuję metodę by sprawdzić, czy użytkownik jest administratorem, czy jest aktywny i sprawdzi e-mail.
    login.get_user_info()

    if not login.is_valid or not login.is_admin:  # Jeśli użytkownik nie jest zalogowany, bądz nie jest administratorem zostanie przekierowany na stronę logowania aby mogł korzystać z tej strony
        return redirect(url_for('login'))

    db = get_db()  # Tworzę obiekt db i łączę się z bazą danych.
    # Usuń z tabeli użytkowników o podanej nazwie (user_name), ale użytkowników innych niż mój login (login.user) jest to zabezpieczenie, aby nie usunąć samego siebie.
    sql_statement = "delete from users where name = ? and name <> ?"
    db.execute(sql_statement, [user_name, login.user])  # Wykonujemy zapytanie.
    db.commit()

    return redirect(url_for('users'))


@app.route('/new_user', methods=['GET', 'POST'])
def new_user():

    # Użytkownik który jest "aktualny"(zalogowany) w sesji
    login = UserPass(session.get('user'))
    # Wywołuję metodę by sprawdzić, czy użytkownik jest administratorem, czy jest aktywny i sprawdzi e-mail.
    login.get_user_info()

    if not login.is_valid or not login.is_admin:  # Jeśli użytkownik nie jest zalogowany, bądz nie jest administratorem zostanie przekierowany na stronę logowania aby mogł korzystać z tej strony
        return redirect(url_for('login'))

    db = get_db()  # Tworzę obiekt db i łączę się z bazą danych.
    message = None  # Tworzę zmienną do przechowywania infomracji.
    user = {}  # Tworzę zmienną do przechowywania danych z fomrularza.

    # Jeśli jest to pierwsze odwołanie do tej funkcji przy pomocy 'GET' będę chiał wyświetlic poniższy formularz.
    if request.method == 'GET':
        return render_template('new_user.html', active_menu='users', user=user, login=login)

    else:
        # Do zmiennej user trafiają dane przekazane przez formularcz('user_name')
        user['user_name'] = '' if not 'user_name' in request.form else request.form['user_name']
        # Do zmiennej user trafiają dane przekazane w formularczu('email')
        user['email'] = '' if not 'email' in request.form else request.form['email']
        # Do zmiennej user trafiają dane przekazane w formularczu('user_pass')
        user['user_pass'] = '' if not 'user_pass' in request.form else request.form['user_pass']

    cursor = db.execute(
        'select count(*) as cnt from users where name = ?', [user['user_name']])  # Sprawdzam czy użytkownik podany w formularzu już nie istnieje
    record = cursor.fetchone()  # Wykonanie polecenia
    # Jeśli wartośc w tym rekordzie jest równa 0 to znaczy że wszystko jest okej
    is_user_name_unique = (record['cnt'] == 0)

    cursor = db.execute(
        'select count(*) as cnt from users where email = ?', [user['email']])  # Sprawdzam czy email podany w formularzu już nie istnieje
    record = cursor.fetchone()  # Wykonanie polecenia
    # Jeśli wartośc w tym rekordzie jest równa 0 to znaczy że wszystko jest okej
    is_user_email_unique = (record['cnt'] == 0)

    # Polecenia sprawdzające czy formularz został odpowienio wypełniony
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

    if not message:  # Jeśli wszystko zostało poprawnie wypisane:
        # tworzę obiekt user_pass i inijcuję go nazwą i hasłem użytkownika
        user_pass = UserPass(user['user_name'], user['user_pass'])
        password_hash = user_pass.hash_password()  # hashuję hasło
        sql_statement = '''insert into users(name, email, password, is_active, is_admin) values(?, ?, ?, True, False);'''  # Polecenie sql wstawiające do tabeli users nowego użytkownika
        db.execute(sql_statement, [user['user_name'],
                   user['email'], password_hash])  # Wykonanie polecenia
        db.commit()  # Zatwiedzenie zmian
        # Komunikat o stworzeniu użytkownika
        flash('User {} created'.format(user['user_name']))
        return redirect(url_for('users'))  # Powrót do strony users
    else:
        # Jeśli coś zostanie zrobione w niepoprawny sposób zostanie to wyświetlone.
        flash('Correct error {}'.format(message))
        # Odesłanie do formularza z wypełnionymi wartościami do poprawy
        return render_template('new_user.html', active_menu=users, user=user, login=login)


if __name__ == '__main__':
    app.run()
