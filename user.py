import random  # Do wygenerowania przypadkowego hasła
import string  # Do wykonywania na napisach
import hashlib  # Do wyliczenia hasha hasła
import binascii  # Do przekształcania wartości binarnych na kod ASCII

from databes_link import get_db


class UserPass:  # Obiek UserPass będzie wykorzystywany przy operacjach na użytkowniku i haśle
    def __init__(self, user='', password=''):
        self.user = user
        self.password = password
        self.email = ''
        self.is_valid = False
        self.is_admin = False

    def hash_password(self):  # Metoda do haszowania haseł
        """Hash a password for storing."""
        # the value generated using os.urandom(60)
        # Wyliczony hash hasła za pomocą algorytmu sha256
        os_urandom_static = b"ID_\x12p:\x8d\xe7&\xcb\xf0=H1\xc1\x16\xac\xe5BX\xd7\xd6j\xe3i\x11\xbe\xaa\x05\xccc\xc2\xe8K\xcf\xf1\xac\x9bFy(\xfbn.`\xe9\xcd\xdd'\xdf`~vm\xae\xf2\x93WD\x04"
        salt = hashlib.sha256(os_urandom_static).hexdigest().encode(
            'ascii')  # Algorytm do wyliczania
        pwdhash = hashlib.pbkdf2_hmac(
            'sha512', self.password.encode('utf-8'), salt, 100000)
        pwdhash = binascii.hexlify(pwdhash)
        # Zwrócona wartośc w postaci ascii
        return (salt + pwdhash).decode('ascii')

    # Funkjca sprawdzająca hasło
    # Metoda do weryfikacji hasła(stored_password - jest zahaszowanym hasłem łącznie z solą)
    def verify_password(self, stored_password, provided_password):
        """Verify a stored password against one provided by user"""
        salt = stored_password[:64]
        stored_password = stored_password[64:]
        pwdhash = hashlib.pbkdf2_hmac('sha512', provided_password.encode('utf-8'),
                                      salt.encode('ascii'), 100000)  # Wydobycie hasłą w postaci zahaszowanej
        pwdhash = binascii.hexlify(pwdhash).decode('ascii')  # Haszowanie hasła
        # hash hasła zahaszowanego porównane z hasłem przekazanym przez użytkownika
        return pwdhash == stored_password

    def get_random_user_password(self):  # Metoda tworząca losowego użtkownika
        random_user = ''.join(random.choice(
            string.ascii_lowercase)for i in range(3))  # Funkcja random.Choice wybiera spośród małych liter alfabetu wybraną liczbę tych liter.
        self.user = random_user  # Nazwa użytkownika

        password_characters = string.ascii_lowercase
        random_password = ''.join(random.choice(
            password_characters)for i in range(3))  # Ponownie funkcja random.Choice wybiera spośród małych liter alfabetu wybraną liczbę tych liter.
        self.password = random_password  # Hasło użytkownika
        return random_password

    def login_user(self):

        db = get_db()  # łączenie z bazą danych
        # Polecenie pobiera z bazy danych dane użytkownika o podanej nazwie
        sql_statement = 'select id, name, email, password, is_active, is_admin from users where name=?;'
        cur = db.execute(sql_statement, [self.user])  # Wykonujemy zapytanie.
        user_record = cur.fetchone()

        # Jeśli wszystko zostało wykonane w prawidłowy sposób user_record nie jest None i pobieramy zahaszowane hasło użytkownika (Weryfikujemy je za pomocą funkcji) sprawdzamy, czy hasło zapisane w user_record['password'] jest takie samo jak hasło odczytane z bazy danych.
        if user_record != None and self.verify_password(user_record['password'], self.password):
            # Jeśli oba powyższe testy wypadły pomyślnie, to użytkownik jest zalogowany i funkcja zwraca pełne informacje o zalogowanym użytkowniku.
            return user_record
        else:
            self.user = None
            self.password = None

            return None  # W przeciwnym razie zwracamy None

    # Definiuje funkjcę, która łączy się z bazą danych, by sprawdzić, czy użytkownik jest administratorem, czy jest aktywny i sprawdzi e-mail.
    def get_user_info(self):
        db = get_db()
        sql_statement = 'select name, email, is_active, is_admin from users where name=?'
        cur = db.execute(sql_statement, [self.user])
        db_user = cur.fetchone()

        if db_user == None:  # sprawdzam czy dany rekord występuje, jeśli nie :
            self.is_valid = False
            self.is_admin = False
            self.email = ''

        # sprawdzam czy konto jest kontem aktywnym, jeśli nie:
        elif db_user['is_active'] != 1:
            self.is_valid = False
            self.is_admin = False
            self.email = db_user['email']

        else:  # Jeśli konto jest aktywne:
            self.is_valid = True
            self.is_admin = db_user['is_admin']
            self.email = db_user['email']
