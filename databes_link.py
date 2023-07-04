
from flask import g
import sqlite3

DATABASE = {
    'db_file': 'C:/Users/pawel/OneDrive/Pulpit/Python - Flask/Hotel/data/notifications.db'}  # zmienna z scieżką do bazy dancyh

def get_db():  # Odpowedzialna za zwrócenie aktualnego połączenia do bazą danych

    if not hasattr(g, 'sqlite_db'):  # Jeśli w obiekcie g znajduje sie właściwośc jak 'sqlite_db'
        # Jeśli nie nawiązujemy połączenie
        conn = sqlite3.connect(DATABASE['db_file'])
        # Dane będą zwracane w postaci słowników(Normalnie zwracane, by były tuplety)
        conn.row_factory = sqlite3.Row
        g.sqlite_db = conn  # połącznenie zapisujemy w zmiennej globalnej g
    return g.sqlite_db

# Kiedy kończy się request flask zamknie połącznie


