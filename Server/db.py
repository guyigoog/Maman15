import logging
import sys
import sqlite3
from threading import Lock
from uuid import uuid4, UUID
from contextlib import contextmanager
from datetime import date
from protocol import Client, File
from consts import DB_FILENAME


class Database:

    def __init__(self):
        """
        Initialize the Database object.
        """
        self.clients = {}
        self.files = {}
        self.lock = Lock()
        self.init_db()

    @contextmanager
    def db_cursor(self):
        """
        Context manager for creating a database cursor.
        """
        with self.lock, sqlite3.connect(DB_FILENAME, check_same_thread=False) as conn:
            yield conn.cursor()

    def init_db(self):
        """
        Initialize the database, creating tables and loading data.
        """
        self.create_tables()
        self.fetch_data()

    def create_tables(self):
        """
        Create database tables if they do not exist.
        """
        try:
            with self.db_cursor() as cursor:
                cursor.executescript("""
                    CREATE TABLE IF NOT EXISTS clients (
                        ID BLOB NOT NULL PRIMARY KEY,
                        Name varchar(255) NOT NULL,
                        PublicKey BLOB,
                        LastSeen text,
                        AESKey BLOB
                    );
                    CREATE TABLE IF NOT EXISTS files (
                        ID BLOB NOT NULL PRIMARY KEY,
                        FileName varchar(255) NOT NULL,
                        PathName varchar(255) NOT NULL,
                        Verified text
                    );
                """)
        except Exception as e:
            self.terminate_server(f"Error creating tables: {e}")

    def fetch_data(self):
        """
        Fetch data from the database and load it into memory.
        """
        try:
            with self.db_cursor() as cursor:
                for client in cursor.execute("SELECT * FROM clients").fetchall():
                    client_id = UUID(bytes=client[0])
                    self.clients[client_id] = Client(client_id=client_id, name=client[1], public_key=client[2],
                                                     last_seen=client[3], aes_key=client[4])

                for file in cursor.execute("SELECT * FROM files").fetchall():
                    client_id = UUID(bytes=file[0])
                    file_obj = File(client_id=client_id, file_name=file[1], path=file[2], verified=file[3])
                    self.files.setdefault(client_id, []).insert(0, file_obj)
        except Exception as e:
            self.terminate_server(f"Error fetching data: {e}")

    def register_new_client(self, name) -> UUID:
        """
        Register a new client and return their UUID.
        """
        client_id = uuid4()
        with self.db_cursor() as cursor:
            cursor.execute("INSERT INTO clients (ID, Name, LastSeen) VALUES (?, ?, ?)",
                           [client_id.bytes, name, str(date.today())])
            self.clients[client_id] = Client(client_id, name, None, str(date.today()), None)
        return client_id

    def get_client_by_id(self, client_id: UUID) -> Client:
        """
        Get a client by their UUID.
        """
        with self.lock:
            return self.clients.get(client_id)

    def is_name_taken(self, name: str) -> bool:
        """
        Check if a client name is already taken.
        """
        with self.lock:
            return any(client.name == name for client in self.clients.values())

    def update_client_keys(self, client_id, public_key, aes_key):
        """
        Update client's public key and AES key in the database.
        """
        with self.db_cursor() as cursor:
            cursor.execute(
                "INSERT OR REPLACE INTO clients (ID, Name, PublicKey, LastSeen, AESKey) VALUES (?, ?, ?, ?, ?)",
                [client_id.bytes, "Unknown name", public_key, str(date.today()), aes_key])
            self.clients.setdefault(client_id,
                                    Client(client_id, "Unknown name", public_key, str(date.today()), aes_key))
            self.clients[client_id].aes_key = aes_key
            self.clients[client_id].public_key = public_key

    def add_file(self, client_id: UUID, file_name, path):
        """
        Add a file to a client's files list in the database.
        """
        with self.db_cursor() as cursor:
            cursor.execute("INSERT OR REPLACE INTO files (ID, FileName, PathName, Verified) VALUES (?, ?, ?, ?)",
                           [client_id.bytes, file_name, path, "False"])
            self.files.setdefault(client_id, []).insert(0, File(client_id, file_name, path, False))

    def delete_file(self, client_id: UUID, file_name):
        """
        Delete a file from a client's files list in the database.
        """
        with self.db_cursor() as cursor:
            cursor.execute("DELETE from files WHERE ID=? AND FileName=?", [client_id.bytes, file_name])
            self.files[client_id] = [file for file in self.files.get(client_id, []) if file.file_name != file_name]

    def set_file_verified(self, client_id: UUID, file_name):
        """
        Set a file as verified in the database.
        """
        with self.db_cursor() as cursor:
            cursor.execute("UPDATE files SET Verified='TRUE' WHERE ID=? AND FileName=?", [client_id.bytes, file_name])
            for file in self.files.get(client_id, []):
                if file.file_name == file_name:
                    file.verified = True

    def get_file_path(self, client_id, file_name) -> str:
        """
        Get the path of a file from a client's files list in the database.
        """
        return next((file.path for file in self.files.get(client_id, []) if file.file_name == file_name), '')

    def set_last_seen(self, client_id):
        """
        Update a client's last seen date in the database.
        """
        with self.db_cursor() as cursor:
            cursor.execute("UPDATE clients SET LastSeen=? WHERE ID=?", [str(date.today()), client_id.bytes])
            self.clients[client_id].last_seen = str(date.today())

    @staticmethod
    def terminate_server(error):
        """Terminates the server in case of an error"""
        logging.error(error)
        logging.info("Shutting down server...")
        sys.exit(-1)
