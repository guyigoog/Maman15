import logging
import sys
import socket
from session import ServerSession
from db import Database
from consts import DEFAULT_PORT, HOST, PORT_FILE

logging.basicConfig(format='%(levelname)s: %(message)s', level=logging.NOTSET)


class Server:
    """Server class"""
    # Constants
    HOST = HOST
    DEFAULT_PORT = DEFAULT_PORT
    PORT_FILE = PORT_FILE

    def __init__(self):
        logging.info("Server is starting...")
        self.port = self.read_port_from_file()
        self.database = Database()
        self.create_socket()

    def read_port_from_file(self):
        """Reads PORT from the file PORT_FILE"""
        try:
            with open(self.PORT_FILE, 'r') as file:
                port = file.readline().strip()
                if port.isnumeric():
                    return int(port)
                else:
                    logging.warning(
                        f"Cannot read port from {self.PORT_FILE}, using default port instead: {self.DEFAULT_PORT}.")
        except Exception as error:
            logging.error(f"Error reading {self.PORT_FILE}: {error}.")
        return self.DEFAULT_PORT

    def create_socket(self):
        """Creates socket and waits for a client connection"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
                server.bind((self.HOST, self.port))
                server.listen()
                logging.info(f"Server listening on {self.HOST}:{self.port}.")
                while True:
                    client_socket, address = server.accept()
                    logging.info(f"New client connected from: {address}.")
                    ServerSession(client_socket, self.database).start()
        except Exception as error:
            self.terminate_server(error)

    @staticmethod
    def terminate_server(error):
        """Terminates the server in case of an error"""
        logging.error(error)
        logging.info("Shutting down server...")
        sys.exit(-1)
