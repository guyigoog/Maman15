"""
This file contains all the constants used in the project.
"""

# -----------------Size Consts----------------------
REQUEST_HEADER_SIZE = 23  # 1 + 4 + 16 + 2
NAME_MAX_LENGTH = 255
AES_KEY_SIZE = 16
PUBLIC_KEY_SIZE = 160
CONTENT_SIZE = 4
FILE_NAME_LENGTH = 255
ID_SIZE = 16
CODE_SIZE = 2
PAYLOAD_SIZE = 4
UUID_SIZE = 16
EMPTY = 0

# -----------------Server Consts----------------------
SERVER_VERSION = 3
DEFAULT_PORT = 1357
HOST = '127.0.0.1'
PORT_FILE = 'port.info'

# -----------------Database Consts----------------------
DB_FILENAME = 'defensive.db'

# -----------------Error Consts----------------------
ERROR = -1  # Error code
