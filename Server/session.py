import logging
import os
import struct
import sys
import threading
from collections import namedtuple
from threading import Thread

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import unpad

from cksum import CRC32
from consts import UUID_SIZE, REQUEST_HEADER_SIZE, AES_KEY_SIZE, PUBLIC_KEY_SIZE, \
    NAME_MAX_LENGTH, CONTENT_SIZE, FILE_NAME_LENGTH, ERROR
from protocol import RequestHeader, RequestPayloadCodes, RegisterRequest, ClientPublicKey, \
    ReconnectRequest, \
    ReceiveFile, ChecksumRequest, Client, ResponseHeader, ResponseRegistrationSuccess, \
    ResponseRegistrationFailed, ResponseSendAES, ResponseValidCRC, ResponseConfirmMessage, ResponseConfirmReconnect, \
    ResponseDenyReconnect, ResponseServerFailed

logging.basicConfig(format='%(levelname)s: %(message)s', level=logging.NOTSET)


class ServerSession(Thread):
    def __init__(self, client_socket, database):
        super().__init__(name='client_socket', daemon=True)
        self.client_socket = client_socket
        self.database = database
        logging.info("Current server thread id: %s", threading.current_thread().ident)

    def run(self):
        try:
            while True:
                self.handle_request()
        except Exception as e:
            self.close_connection(f"Request failed: {e}", ERROR)

    # --------------------------------- Request --------------------------

    def handle_request(self):
        try:
            header = self.receive_header()
            unpacked_header = struct.unpack(f'<{UUID_SIZE}sBHI', header)
            header = RequestHeader(*unpacked_header)
            self.process_request(header)
        except Exception as e:
            self.close_connection(f"Request failed: {e}", ERROR)

    @staticmethod
    def parse_header(header) -> tuple:
        """ Unpacks the header according to sizes specified in consts.py.
            :param: request header from client
            :return: a tuple of the unpacked header
        """
        return struct.unpack(f'<{UUID_SIZE}sBHI', header)

    def receive_header(self):
        """ Receives the header of the request from the client.
            :return: bytes of the header received
        """
        header = self.client_socket.recv(REQUEST_HEADER_SIZE)
        if not header or len(header) != REQUEST_HEADER_SIZE:
            raise ValueError("Invalid header")
        return header

    def process_request(self, header):
        """ Processes the request according to the code in the header.
            :param: the unpacked header of the request.
        """
        try:
            handler = {
                RequestPayloadCodes.Register.value: self.register,
                RequestPayloadCodes.ClientSendPublicKey.value: self.send_public_key,
                RequestPayloadCodes.Reconnect.value: self.reconnect,
                RequestPayloadCodes.SendFile.value: self.receive_file,
                RequestPayloadCodes.ValidCRC.value: self.handle_valid_crc_request,
                RequestPayloadCodes.InvalidCRCRetry.value: self.invalid_crc_retry,
                RequestPayloadCodes.InvalidCRCAbort.value: self.handle_invalid_crc_abort
            }.get(header.code, self.invalid_request)
            handler(header)
        except Exception as e:
            self.close_connection(e, ERROR)

    def invalid_request(self, header):
        """ Handles invalid requests.
            receive: the unpacked header of the request.
            :raise: Exception with error message
        """
        raise Exception("Invalid request code")

    @staticmethod
    def parse_payload(payload, **kwargs) -> tuple:
        """ Unpacks the payload according to sizes specified in kwargs.
            :param: payload from client
            :param: kwargs - a dictionary of the sizes of the payload
            :return: a tuple of the unpacked payload
        """
        if len(payload) != sum(kwargs.values()):
            raise ValueError("Invalid payload size")
        splitter = ''.join(f'{size}s' for size in kwargs.values())
        return struct.unpack(splitter, payload)

    def register(self, header: RequestHeader) -> None:
        """
        Handle registration request.
        :param header: header of the request
        :raise: ValueError, Exception
        """
        try:
            request = self.registration_request(header)
            if self.database.is_name_taken(request.name):
                raise ValueError(f"Error: The name '{request.name}' is already taken")

            client_id = self.database.register_new_client(request.name)
            self.send_response(ResponseRegistrationSuccess(client_id))
        except ValueError as e:
            logging.error(e)
            self.send_response(ResponseRegistrationFailed())
            self.close_connection(e, ERROR)
        except Exception as e:
            logging.error(f"Registration failed: {e}")
            self.send_response(ResponseRegistrationFailed())
            self.close_connection(e, ERROR)

    def registration_request(self, header: RequestHeader) -> RegisterRequest:
        """
        Parses the payload of the registration request.
        :param header:
        :return:
        """
        try:
            payload = self.receive_payload(header.payload_size)
            Payload = namedtuple('Payload', ['client_name'])
            unpacked_payload = Payload._make(self.parse_payload(
                payload, clientname_size=NAME_MAX_LENGTH))
            return RegisterRequest(unpacked_payload.client_name)
        except Exception as error:
            logging.error(error)
            self.send_response(ResponseRegistrationFailed())

    def receive_payload(self, expected_size: int) -> bytes:
        """
        Receives an exact-sized payload from the client socket.

        :param expected_size: Expected size of the payload
        :return: Payload as a bytes object
        :raises ValueError: If the received payload size doesn't match the expected size
        """
        payload = self.client_socket.recv(expected_size)
        if len(payload) != expected_size:
            raise ValueError("Invalid payload size received")
        return payload

    def send_public_key(self, header: RequestHeader) -> None:
        """
        Handle public key exchange request.
        :param header: header of the request
        """
        try:
            request = self.unpack_client_public_key(header)
            logging.info(f"Client {request.name} sent public key")

            aes_key = os.urandom(AES_KEY_SIZE)
            encrypted_key = PKCS1_OAEP.new(RSA.importKey(request.public_key)).encrypt(aes_key)

            self.database.update_client_keys(header.client_id, request.public_key, aes_key)

            self.send_response(ResponseSendAES(header.client_id, encrypted_key))
        except Exception as error:
            logging.error(error)
            self.send_response(ResponseServerFailed())

    def unpack_client_public_key(self, header: RequestHeader) -> ClientPublicKey:
        """
        Unpacks the client's public key request from the received payload.
        :param header: The header of the request.
        :return: ClientPublicKey object.
        """
        try:
            payload = self.receive_payload(header.payload_size)
            Payload = namedtuple('Payload', ['client_name', 'public_key'])
            unpacked_payload = Payload._make(self.parse_payload(
                payload, clientname_size=NAME_MAX_LENGTH, public_key_size=PUBLIC_KEY_SIZE))
            return ClientPublicKey(unpacked_payload.client_name, unpacked_payload.public_key)
        except Exception as error:
            logging.error(error)
            self.send_response(ResponseServerFailed())

    def reconnect(self, header: RequestHeader) -> None:
        """
        Handles a client's reconnect request.
        :param header: The header of the request.
        """
        try:
            request = self.unpack_reconnect_request(header)
            if not self.database.is_name_taken(request.name):
                raise ValueError(f"Reconnect failed, client {request.name} is not exist")

            client = self.database.get_client_by_id(header.client_id)
            aes_key = client.aes_key

            if aes_key is None:
                raise ValueError(f"Reconnect failed, client {request.name} has not sent AES key")

            encrypted_aes = PKCS1_OAEP.new(RSA.importKey(client.public_key)).encrypt(aes_key)

            self.database.set_last_seen(client.client_id)
            response = ResponseConfirmReconnect(client.client_id, encrypted_aes)
            self.send_response(response)

        except Exception as error:
            logging.error(error)
            response = ResponseDenyReconnect(header.client_id)
            self.send_response(response)

    def unpack_reconnect_request(self, header: RequestHeader) -> ReconnectRequest:
        """
        Unpacks the client's reconnect request from the received payload.

        :param header: The header of the request.
        :return: ReconnectRequest object.
        """
        payload = self.receive_payload(header.payload_size)
        Payload = namedtuple('Payload', ['client_name'])
        unpacked_payload = Payload._make(self.parse_payload(
            payload, clientname_size=NAME_MAX_LENGTH))
        return ReconnectRequest(unpacked_payload.client_name)

    def receive_file(self, header: RequestHeader) -> None:
        """
        Handles a client's request to receive a file.
        :param header: The header of the request.
        """
        try:
            request = self.receive_file_request(header)
            client_id = header.client_id
            client = self.database.get_client_by_id(client_id)
            file_name = request.file_name

            if client.aes_key is None:
                raise ValueError(f"Client {client.name} has not sent AES key")

            tmp_path = os.path.join('backup', client.name.strip())
            os.makedirs(tmp_path, exist_ok=True)
            path = os.path.join(tmp_path, file_name)

            self.decrypt_and_save_to_file(path, request.message_content, client.aes_key)

            self.database.add_file(client.client_id, file_name, path)
            crc = CRC32.file_crc_calc(path)
            logging.info(f"File {file_name} received successfully, CRC: 0x{crc:02x}")

            response = ResponseValidCRC(client.client_id, request.content_size, file_name, crc)
            self.send_response(response)

        except Exception as error:
            logging.error(f"Failed to receive file: {error}")
            self.send_response(ResponseServerFailed())

    @staticmethod
    def decrypt_and_save_to_file(file_path, encrypted_content, decryption_key):
        """
        Decrypts the encrypted content and saves it to a local file.

        :param file_path: Path to the local file where decrypted content will be saved.
        :param encrypted_content: Encrypted content to be decrypted.
        :param decryption_key: AES decryption key.
        """
        try:
            iv = b'\0' * AES.block_size
            cipher = AES.new(key=decryption_key, mode=AES.MODE_CBC, iv=iv)

            decrypted_content = unpad(cipher.decrypt(encrypted_content), AES.block_size)

            with open(file_path, 'wb') as file:
                file.write(decrypted_content)
        except Exception as e:
            raise ValueError(f"Failed to decrypt and save to file: {str(e)}")

    def receive_file_request(self, header: RequestHeader) -> ReceiveFile:
        """
        Receives payload and builds a ReceiveFile object.
        :param header: The header of the request.
        :return: ReceiveFile object.
        :raises Exception: If an error occurs during payload reception or processing.
        """
        try:
            payload_size = CONTENT_SIZE + FILE_NAME_LENGTH
            payload = self.receive_payload(payload_size)
            Payload = namedtuple('Payload', ['content_size', 'file_name'])
            unpacked_payload = Payload._make(self.parse_payload(
                payload, content_size=CONTENT_SIZE, file_name=FILE_NAME_LENGTH))

            message_size = header.payload_size - payload_size
            message_content = self.receive_payload(message_size)
            MessageContent = namedtuple('MessageContent', ['content'])
            content = MessageContent._make(self.parse_payload(
                message_content, message_size=message_size))

            return ReceiveFile(message_size, unpacked_payload.file_name, content.content)
        except Exception as error:
            raise error

    def unpack_checksum_payload(self, header: RequestHeader) -> ChecksumRequest:
        """
            Unpacks the payload of a checksum request and returns a ChecksumRequest object.
            :param header: The header of the request.
            :return: ChecksumRequest object.
            :raises Exception: If an error occurs during payload reception or processing.
            """
        try:
            payload = self.receive_payload(header.payload_size)
            Payload = namedtuple('Payload', ['file_name'])
            unpacked_payload = Payload._make(self.parse_payload(
                payload, file_name=FILE_NAME_LENGTH))
            return ChecksumRequest(unpacked_payload.file_name)
        except Exception as error:
            raise error

    def handle_valid_crc_request(self, header: RequestHeader) -> None:
        """
        Handles a valid CRC request.
        :param header: The header of the request.
        """
        try:
            request = self.unpack_checksum_payload(header)
            client_id = header.client_id
            file_name = request.file_name

            self.database.set_file_verified(client_id, file_name)
            logging.info(f"Client {client_id} verified file {file_name} successfully.")

            response = ResponseConfirmMessage(client_id)
            self.send_response(response)
            self.close_connection("Client process finished successfully.")

        except Exception as error:
            logging.error(error)
            self.send_response(ResponseServerFailed())

    def invalid_crc_retry(self, header: RequestHeader) -> None:
        """Handles requests to retry an invalid CRC.
        :param header: The header of the request.
        """
        try:
            client_id, file_name = header.client_id, self.unpack_checksum_payload(header).file_name
            logging.warning(f"Failed to upload '{file_name}' due to invalid CRC. Retrying...")
            self.send_response(ResponseConfirmMessage(client_id))
        except Exception as error:
            logging.error(error)

    def handle_invalid_crc_abort(self, header: RequestHeader) -> None:
        """
        Handles requests to abort due to an invalid CRC.
        :param header: The header of the request.
        """
        try:
            request = self.unpack_checksum_payload(header)
            client_id, file_name = header.client_id, request.file_name

            logging.warning(f"Aborted file reception for client {client_id}: Invalid CRC for '{file_name}'.")

            file_path = self.database.get_file_path(client_id, file_name)

            if os.path.isfile(file_path):
                os.remove(file_path)

            self.database.delete_file(client_id, file_name)

            response = ResponseConfirmMessage(client_id)
            self.send_response(response)
            self.close_connection(f"Aborted client process for client {client_id} due to an invalid CRC.", ERROR)

        except Exception as error:
            logging.error(error)
            self.send_response(ResponseServerFailed())

    # --------------------------------- Response --------------------------

    @staticmethod
    def response_header(header: ResponseHeader) -> bytes:
        """
        Creates a response header byte sequence.
        :param header: The response header.
        :return: A byte sequence representing the response header.
        """
        return struct.pack('<BHI', header.version, header.code, header.payload_size)

    def send(self, package: bytes):
        """
        Sends a server response to the client through the socket.
        :param package: The byte sequence to be sent.
        """
        self.client_socket.send(package)

    def send_response(self, response):
        """
        Sends a server response to the client through the socket.

        :param response: The response object to send.
        """
        if isinstance(response, ResponseRegistrationSuccess):
            fmt = f'<{UUID_SIZE}s'
            v = [response.client_id.bytes]
            response.set_payload_size(struct.calcsize(fmt))
            packed_payload = struct.pack(fmt, *v)
        elif isinstance(response, ResponseRegistrationFailed):
            packed_payload = b''
        elif isinstance(response, ResponseSendAES):
            response.set_payload_size(len(response.aes_key) + UUID_SIZE)
            packed_payload = struct.pack(f'<{UUID_SIZE}s', response.client_id.bytes) + response.aes_key
        elif isinstance(response, ResponseConfirmMessage):
            fmt = f'<{UUID_SIZE}s'
            v = [response.client_id.bytes]
            response.set_payload_size(struct.calcsize(fmt))
            packed_payload = struct.pack(fmt, *v)
        elif isinstance(response, ResponseValidCRC):
            fmt = f'<{UUID_SIZE}sL{FILE_NAME_LENGTH}sL'
            v = [response.client_id.bytes, response.content_size, str.encode(response.file_name), response.checksum]
            response.set_payload_size(struct.calcsize(fmt))
            packed_payload = struct.pack(fmt, *v)
        elif isinstance(response, ResponseConfirmReconnect):
            response.set_payload_size(len(response.aes_key) + UUID_SIZE)
            packed_payload = struct.pack(f'<{UUID_SIZE}s', response.client_id.bytes) + response.aes_key
        elif isinstance(response, ResponseDenyReconnect):
            fmt = f'<{UUID_SIZE}s'
            v = [response.client_id.bytes]
            response.set_payload_size(struct.calcsize(fmt))
            packed_payload = struct.pack(fmt, *v)
        elif isinstance(response, ResponseServerFailed):
            packed_payload = b''
        else:
            raise ValueError("Invalid response type")

        packed_header = self.response_header(response)

        # send header and payload to client through the socket
        self.send(packed_header)
        self.send(packed_payload)

    def close_connection(self, message, exit_status=0):
        """
        Close the client connection with the given message and exit status.

        :param message: Message indicating the reason for closing the connection.
        :param exit_status: Exit status code (default is 0).
        """
        logging.error(message) if exit_status != 0 else logging.info(message)
        logging.info("Client disconnected." if exit_status == 0 else "Client disconnected due to an error.")
        self.client_socket.close()
        sys.exit(exit_status)
