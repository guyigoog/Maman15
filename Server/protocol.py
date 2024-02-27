import uuid
from enum import Enum
from uuid import UUID

from consts import SERVER_VERSION, EMPTY


class UUIDMixin:
    def __init__(self, client_id: UUID):
        self.client_id = client_id


class NameMixin:
    def __init__(self, name):
        self.name = name.decode('windows-1252').split('\0', 1)[0]


class FileNameMixin:
    def __init__(self, file_name):
        self.file_name = file_name.decode('windows-1252').split('\0', 1)[0]


class File:
    def __init__(self, client_id, file_name, path, verified):
        self.client_id = client_id
        self.file_name = file_name
        self.path = path
        self.verified = verified


class Client(UUIDMixin):
    def __init__(self, client_id, name, public_key, last_seen, aes_key):
        super().__init__(client_id)
        self.name = name
        self.public_key = public_key
        self.last_seen = last_seen
        self.aes_key = aes_key


class RequestHeader:
    def __init__(self, client_id, version, code, payload_size):
        try:
            self.client_id = uuid.UUID(bytes=client_id)
        except ValueError:
            raise ValueError("Illegal client_id, not a UUID")
        self.version = version
        self.code = code
        self.payload_size = payload_size


class RegisterRequest(NameMixin):
    def __init__(self, name):
        super().__init__(name)


class ReconnectRequest(NameMixin):
    def __init__(self, name):
        super().__init__(name)


class ClientPublicKey(NameMixin):
    def __init__(self, name, public_key):
        super().__init__(name)
        self.public_key = public_key


class ReceiveFile(FileNameMixin):
    def __init__(self, content_size, file_name, message_content):
        super().__init__(file_name)
        self.content_size = content_size
        self.message_content = message_content


class ChecksumRequest(FileNameMixin):
    def __init__(self, file_name):
        super().__init__(file_name)


class RequestPayloadCodes(Enum):
    Register = 1025
    ClientSendPublicKey = 1026
    Reconnect = 1027
    SendFile = 1028
    ValidCRC = 1029
    InvalidCRCRetry = 1030
    InvalidCRCAbort = 1031


class ResponsePayloadCodes(Enum):
    RegistrationSuccess = 2100
    RegistrationFailed = 2101
    SendAES = 2102
    ValidCRC = 2103
    ConfirmMessage = 2104
    ConfirmReconnect = 2105
    DenyReconnect = 2106
    ServerFailed = 2107


class ResponseHeader:
    def __init__(self, code):
        self.version = SERVER_VERSION
        self.code = code
        self.payload_size = EMPTY

    def set_payload_size(self, payload_size):
        self.payload_size = payload_size


class ResponseRegistrationSuccess(UUIDMixin, ResponseHeader):
    def __init__(self, client_id):
        ResponseHeader.__init__(self, ResponsePayloadCodes.RegistrationSuccess.value)
        UUIDMixin.__init__(self, client_id)


class ResponseRegistrationFailed(ResponseHeader):
    def __init__(self):
        super().__init__(ResponsePayloadCodes.RegistrationFailed.value)


class ResponseSendAES(UUIDMixin, ResponseHeader):
    def __init__(self, client_id, aes_key):
        ResponseHeader.__init__(self, ResponsePayloadCodes.SendAES.value)
        UUIDMixin.__init__(self, client_id)
        self.aes_key = aes_key


class ResponseValidCRC(UUIDMixin, ResponseHeader):
    def __init__(self, client_id, content_size, file_name, checksum):
        ResponseHeader.__init__(self, ResponsePayloadCodes.ValidCRC.value)
        UUIDMixin.__init__(self, client_id)
        self.content_size = content_size
        self.file_name = file_name
        self.checksum = checksum


class ResponseConfirmMessage(UUIDMixin, ResponseHeader):
    def __init__(self, client_id):
        ResponseHeader.__init__(self, ResponsePayloadCodes.ConfirmMessage.value)
        UUIDMixin.__init__(self, client_id)


class ResponseConfirmReconnect(UUIDMixin, ResponseHeader):
    def __init__(self, client_id, aes_key):
        ResponseHeader.__init__(self, ResponsePayloadCodes.ConfirmReconnect.value)
        UUIDMixin.__init__(self, client_id)
        self.aes_key = aes_key


class ResponseDenyReconnect(UUIDMixin, ResponseHeader):
    def __init__(self, client_id):
        ResponseHeader.__init__(self, ResponsePayloadCodes.DenyReconnect.value)
        UUIDMixin.__init__(self, client_id)


class ResponseServerFailed(ResponseHeader):
    def __init__(self):
        super().__init__(ResponsePayloadCodes.ServerFailed.value)
