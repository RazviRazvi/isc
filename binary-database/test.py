import sys
import struct
import socket
import ctypes


class ReqPacket():
    DB_NOOP = 0
    DB_RETRIEVE = 1
    DB_STORE = 2
    DB_DELETE = 3

    PY_TYPE_MAP = {
        "NoneType": (0, "x"),
        "int": (1, "<i"),
        "float": (2, "<f"),
        "str": (5, "<s"),
        "bytes": (9, "<s"),
    }

    def __init__(self, action, key=None, value=None):
        self.action = action
        self.key = str(key)
        self.value = value

    def raw_data(self):
        raw_data = bytearray()
        raw_data += struct.pack("<i", self.action)
        if self.action in (self.DB_RETRIEVE, self.DB_STORE, self.DB_DELETE):
            raw_data += struct.pack("<16s", self.key.encode("ASCII"))
            if self.action == self.DB_STORE:
                value = self.value
                s_type = type(value).__name__
                raw_type = self.PY_TYPE_MAP.get(s_type, None)
                if not raw_type:
                    # cast value to str
                    value = str(self.value)
                    raw_type = self.PY_TYPE_MAP["str"]
                raw_data += struct.pack("<i", raw_type[0])
                if s_type == "str":
                    raw_data += value.encode("ASCII") + b"\x00"
                elif s_type == "bytes" or s_type == "bytestring":
                    raw_data += value
                else:
                    raw_data += struct.pack(raw_type[1], value)
        return raw_data

    @classmethod
    def retrieve(cls, key):
        return cls(cls.DB_RETRIEVE, key)

    @classmethod
    def store(cls, key, value):
        return cls(cls.DB_STORE, key, value)

    @classmethod
    def delete(cls, key):
        return cls(cls.DB_DELETE, key)


class ReplyPacket():
    RAW_TYPE_MAP = {
        0: (None, ""),
        1: (int, "<i"),
        2: (float, "<f"),
        5: (str, "<s"),
    }

    def __init__(self, raw_data, key=None, ret_raw=False):
        self.status = -1
        self.key = key
        self.value = None
        self._parse(raw_data)

    def _parse(self, raw_data):
        if len(raw_data) < 4:
            return False
        offset = 0
        extracted = struct.unpack_from("<i", raw_data, offset)
        offset += 4
        self.status = extracted[0]
        if len(raw_data) < 8:
            return False
        extracted = struct.unpack_from("<i", raw_data, offset)
        offset += 4
        self.type = extracted[0]
        rest = raw_data[offset:]
        if self.type in self.RAW_TYPE_MAP:
            conv_value = self.RAW_TYPE_MAP.get(self.type)
            if conv_value[0] == str:
                self.value = ctypes.create_string_buffer(rest).value
            elif conv_value[0]:
                self.value = struct.unpack_from(conv_value[1], rest, 0)[0]
        else:
            self.value = rest
        return True

    def __repr__(self):
        s = ""
        if self.key:
            s += f"key={str(self.key)}, "
        return f"DBEntry{{ status={self.status}, {s}val={str(self.value)} }}"

DEBUG = False

def send_request(sock, req_obj):
    data = req_obj
    if isinstance(req_obj, ReqPacket):
        data = req_obj.raw_data()
    if DEBUG:
        print(f"DEBUG: send [{len(data)}]", data)
    sock.send(struct.pack("<i", len(data)))
    if data:
        sock.send(data)
        # now receive reply
        data_len = sock.recv(4)
        data_len = data_len[0]
        data = sock.recv(data_len)
        if DEBUG:
            print(f"DEBUG: recv [{data_len}]", data)
        return ReplyPacket(raw_data=data, key=req_obj.key)
    return None


def main(argv):
    sock = socket.socket(socket.AF_INET)
    sock.connect((argv[1], int(argv[2])))

    reply = send_request(sock, ReqPacket.store("my_first_test", "Hello 123"))
    reply = send_request(sock, ReqPacket.retrieve("my_first_test"))
    print(reply)

    reply = send_request(sock, ReqPacket.store("number1", 666))
    reply = send_request(sock, ReqPacket.retrieve("number1"))
    print(reply)

    reply = send_request(sock, ReqPacket.store("ffl04t", 76.4))
    reply = send_request(sock, ReqPacket.retrieve("ffl04t"))
    print(reply)

    reply = send_request(sock, ReqPacket.retrieve("inexistent"))
    print(reply)
    reply = send_request(sock, ReqPacket.delete("my_first_test"))
    print(reply)
    reply = send_request(sock, ReqPacket.retrieve("my_first_test"))
    print(reply)

    reply = send_request(sock, ReqPacket.store("last_test_entry", "Please don't crash!"))
    print(reply)
    reply = send_request(sock, ReqPacket.retrieve("last_test_entry"))
    print(reply)

    send_request(sock, b"")


if __name__ == "__main__":
    main(sys.argv)
