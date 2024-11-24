import socket

host = "isc2024.1337.cx"
port = 11001

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((host, port))
    s.sendall(b"Hello, server!\n")
    data = s.recv(1024)

print("Received", repr(data))
