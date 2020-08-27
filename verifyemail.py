# TCP client example
import socket
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(("192.168.0.119", 25))

data = client_socket.recv(512).decode()
print ("<= " , data)

data = "HELO thundermail.kr\n"
print ("=> " , data)
client_socket.send(data.encode())

data = client_socket.recv(512).decode()
print ("<= " , data)

data = "MAIL FROM:<r@thundermail.kr>\n"
print ("=> " , data)
client_socket.send(data.encode())

data = client_socket.recv(512).decode()
print ("<= " , data)


data = "RCPT TO:<r@post.thundermail.kr>\n"
print ("=> " , data)
client_socket.send(data.encode())

data = client_socket.recv(512).decode()
print ("<= " , data)

client_socket.close()