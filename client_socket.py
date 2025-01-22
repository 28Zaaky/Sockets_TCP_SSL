import socket
import threading
import ssl

def receive_messages(client_socket):
    while True:
        try:
            message = client_socket.recv(1024).decode('utf-8')
            if message:
                print(message)
            else:
                break
        except:
            break

def start_client():
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)

    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    context.load_verify_locations('server.crt')

    raw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket = context.wrap_socket(raw_socket, server_hostname="192.168.0.212")
    client_socket.connect(("192.168.0.212", 5000))

    username = input("Entrez votre nom d'utilisateur: ")
    client_socket.send(username.encode('utf-8'))

    receive_thread = threading.Thread(target=receive_messages, args=(client_socket,))
    receive_thread.start()

    while True:
        message = input()
        if message.lower() == '/quit':
            client_socket.send('/quit'.encode('utf-8'))
            client_socket.close()
            break
        client_socket.send(message.encode('utf-8'))

if __name__ == "__main__":
    start_client()