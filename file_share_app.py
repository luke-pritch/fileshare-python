#!/usr/bin/env python3

########################################################################

import socket
import argparse
import sys
import threading
import time
import os

########################################################################

# Define all of the packet protocol field lengths. See the
# corresponding packet formats below.
CMD_FIELD_LEN = 1  # 1 byte commands sent from the client.
FILE_SIZE_FIELD_LEN = 8  # 8 byte file size field.

# Packet format when a GET command is sent from a client, asking for a
# file download:

# -------------------------------------------
# | 1 byte GET command  | ... file name ... |
# -------------------------------------------

# When a GET command is received by the server, it reads the file name
# then replies with the following response:

# -----------------------------------
# | 8 byte file size | ... file ... |
# -----------------------------------

# Define a dictionary of commands. The actual command field value must
# be a 1-byte integer. For now, we only define the "GET" command,
# which tells the server to send a file.

CMD = {"GET": 2,
       "PUT": 3,
       "LIST": 4}

MSG_ENCODING = "utf-8"


########################################################################
# File Sharing Client Template
########################################################################

class Client:
    RECV_SIZE = 256
    INITIAL_PROMPT = "No connection. Enter one of 'scan', 'connect'\n"
    CONNECT_PROMPT = "Connected to server. Enter on of 'put', 'get', 'llist', 'rlist' ('bye' to exit)\n"
    HOSTNAME = socket.gethostname()
    # Define the message to broadcast.
    MSG_ENCODING = "utf-8"
    MESSAGE = "SERVICE DISCOVERY"
    MESSAGE_ENCODED = MESSAGE.encode('utf-8')

    # Use the broadcast-to-everyone IP address or a directed broadcast
    # address. Define a broadcast port.
    BROADCAST_ADDRESS = "255.255.255.255"  # or e.g., "192.168.1.255"
    BROADCAST_PORT = 30000
    BRODCAST_TIMEOUT = 5
    ADDRESS_PORT = (BROADCAST_ADDRESS, BROADCAST_PORT)

    def __init__(self):
        self.socketFS = None
        self.socketSD = None
        self.connected = False
        self.local_directory = './file_share'
        os.chdir(self.local_directory)

        self.get_tcp_socket()

        self.process_connect_prompt_input()

    def create_discovery_socket(self):
        try:
            # Set up a UDP socket.
            self.socketSD = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

            # set socket layer socket options.
            self.socketSD.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            # Set the option for broadcasting.
            self.socketSD.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            # Set service discovery timeout.
            self.socketSD.settimeout(self.BRODCAST_TIMEOUT)

        except Exception as msg:
            print(msg)
            sys.exit(1)

    def send_broadcasts(self):
        try:
            self.create_discovery_socket()
            print("SERVICE DISCOVERY scan ...")
            print("Sending to {} ...".format(Client.ADDRESS_PORT))
            self.socketSD.sendto(Client.MESSAGE_ENCODED, Client.ADDRESS_PORT)
            recvd_bytes, address = self.socketSD.recvfrom(Client.RECV_SIZE)
            print("{} found at {}".format(recvd_bytes.decode(Server.MSG_ENCODING), address))

        except Exception as msg:
            print(msg)
        except KeyboardInterrupt:
            print()
        except socket.timeout:
            print("No services found")
        finally:
            self.socketSD.close()
    def process_connect_prompt_input(self):
        while True:
            # We are connected to the FS. Prompt the user for what to
            # do.
            if not self.connected:
                initial_prompt = input(Client.INITIAL_PROMPT)
                initial_prompt_cmd, *initial_prompt_args = initial_prompt.split()

                if initial_prompt_cmd == 'scan':
                    self.send_broadcasts()
                elif initial_prompt_cmd == 'connect':
                    self.connect_to_server(*initial_prompt_args)
            else:
                connect_prompt_input = input(Client.CONNECT_PROMPT)
                if connect_prompt_input:
                    # If the user enters something, process it.
                    try:
                        # Parse the input into a command and its
                        # arguments.
                        connect_prompt_cmd, *connect_prompt_args = connect_prompt_input.split()
                    except Exception as msg:
                        print(msg)
                        continue
                    if connect_prompt_cmd == 'llist':
                        # Get a local files listing and print it out.
                        print('The files within the directory {} are'
                              .format(self.local_directory))
                        print(os.listdir())
                    elif connect_prompt_cmd == 'rlist':
                        # Do a sendall and ask the FS for a remote file listing.
                        # Do a recv and output the response when it returns.
                        self.list_cmd()
                    elif connect_prompt_cmd == 'put':
                        # Write code to interact with the FS and upload a
                        # file.
                        self.put_file(*connect_prompt_args)
                    elif connect_prompt_cmd == 'get':
                        # Write code to interact with the FS and download
                        # a file.
                        self.get_file(*connect_prompt_args)
                    elif connect_prompt_cmd == 'bye':
                        # Disconnect from the FS.
                        print('Good bye!')
                        self.socketFS.close()
                        break
                    else:
                        pass

    def get_tcp_socket(self):
        try:
            self.socketFS = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        except Exception as msg:
            print(msg)
            exit()

    def connect_to_server(self, ip_addr, port):
        try:
            self.socketFS.connect((str(ip_addr), int(port)))
            self.connected = True
        except Exception as msg:
            print(msg)
            exit()

    def socket_recv_size(self, length):
        bytes = self.socketFS.recv(length)
        if len(bytes) < length:
            self.socketFS.close()
            exit()
        return (bytes)

    def list_cmd(self):
        pkt = CMD["LIST"].to_bytes(CMD_FIELD_LEN, byteorder='big')
        self.socketFS.sendall(pkt)
        # TODO: read the response
        dir_size_bytes = self.socket_recv_size(FILE_SIZE_FIELD_LEN)
        if len(dir_size_bytes) == 0:
            self.socketFS.close()
            return

        # Convert to host byte order
        dir_size = int.from_bytes(dir_size_bytes, byteorder='big')

        # Receive the listing
        recvd_bytes_total = bytearray()
        try:
            # recv until size is reached
            while len(recvd_bytes_total) < dir_size:
                recvd_bytes_total += self.socketFS.recv(Client.RECV_SIZE)

            # Decode the listing and print to user
            print("Received {} bytes.".format(len(recvd_bytes_total)))
            directory_list = recvd_bytes_total.decode(MSG_ENCODING)
            print("Remote directory listing: ")
            for element in directory_list.split(","):
                print(element)
        except KeyboardInterrupt:
            print()
            exit(1)
            # If the socket has been closed by the server, break out
            # and close it on this end.
        except socket.error:
            self.socketFS.close()

    def put_file(self, filename):
        # Create the packet PUT field.
        get_field = CMD["PUT"].to_bytes(CMD_FIELD_LEN, byteorder='big')
        # Create the packet filename field.
        filename_field = filename.encode(MSG_ENCODING)
        # Create the packet.
        pkt = get_field + filename_field
        # Send the request packet to the server.
        self.socketFS.sendall(pkt)

        # Wait for response from the server as we don't want to upload a file that exists
        upload_resp_bytes = self.socketFS.recv(1)
        print("Received {}".format(upload_resp_bytes))
        success = 1
        if upload_resp_bytes == success.to_bytes(1, byteorder='big'):
            # Good to upload
            # Open the requested file and get set to send it to the
            # client.
            try:
                file_bytes = open(filename, 'rb').read()
            except FileNotFoundError:
                print("Local file not found: {}".format(filename))
                self.socketFS.close()
                return

            # read the binary file
            file_size_bytes = len(file_bytes)
            file_size_field = file_size_bytes.to_bytes(FILE_SIZE_FIELD_LEN, byteorder='big')

            # Create the packet to be sent with the header field.
            pkt = file_size_field + file_bytes

            try:
                # Send the packet to the connected client.
                self.socketFS.sendall(pkt)
                # print("Sent packet bytes: \n", pkt)
                print("Sending file: ", filename)
            except socket.error:
                # If the server has closed the connection, close the
                # socket on this end.
                print("Closing server connection ...")
                self.socketFS.close()
                return
        else:
            print("Upload refused by server")
            return

    def get_file(self, filename):

        # Create the packet GET field.
        get_field = CMD["GET"].to_bytes(CMD_FIELD_LEN, byteorder='big')

        # Create the packet filename field.
        filename_field = filename.encode(MSG_ENCODING)

        # Create the packet.
        pkt = get_field + filename_field

        # Send the request packet to the server.
        self.socketFS.sendall(pkt)

        # Read the file size field.
        file_size_bytes = self.socket_recv_size(FILE_SIZE_FIELD_LEN)
        if len(file_size_bytes) == 0:
            self.socketFS.close()
            return

        # Make sure that you interpret it in host byte order.
        file_size = int.from_bytes(file_size_bytes, byteorder='big')

        # Receive the file itself.
        recvd_bytes_total = bytearray()
        try:
            # Keep doing recv until the entire file is downloaded.
            while len(recvd_bytes_total) < file_size:
                recvd_bytes_total += self.socketFS.recv(Client.RECV_SIZE)

            # Create a file using the received filename and store the
            # data.
            print("Received {} bytes. Creating file: {}" \
                  .format(len(recvd_bytes_total), filename))

            with open(filename, 'wb') as f:
                f.write(recvd_bytes_total)
        except KeyboardInterrupt:
            print()
            exit(1)
        # If the socket has been closed by the server, break out
        # and close it on this end.
        except socket.error:
            self.socketFS.close()


########################################################################


# File Sharing Server Template
########################################################################

class Server:
    HOSTNAME = "0.0.0.0"#socket.gethostname()
    TCP_PORT = 30001
    UDP_PORT = 30000
    TCP_ADDRESS_PORT = (HOSTNAME, TCP_PORT)

    RECV_SIZE = 1024
    FILE_NOT_FOUND_MSG = "Error: Requested file is not available!"
    BACKLOG = 10

    HOST = "0.0.0.0"
    UDP_ADDRESS_PORT = (HOST, UDP_PORT)

    MSG_ENCODING = "utf-8"
    MESSAGE = "You've connected to TLT File Sharing Service on:" + HOSTNAME
    MESSAGE_ENCODED = MESSAGE.encode('utf-8')

    def __init__(self):
        os.chdir('./fileshare')  # Make the working directory the file share folder
        self.socketSD = None
        self.socketFS = None
        self.get_discovery_socket()
        self.get_file_sharing_socket()
        self.receive_forever()

    def get_discovery_socket(self):
        try:
            # Create an IPv4 UDP socket.
            self.socketSD = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

            # Bind to all interfaces and the agreed on broadcast port.
            self.socketSD.bind(Server.UDP_ADDRESS_PORT)

            print("Listening for service discovery on port {}".format(Server.UDP_ADDRESS_PORT))
        except Exception as msg:
            print(msg)
            sys.exit(1)

    def listen_for_service_discovery(self):
        while True:
            # Check for service discovery queries and respond with
            # your name and address.
            data, address = self.socketSD.recvfrom(Server.RECV_SIZE)
            data = data.decode('utf-8')
            if data == "SERVICE DISCOVERY":
                print("Broadcast received: ", data, address)
                self.socketSD.sendto(self.MESSAGE_ENCODED, address)
            else:
                pass

    def get_file_sharing_socket(self):
        try:
            # Create the TCP server listen socket in the usual way.
            self.socketFS = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socketFS.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socketFS.setblocking(False)
            self.socketFS.bind((Server.HOSTNAME, Server.TCP_PORT))
            self.socketFS.listen(Server.BACKLOG)
            print("File share listening on port {} ...".format(Server.TCP_PORT))
        except Exception as msg:
            print(msg)
            exit()

    def receive_forever(self):
        # First, create a thread that will handle incoming service
        # discoveries.
        threading.Thread(target=self.listen_for_service_discovery).start()
        # Then loop forever, accepting incoming file sharing
        # connections. When one occurs, create a new thread for
        # handling it.
        try:
            while True:
                # Check for new file sharing clients. Pass the new client
                # off to the connection handler with a new execution
                # thread.
                try:
                    client = self.socketFS.accept()
                    threading.Thread(target=self.connection_handler, args=(client,)).start()
                except socket.error:
                    pass
        except KeyboardInterrupt:
            print()
        finally:
            self.socketSD.close()
            self.socketFS.close()
            sys.exit(1)

    def connection_handler(self, client):
        connection, address_port = client
        connection.setblocking(True)
        threadName = threading.currentThread().getName()
        print(threadName, " - Connection received from", address_port)
        while True:
            print("-" * 72)
            print("Connection received from {}.".format(address_port))

            in_bytes = connection.recv(CMD_FIELD_LEN)
            if len(in_bytes) == 0:
                print(threadName, " - Closing client connection ... ")
                connection.close()
                break

            # Read the command and parse it
            cmd = int.from_bytes(in_bytes, byteorder='big')
            if cmd == CMD["GET"]:
                print("GET command received")
                self.do_get(connection)
            elif cmd == CMD["PUT"]:
                print("PUT command received")
                self.do_put(connection)
            elif cmd == CMD["LIST"]:
                print("List command received")
                self.do_list(connection)
            else:
                # Not a valid command
                print("Invalid command {}".format(cmd))

    def do_get(self, connection):
        # Complete a GET command: Client wants to get a file
        # The command is good. Now read and decode the requested
        # filename.
        filename_bytes = connection.recv(Server.RECV_SIZE)
        filename = filename_bytes.decode(MSG_ENCODING)

        # Open the requested file and get set to send it to the
        # client.
        try:
            file_bytes = open(filename, 'rb').read()
        except FileNotFoundError:
            print(Server.FILE_NOT_FOUND_MSG)
            connection.close()
            return

        # read the binary file
        file_size_bytes = len(file_bytes)
        file_size_field = file_size_bytes.to_bytes(FILE_SIZE_FIELD_LEN, byteorder='big')

        # Create the packet to be sent with the header field.
        pkt = file_size_field + file_bytes

        try:
            # Send the packet to the connected client.
            connection.sendall(pkt)
            # print("Sent packet bytes: \n", pkt)
            print("Sending file: ", filename)
        except socket.error:
            # If the client has closed the connection, close the
            # socket on this end.
            print("Closing client connection ...")
            connection.close()
            return

    def do_put(self, connection):
        # Complete a PUT command: Client is uploading a file

        # Get the file name to write
        filename_bytes = connection.recv(Server.RECV_SIZE)
        filename = filename_bytes.decode(MSG_ENCODING)

        print("Recieved filename = ", filename)

        # TODO: check if name is valid?
        valid_bytes = 1
        connection.sendall(valid_bytes.to_bytes(1, byteorder='big'))
        # Read the file size field.
        file_size_bytes = connection.recv(FILE_SIZE_FIELD_LEN)
        if len(file_size_bytes) == 0:
            connection.close()
            return

        # Make sure that you interpret it in host byte order.
        file_size = int.from_bytes(file_size_bytes, byteorder='big')

        print("Received file size = {}".format(file_size))

        # Receive the file itself.
        recvd_bytes_total = bytearray()
        try:
            # Keep doing recv until the entire file is downloaded.
            while len(recvd_bytes_total) < file_size:
                recvd_bytes_total += connection.recv(Server.RECV_SIZE)

            # Create a file using the received filename and store the
            # data.
            print("Received {} bytes. Creating file: {}".format(len(recvd_bytes_total), filename))

            with open(filename, 'wb') as f:
                f.write(recvd_bytes_total)
        except KeyboardInterrupt:
            print()
            exit(1)
        # If the socket has been closed by the server, break out
        # and close it on this end.
        except socket.error:
            connection.close()

    def do_list(self, connection):
        # Complete a list command: return a directory listing of the server
        # Send the directory as a comma separated string
        directory = ",".join(os.listdir())
        dir_bytes = directory.encode(MSG_ENCODING)
        dir_size_bytes = len(dir_bytes)
        dir_size_field = dir_size_bytes.to_bytes(FILE_SIZE_FIELD_LEN, byteorder='big')
        # Create the packet to be sent with the header field.
        pkt = dir_size_field + dir_bytes

        try:
            connection.sendall(pkt)
            print("Sending directory listing: ", directory)
        except socket.error:
            # If client closed conn, close on this end
            print("Closing client connection ...")
            connection.close()
            return


########################################################################

if __name__ == '__main__':
    roles = {'client': Client, 'server': Server}
    parser = argparse.ArgumentParser()

    parser.add_argument('-r', '--role',
                        choices=roles,
                        help='server or client role',
                        required=True, type=str)

    args = parser.parse_args()
    roles[args.role]()

########################################################################
