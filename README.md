# File Sharing Application w/Python
The following is a basic client/server application written in python 3. Utilising the following python libraries project:

- socket
- argparse
- sys
- threading
- time
- os

The included python script can be used from the command line via:
```bash
python file_share_app.py -r client
python file_share_app.py -r server
```
The client is able to broadcast across the current network that it is in to locate a server, the user is then prompted to connect to the server's IP and port via the 'connect' command. When connected the client can 'put' a file to the server and 'get' a file from the server to enable file sharing between the client and server. Multiple client connections are enabled through threading, Please note that there is no real security, just an exploration of transferring various file to and from a server and clients.
