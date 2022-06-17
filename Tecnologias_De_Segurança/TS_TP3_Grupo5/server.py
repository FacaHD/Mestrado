import os
import subprocess
import sys
import socket
import socket
import asyncio
import websockets



HOST = "127.0.0.1"  # Standard loopback interface address (localhost)
PORT = 65430  # Port to listen on (non-privileged ports are > 1023)

def openBrowser():
    myEnv = dict(os.environ)

    toDelete = [] 
    for (k, v) in myEnv.items():
        if k != 'PATH' and 'tmp' in v:
            toDelete.append(k)

    for k in toDelete:
        myEnv.pop(k, None)

    shell = False
    if sys.platform == "win32":
        opener = "start"
        shell = True
    elif sys.platform == "darwin":
        opener = "open"
    else: # Assume Linux
        opener = "xdg-open"

    subprocess.call([opener, 'index.html'], env=myEnv, shell=shell)


# create handler for each connection

async def handler(websocket, path):
    data = await websocket.recv()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((HOST, PORT))
    sock.sendall(data.encode())
    sock.close()
    

    
    

start_server = websockets.serve(handler, "localhost", 9995)
asyncio.get_event_loop().run_until_complete(start_server)
asyncio.get_event_loop().run_forever()


