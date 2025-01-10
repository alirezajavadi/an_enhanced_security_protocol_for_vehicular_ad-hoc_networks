import socket
from ecdsa import SECP256k1, SigningKey, VerifyingKey
from ecdsa.ellipticcurve import Point, PointJacobi
import os
import time
import base64
import xxhash


def str_to_point(b64_str):
        point = Point.from_bytes(SECP256k1.curve, base64.b64decode(b64_str.encode('utf-8')))
        return PointJacobi(SECP256k1.curve, point.x(), point.y(),1)

def xor_bytes(list_of_bytes):
    max_len = max(len(b) for b in list_of_bytes)

    result = bytearray(max_len)
    for i in range(len(result)):
        result[i] = list_of_bytes[0][i] if i < len(list_of_bytes[0]) else 0

    for b in list_of_bytes[1:]:
        for i in range(len(b)):
            result[i] ^= b[i]

    return bytes(result)

def printit(msg,style):
    msg += "\033[0m"
    if style == 1 : # blue
        msg = "\033[94m" + msg
    elif style == 2: # green
        msg = "\033[92m" + msg
    elif style == 3: # red
        msg = "\033[91m" + msg
    elif style == 4: # bold
        msg = "\033[1m" + msg

    print(msg)

# connection
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
host = '192.168.100.1'
port = 8910

try:
    sock.bind((host, port))
except socket.error as e:
    print(str(e))
    exit(0)

sock.listen(2)
printit("[#] Connection Setting:",111)
print("\tGrid server: ",end="",flush=True)
grid_server, grid_server_address = sock.accept()
#print("The grid server: ",end="")
printit(f"Connected",4)

PKs = grid_server.recv(1024)
PKs = VerifyingKey.from_string(PKs, curve=SECP256k1)

print("\tVehicle: ", end="",flush=True)
vehicle, vehicle_address = sock.accept()
printit(f"Connected",4)

PKv = vehicle.recv(1024)
PKv = VerifyingKey.from_string(PKv, curve=SECP256k1)

# initial
IDa = "32168421"
K = "123456789012"

Sa = SigningKey.generate(curve=SECP256k1)
PKa = Sa.get_verifying_key()
vehicle.send(PKa.to_string())

grid_server.send(PKa.to_string())
#PKs = grid_server.recv(1024)
#PKs = VerifyingKey.from_string(PKs, curve=SECP256k1)

curve = SECP256k1 # Use SECP256k1 curve
P = curve.generator

# vehicle - first
M1 = vehicle.recv(10240).decode('utf-8')
printit(f"[#] The first message from the vehicle has been recieved {{PIDv, V1, V3, T1}}: {M1}",2)

M1_list = M1.split(",")
received_PIDv_str = M1_list[0]
received_PIDv = base64.b64decode(received_PIDv_str.encode('utf-8'))

received_V1_str = M1_list[1]
received_V3 = M1_list[2]
received_T1 = M1_list[3]

if time.time() - float(received_T1) > 50:
    printit("[!] T1 is not fresh! The connection has been closed.",3)
    exit()

received_V1 = str_to_point(received_V1_str)
V2 = Sa.privkey.secret_multiplier * received_V1
V2_str = base64.b64encode(V2.to_bytes()).decode('utf-8')

V3_prime = xxhash.xxh128(f"{received_PIDv}{V2_str}{received_T1}").hexdigest()
if V3_prime == received_V3:
    printit("[#] The vehicle has been authenticated successfully.",0)
else:
    printit("[!] The vehicle's authentication has failed.",3)
    exit()

Na = int.from_bytes(os.urandom(32), byteorder='big')
Auth1 = xor_bytes([received_PIDv, xxhash.xxh128(V2.to_bytes()).digest()]).decode("utf-8")
IDv = Auth1.split(',')[0]

A1 = Na * P
A1_str = base64.b64encode(A1.to_bytes()).decode('utf-8')
A2 = Na * received_V1
A2_str = base64.b64encode(A2.to_bytes()).decode('utf-8')
A3 = Na * PKs.pubkey.point
A3_str = base64.b64encode(A3.to_bytes()).decode('utf-8')
PIDa1 = xor_bytes([f"{IDa},{IDv},{K},{A2_str},{received_V1_str}".encode('utf-8'),xxhash.xxh128(A3.to_bytes()).digest()])
PIDa1_str = base64.b64encode(PIDa1).decode('utf-8')
T2 = time.time()
A4 = xxhash.xxh128(f"{PIDa1}{received_V1_str}{A2_str}{A3_str}{T2}").hexdigest()
M2 = f"{PIDa1_str},{A1_str},{A4},{T2}"
printit(f"[#] Sending the second message {{PIDa1, A1, A4, T2}}: {M2}",1)
time.sleep(3)
grid_server.send(M2.encode('utf-8'))

# aggregator - second
M3 = grid_server.recv(10240).decode('utf-8')
printit(f"[#] The third message from the grid server has been recieved {{PIDs, S1, S5, T3}}: {M3}",2)
M3_list = M3.split(",")
received_PIDs_str = M3_list[0]
received_PIDs = base64.b64decode(received_PIDs_str.encode('utf-8'))
received_S1_str = M3_list[1]
received_S1 = str_to_point(received_S1_str)
received_S5 = M3_list[2]
received_T3 = M3_list[3]


if time.time() - float(received_T3) > 50:
    printit("[!] T3 is not fresh! The connection has been closed.",3)
    exit()

S4 = Sa.privkey.secret_multiplier * received_S1
S4_str = base64.b64encode(S4.to_bytes()).decode('utf-8')

Auth3 = xor_bytes([received_PIDs,xxhash.xxh128(S4.to_bytes()).digest()]).decode("utf-8")
Auth3_list = Auth3.split(",")
IDs = Auth3_list[0]
S2_str = Auth3_list[4]
S2 = str_to_point(S2_str)
S3_str = Auth3_list[5]
S3 = str_to_point(S3_str)


SKa = Na * S3
SKa_str =base64.b64encode(SKa.to_bytes()).decode('utf-8')
printit(f"SKa: {SKa_str}",4)

S5_prime = xxhash.xxh128(f"{received_PIDs}{S2_str}{S4_str}{SKa_str}{received_T3}").hexdigest()

if S5_prime == received_S5:
    printit("[#] The grid server has been authenticated successfully.",0)
else:
    printit("[!] The grid server's authentication has failed.",3)
    exit()

A5 = Na * PKv.pubkey.point
A5_str = base64.b64encode(A5.to_bytes()).decode('utf-8')

PIDa2 = xor_bytes([f"{IDa},{IDv},{IDs},{K},{S2_str}".encode('utf-8'), xxhash.xxh128(A5.to_bytes()).digest() ])
PIDa2_str = base64.b64encode(PIDa2).decode('utf-8')
T4 = time.time()
A6 = xxhash.xxh128(f"{PIDa2}{A5_str}{SKa_str}{T4}").hexdigest()
M4 = f"{PIDa2_str},{A1_str},{A6},{T4}"
printit(f"[#] Sending the fourth message {{PIDa2, A1, A6, T4}}: {M4}",1)
time.sleep(3)
vehicle.send(M4.encode('utf-8'))
