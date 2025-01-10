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


# connection establish
HOST = "192.168.100.1"
PORT = 8910
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((HOST, PORT))

# initials
IDs = "12345678"
K = "123456789012"

Ss = SigningKey.generate(curve=SECP256k1)
PKs = Ss.get_verifying_key()
sock.send(PKs.to_string())

PKa = sock.recv(1024)
PKa = VerifyingKey.from_string(PKa, curve=SECP256k1)

curve = SECP256k1 # Use SECP256k1 curve
P = curve.generator

# grid
M2 = sock.recv(10240).decode('utf-8')
printit(f"[#] The second message from the aggregator has been recieved {{PIDa1, A1, A4, T2}}: {M2}",2)

M2_list = M2.split(",")
received_PIDa1_str = M2_list[0]
received_PIDa1 = base64.b64decode(received_PIDa1_str.encode('utf-8'))
received_A1_str = M2_list[1]
received_A1 = str_to_point(received_A1_str)
received_A4 = M2_list[2]
received_T2 = M2_list[3]

if time.time() - float(received_T2) > 50:
    printit("[!] T2 is not fresh! The connection has been closed.",3)
    exit()

A3 = Ss.privkey.secret_multiplier * received_A1
A3_str = base64.b64encode(A3.to_bytes()).decode('utf-8')

Auth2 = xor_bytes([received_PIDa1,xxhash.xxh128(A3.to_bytes()).digest()]).decode('utf-8')
Auth2_list = Auth2.split(",")
IDa = Auth2_list[0]
IDv = Auth2_list[1]
A2_str = Auth2_list[3]
V1_str = Auth2_list[4]
A4_prime = xxhash.xxh128(f"{received_PIDa1}{V1_str}{A2_str}{A3_str}{received_T2}").hexdigest()

if A4_prime == received_A4:
    printit("[#] The aggregrator has been authenticated successfully.",0)
else:
    printit("[!] The aggregrator's authentication has failed.",3)
    exit()

Ns = int.from_bytes(os.urandom(32), byteorder='big')
V1 = str_to_point(V1_str)
A2 = str_to_point(A2_str)
S1 = Ns * P
S1_str = base64.b64encode(S1.to_bytes()).decode('utf-8')
S2 = Ns * received_A1
S2_str = base64.b64encode(S2.to_bytes()).decode('utf-8')
S3 = Ns * V1
S3_str = base64.b64encode(S3.to_bytes()).decode('utf-8')
S4 = Ns * PKa.pubkey.point
S4_str = base64.b64encode(S4.to_bytes()).decode('utf-8')

SKs = Ns * A2
SKs_str = base64.b64encode(SKs.to_bytes()).decode('utf-8')
printit(f"SKs: {SKs_str}",4)

PIDs = xor_bytes([f"{IDs},{IDa},{IDv},{K},{S2_str},{S3_str}".encode("utf-8"), xxhash.xxh128(S4.to_bytes()).digest()])
PIDs_str = base64.b64encode(PIDs).decode('utf-8')
T3 = time.time()
S5 =  xxhash.xxh128(f"{PIDs}{S2_str}{S4_str}{SKs_str}{T3}").hexdigest()

M3 = f"{PIDs_str},{S1_str},{S5},{T3}"

printit(f"[#] Sending the third message {{PIDs, S1, S5, T3}}: {M3}",1)
time.sleep(3)
sock.send(M3.encode('utf-8'))

