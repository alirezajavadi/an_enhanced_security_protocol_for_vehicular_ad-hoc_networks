import socket
from ecdsa import SECP256k1, SigningKey, VerifyingKey
from ecdsa.ellipticcurve import Point, PointJacobi
import os
import time
import base64
import xxhash


start=time.time()


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
HOST = "192.168.100.1"
PORT = 8910
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((HOST, PORT))



# initial
IDv = "12481632"
K = "123456789012"

Sv = SigningKey.generate(curve=SECP256k1)
PKv = Sv.get_verifying_key()
sock.send(PKv.to_string())

PKa = sock.recv(1024)
PKa = VerifyingKey.from_string(PKa, curve=SECP256k1)

# frist

Nv = int.from_bytes(os.urandom(32), byteorder='big') 

curve = SECP256k1 # Use SECP256k1 curve
P = curve.generator

V1 = Nv * P
V1_toSend = base64.b64encode(V1.to_bytes()).decode('utf-8')
V2 = Nv * PKa.pubkey.point
V2_str = base64.b64encode(V2.to_bytes()).decode('utf-8')
PIDv = xor_bytes([f"{IDv},{K}".encode('utf-8'), xxhash.xxh128(V2.to_bytes()).digest()])
PIDv_str = base64.b64encode(PIDv).decode('utf-8')
T1 = time.time()
V3 = xxhash.xxh128(f"{PIDv}{V2_str}{T1}").hexdigest()

M1 = f"{PIDv_str},{V1_toSend},{V3},{T1}"

printit(f"[#] Sending the first message {{PIDv, V1, V3, T1}}: {M1}",1)
time.sleep(3)
sock.send(M1.encode('utf-8'))


# vehcile - second
M4 = sock.recv(10240).decode('utf-8')
printit(f"[#] The fourth message from the aggregator has been recieved {{PIDa2, A1, A6, T4}}: {M4}",2)

M4_list = M4.split(",")
received_PIDa2_str = M4_list[0]
received_PIDa2 = base64.b64decode(received_PIDa2_str.encode('utf-8'))
received_A1_str = M4_list[1]
received_A1 = str_to_point(received_A1_str)
received_A6 = M4_list[2]
received_T4 = M4_list[3]


if time.time() - float(received_T4) > 50:
    printit("[!] T4 is not fresh! The connection has been closed.",3)
    exit()

A5 = Sv.privkey.secret_multiplier * received_A1
A5_str = base64.b64encode(A5.to_bytes()).decode('utf-8')
Auth4 = xor_bytes([received_PIDa2, xxhash.xxh128(A5.to_bytes()).digest()]).decode('utf-8')
Auth4_list = Auth4.split(",")
S2_str = Auth4_list[4]
S2 = str_to_point(S2_str)

SKv = Nv * S2
SKv_str = base64.b64encode(SKv.to_bytes()).decode('utf-8')
printit(f"SKv: {SKv_str}",4)

A6_prime = xxhash.xxh128(f"{received_PIDa2}{A5_str}{SKv_str}{received_T4}").hexdigest()


if A6_prime == received_A6:
    printit("[#] The aggregator has been authenticated successfully.",0)
else:
    printit("[!] The aggregator's authentication has failed.",3)
    exit()


# timing
end = time.time()

#print(f"---------------------------------\nElapsed Time (millisecond): {(end - start) * 1000}")
