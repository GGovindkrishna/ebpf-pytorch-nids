import socket

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
print("[*] Sending UDP anomaly traffic spike...")
for i in range(200):
    sock.sendto(b"X" * 256, ("127.0.0.1", 9999))
print("[+] Spike sent successfully!")
