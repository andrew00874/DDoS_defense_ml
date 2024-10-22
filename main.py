import socket

from scapy.sendrecv import AsyncSniffer

from module.util import get_ip_address
from vendor.cicflowmeter.flow_session import FlowSession

# setattr(FlowSession, "output_mode", "csv")
# setattr(FlowSession, "output_mode", "stdout")
setattr(FlowSession, "output_mode", "ddos_verifi")
setattr(FlowSession, "output", "output.csv")
setattr(FlowSession, "verbose", False)

my_ip_address = get_ip_address()
my_ip_addresses = input(f"My IP addresses (comma separated) (default: {my_ip_address}): ")
if my_ip_addresses:
    setattr(FlowSession, "my_ip_addresses", my_ip_addresses.split(","))
else:
    setattr(FlowSession, "my_ip_addresses", [my_ip_address])

# IP 주소가 유효한지 검사
for ip in FlowSession.my_ip_addresses:
    try:
        socket.inet_aton(ip)
    except socket.error:
        print(f"Invalid IP address: {ip}")
        exit(1)

print(f"My IP addresses: {FlowSession.my_ip_addresses}")
print("프로그램을 시작합니다...")

# 네트워크 인터페이스에서 실시간 캡처
sniffer = AsyncSniffer(
    filter="ip and (tcp or udp)",
    prn=None,
    session=FlowSession,
    store=False,
)


sniffer.start()

try:
    sniffer.join()
except KeyboardInterrupt:
    sniffer.stop()
finally:
    sniffer.join()