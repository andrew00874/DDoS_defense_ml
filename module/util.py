import socket


def get_ip_address(ifname=None):
    try:
        if ifname is None:
            ifname = socket.gethostname()  # gethostname으로 현재 호스트 이름 가져오기  

        # gethostbyname으로 현재 인터페이스의 IP 가져오기
        ip_address = socket.gethostbyname(ifname)
        return ip_address
    except socket.error as e:
        print(f"Error getting IP address: {e}")
        return None