import platform
import subprocess
from abc import ABC, abstractmethod


class FirewallInterface(ABC):
    @abstractmethod
    def block_ip(self, ip_address):
        pass

    @abstractmethod
    def unblock_ip(self, ip_address):
        pass


class LinuxFirewall(FirewallInterface):
    def block_ip(self, ip_address):
        try:
            subprocess.run(['sudo', 'iptables', '-A', 'INPUT', '-s', ip_address, '-j', 'DROP'], check=True)
            print(f"{ip_address} 차단 완료 (Linux).")
        except subprocess.CalledProcessError as e:
            print(f"{ip_address} 차단 실패 (Linux): {e}")

    def unblock_ip(self, ip_address):
        try:
            subprocess.run(['sudo', 'iptables', '-D', 'INPUT', '-s', ip_address, '-j', 'DROP'], check=True)
            print(f"{ip_address} 차단 해제 완료 (Linux).")
        except subprocess.CalledProcessError as e:
            print(f"{ip_address} 차단 해제 실패 (Linux): {e}")


class MacOSFirewall(FirewallInterface):
    def block_ip(self, ip_address):
        rule = f"block drop from {ip_address} to any\n"
        try:
            with open('/etc/pf.conf', 'a') as pf_conf:
                pf_conf.write(rule)

            subprocess.run(['sudo', 'pfctl', '-f', '/etc/pf.conf'], check=True)
            subprocess.run(['sudo', 'pfctl', '-e'], check=True)
            print(f"{ip_address} 차단 완료 (macOS).")
        except Exception as e:
            print(f"{ip_address} 차단 실패 (macOS): {e}")

    def unblock_ip(self, ip_address):
        try:
            # 해제는 pf.conf에서 수동으로 규칙을 삭제한 후 다시 pfctl -f 명령어를 실행해야 함
            print(f"차단 해제를 위해 /etc/pf.conf에서 {ip_address} 규칙을 수동으로 삭제하세요.")
            subprocess.run(['sudo', 'pfctl', '-f', '/etc/pf.conf'], check=True)
        except Exception as e:
            print(f"{ip_address} 차단 해제 실패 (macOS): {e}")


class WindowsFirewall(FirewallInterface):
    def block_ip(self, ip_address):
        try:
            subprocess.run(['netsh', 'advfirewall', 'firewall', 'add', 'rule',
                            f'name=Block {ip_address}', 'dir=in', 'action=block', f'remoteip={ip_address}'], check=True)
            print(f"{ip_address} 차단 완료 (Windows).")
        except subprocess.CalledProcessError as e:
            print(f"{ip_address} 차단 실패 (Windows): {e}")

    def unblock_ip(self, ip_address):
        try:
            subprocess.run(['netsh', 'advfirewall', 'firewall', 'delete', 'rule',
                            f'name=Block {ip_address}', f'remoteip={ip_address}'], check=True)
            print(f"{ip_address} 차단 해제 완료 (Windows).")
        except subprocess.CalledProcessError as e:
            print(f"{ip_address} 차단 해제 실패 (Windows): {e}")


def get_firewall():
    system_name = platform.system()
    if system_name == "Linux":
        return LinuxFirewall()
    elif system_name == "Darwin":  # macOS의 경우 platform.system()은 "Darwin"을 반환
        return MacOSFirewall()
    elif system_name == "Windows":
        return WindowsFirewall()
    else:
        raise NotImplementedError(f"{system_name}에 대한 방화벽 구현체가 없습니다.")