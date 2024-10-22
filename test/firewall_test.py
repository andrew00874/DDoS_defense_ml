import os
import sys

current_project_directory = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(current_project_directory)

from module.firewall import get_firewall


def test_get_firewall():
    firewall = get_firewall()
    assert firewall is not None
    assert firewall.block_ip("192.168.1.100") is None
    assert firewall.unblock_ip("192.168.1.100") is None


test_get_firewall()