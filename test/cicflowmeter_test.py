import os
import sys

import joblib
from scapy.sendrecv import AsyncSniffer

current_project_directory = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(current_project_directory)

from vendor.cicflowmeter.flow_session import FlowSession

# 모델과 피처 목록 불러오기
model_data = joblib.load('ddos_random_forest_model_with_features.pkl')
model = model_data['model']

# setattr(FlowSession, "output_mode", "csv")
setattr(FlowSession, "output_mode", "stdout")
setattr(FlowSession, "output", "output.csv")
# setattr(FlowSession, "fields", fields)
setattr(FlowSession, "verbose", False)


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