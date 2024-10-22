import joblib
import pandas as pd
from sklearn.preprocessing import StandardScaler

# 모델과 피처 목록 불러오기
model_data = joblib.load('ddos_random_forest_model_with_features.pkl')
model = model_data['model']
feature_columns = model_data['features']  # 자동으로 피처 목록을 불러옴

ddos_pkt_data = {
    'Src Port': 45044,
    'Dst Port': 80,
    'Protocol': 6,
    'Flow Duration': 3974862,
    'Tot Fwd Pkts': 29,  # 현재 패킷이 전송된 방향 패킷 수를 1로 설정
    'Tot Bwd Pkts': 44,  # 현재 패킷은 전송된 방향으로만 있으므로 0으로 설정
    'TotLen Fwd Pkts': 86,  # Fwd 패킷의 총 길이
    'TotLen Bwd Pkts': 59811,  # 역방향 패킷은 없으므로 0
    'Fwd Pkt Len Max': 86,
    'Fwd Pkt Len Min': 0,
    'Fwd Pkt Len Mean': 2.9655172413793096,
    'Fwd Pkt Len Std': 15.969799083226464,
    'Bwd Pkt Len Max': 1460,
    'Bwd Pkt Len Min': 0,
    'Bwd Pkt Len Mean': 1359.3409090909086,
    'Bwd Pkt Len Std': 372.02718975289076,
    'Flow Byts/s': 15068.950821437324,
    'Flow Pkts/s': 18.365417466065487,
    'Flow IAT Mean': 55206.41666666666,
    'Flow IAT Std': 195478.31665363663,
    'Flow IAT Max': 1566821.0,
    'Flow IAT Min': 167.0,
    'Fwd IAT Tot': 3735347.0,
    'Fwd IAT Mean': 133405.25,
    'Fwd IAT Std': 341775.6887123293,
    'Fwd IAT Max': 1805015.0,
    'Fwd IAT Min': 167.0,
    'Bwd IAT Tot': 3974862.0,
    'Bwd IAT Mean': 92438.65116279072,
    'Bwd IAT Std': 248174.8205743075,
    'Bwd IAT Max': 1566821.0,
    'Bwd IAT Min': 3997.0,
    'Fwd PSH Flags': 0,
    'Bwd PSH Flags': 0,
    'Fwd URG Flags': 0,
    'Bwd URG Flags': 0,
    'Fwd Header Len': 768,
    'Bwd Header Len': 896,
    'Fwd Pkts/s': 7.295850774190399,
    'Bwd Pkts/s': 11.069566691875089,
    'Pkt Len Min': 0,
    'Pkt Len Max': 1460,
    'Pkt Len Mean': 809.4189189189186,
    'Pkt Len Std': 728.8624277195806,
    'Pkt Len Var': 531240.438541281,
    'FIN Flag Cnt': 0,
    'SYN Flag Cnt': 1,
    'RST Flag Cnt': 0,
    'PSH Flag Cnt': 0,
    'ACK Flag Cnt': 0,
    'URG Flag Cnt': 0,
    'CWE Flag Count': 0,  # placeholder
    'ECE Flag Cnt': 0,  # placeholder
    'Down/Up Ratio': 1,  # placeholder, 필요시 계산
    'Pkt Size Avg': 820.5068493150685,
    'Fwd Seg Size Avg': 2.9655172413793105,  # 1 패킷당 세그먼트 크기 평균
    'Bwd Seg Size Avg': 1359.340909090909,  # 역방향 세그먼트 없음
    'Fwd Byts/b Avg': 0,  # 필요시 계산
    'Fwd Pkts/b Avg': 0,  # 필요시 계산
    'Fwd Blk Rate Avg': 0,  # 필요시 계산
    'Bwd Byts/b Avg': 0,  # 필요시 계산
    'Bwd Pkts/b Avg': 0,  # 필요시 계산
    'Bwd Blk Rate Avg': 0,  # 필요시 계산
    'Subflow Fwd Pkts': 29,
    'Subflow Fwd Byts': 86,
    'Subflow Bwd Pkts': 44,
    'Subflow Bwd Byts': 59811,
    'Init Fwd Win Byts': -1,  # 패킷에 따라 계산 필요
    'Init Bwd Win Byts': 5840,  # 패킷에 따라 계산 필요
    'Fwd Act Data Pkts': 1,  # 전송한 데이터 패킷
    'Fwd Seg Size Min': 0,
    'Active Mean': 0,  # 필요시 계산
    'Active Std': 0,
    'Active Max': 0,
    'Active Min': 0,
    'Idle Mean': 0,  # 필요시 계산
    'Idle Std': 0,
    'Idle Max': 0,
    'Idle Min': 0
}

normal_pkt_data = {
    'Src Port': 6553,
    'Dst Port': 8888,
    'Protocol': 6,
    'Timestamp': '2024-10-02 17:40:04',
    'Flow Duration': 0.0,
    'Flow Byts/s': 0,
    'Flow Pkts/s': 0,
    'Fwd Pkts/s': 0,
    'Bwd Pkts/s': 0,
    'Tot Fwd Pkts': 1,
    'Tot Bwd Pkts': 0,
    'TotLen Fwd Pkts': 60,
    'TotLen Bwd Pkts': 0,
    'Fwd Pkt Len Max': 60,
    'Fwd Pkt Len Min': 60,
    'Fwd Pkt Len Mean': 60.0,
    'Fwd Pkt Len Std': 0.0,
    'Bwd Pkt Len Max': 0,
    'Bwd Pkt Len Min': 0,
    'Bwd Pkt Len Mean': 0,
    'Bwd Pkt Len Std': 0.0,
    'Pkt Len Max': 60,
    'Pkt Len Min': 60,
    'Pkt Len Mean': 60.0,
    'Pkt Len Std': 0.0,
    'Pkt Len Var': 0.0,
    'Fwd Header Len': 20,
    'Bwd Header Len': 0,
    'Fwd Seg Size Min': 20,
    'Fwd Act Data Pkts': 1,
    'Flow IAT Mean': 0,
    'Flow IAT Max': 0,
    'Flow IAT Min': 0,
    'Flow IAT Std': 0,
    'Fwd IAT Tot': 0,
    'Fwd IAT Max': 0,
    'Fwd IAT Min': 0,
    'Fwd IAT Mean': 0,
    'Fwd IAT Std': 0,
    'Bwd IAT Tot': 0,
    'Bwd IAT Max': 0,
    'Bwd IAT Min': 0,
    'Bwd IAT Mean': 0,
    'Bwd IAT Std': 0,
    'Fwd PSH Flags': 0,
    'Bwd PSH Flags': 0,
    'Fwd URG Flags': 0,
    'Bwd URG Flags': 0,
    'FIN Flag Cnt': 0,
    'SYN Flag Cnt': 1,
    'RST Flag Cnt': 0,
    'PSH Flag Cnt': 0,
    'ACK Flag Cnt': 0,
    'URG Flag Cnt': 0,
    'ECE Flag Cnt': 0,
    'CWE Flag Count': 0,
    'Down/Up Ratio': 0.0,
    'Pkt Size Avg': 60.0,
    'Init Fwd Win Byts': 512,
    'Init Bwd Win Byts': 0,
    'Active Max': 0,
    'Active Min': 0,
    'Active Mean': 0,
    'Active Std': 0,
    'Idle Max': 0,
    'Idle Min': 0,
    'Idle Mean': 0,
    'Idle Std': 0,
    'Fwd Byts/b Avg': 0,
    'Fwd Pkts/b Avg': 0,
    'Bwd Byts/b Avg': 0,
    'Bwd Pkts/b Avg': 0,
    'Fwd Blk Rate Avg': 0,
    'Bwd Blk Rate Avg': 0,
    'Fwd Seg Size Avg': 60.0,
    'Bwd Seg Size Avg': 0,
    'CWR Flag Count': 0,
    'Subflow Fwd Pkts': 1,
    'Subflow Bwd Pkts': 0,
    'Subflow Fwd Byts': 60,
    'Subflow Bwd Byts': 0
}


def predict_model(pkt_data):
    # pandas DataFrame으로 변환
    df = pd.DataFrame([pkt_data])

    # 피처 순서 맞추기 (모델에서 학습한 피처 순서에 맞춰야 함)
    df = df[feature_columns]  # feature_columns에 따라 열을 정렬

    # # 스케일링 처리 (필요에 따라 스케일링)
    scaler = StandardScaler()
    df_scaled = scaler.fit_transform(df)

    # 다시 DataFrame으로 변환하여 피처 이름 복원
    df_scaled = pd.DataFrame(df, columns=feature_columns)

    prediction = model.predict(df_scaled)
    if prediction == 1:
        print("[!] DDoS 공격 탐지")
    else:
        print("정상 트래픽")


predict_model(ddos_pkt_data)
predict_model(normal_pkt_data)