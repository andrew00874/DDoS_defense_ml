import time

import joblib
import numpy as np
import pandas as pd
import scapy.all as scapy

# 블록 크기 정의 (512 바이트로 설정)
BLOCK_SIZE = 512

# 모델과 피처 목록 불러오기
model_data = joblib.load('ddos_random_forest_model_with_features.pkl')
model = model_data['model']
feature_columns = model_data['features']

flow_stats = {}


# IAT 계산 함수 (Fwd 및 Bwd)
def calculate_iat(flow_dir, direction):
    packet_times = flow_dir[f'Packet Times {direction.capitalize()}']
    if len(packet_times) > 1:
        iat_list = np.diff(packet_times)  # 패킷 간 시간 차이 계산
        iat_tot = np.sum(iat_list)
        iat_mean = np.mean(iat_list)
        iat_std = np.std(iat_list)
        iat_max = np.max(iat_list)
        iat_min = np.min(iat_list)
        return iat_tot, iat_mean, iat_std, iat_max, iat_min
    return 0, 0, 0, 0, 0  # 패킷이 1개 이하일 경우


# Active 및 Idle 통계 계산 함수
def calculate_active_idle(flow_dir):
    active_times = flow_dir.get('Active Times', [])
    idle_times = flow_dir.get('Idle Times', [])

    # Active 시간 통계 계산
    if active_times:
        active_mean = np.mean(active_times)
        active_std = np.std(active_times)
        active_max = np.max(active_times)
        active_min = np.min(active_times)
    else:
        active_mean = active_std = active_max = active_min = 0

    # Idle 시간 통계 계산
    if idle_times:
        idle_mean = np.mean(idle_times)
        idle_std = np.std(idle_times)
        idle_max = np.max(idle_times)
        idle_min = np.min(idle_times)
    else:
        idle_mean = idle_std = idle_max = idle_min = 0

    return active_mean, active_std, active_max, active_min, idle_mean, idle_std, idle_max, idle_min


# 패킷 길이 통계 계산 함수
def calculate_pkt_len_stats(flow_dir):
    pkt_len_list = flow_dir.get('Pkt Len List', [])
    if pkt_len_list:
        pkt_len_min = np.min(pkt_len_list)
        pkt_len_max = np.max(pkt_len_list)
        pkt_len_mean = np.mean(pkt_len_list)
        pkt_len_std = np.std(pkt_len_list)
        pkt_len_var = np.var(pkt_len_list)
    else:
        pkt_len_min = pkt_len_max = pkt_len_mean = pkt_len_std = pkt_len_var = 0
    return pkt_len_min, pkt_len_max, pkt_len_mean, pkt_len_std, pkt_len_var


# 추가 피처 계산 함수
def calculate_additional_features(flow_dir):
    tot_fwd_pkts, tot_bwd_pkts = flow_dir.get('Tot Fwd Pkts', 0), flow_dir.get('Tot Bwd Pkts', 0)
    tot_len_fwd_pkts, tot_len_bwd_pkts = flow_dir.get('TotLen Fwd Pkts', 0), flow_dir.get('TotLen Bwd Pkts', 0)

    # Down/Up Ratio 계산
    down_up_ratio = (tot_len_bwd_pkts / tot_len_fwd_pkts) if tot_len_fwd_pkts > 0 else 0

    # 세그먼트 크기 평균 계산
    fwd_seg_size_avg = (tot_len_fwd_pkts / tot_fwd_pkts) if tot_fwd_pkts > 0 else 0
    bwd_seg_size_avg = (tot_len_bwd_pkts / tot_bwd_pkts) if tot_bwd_pkts > 0 else 0

    # 패킷 크기 평균
    pkt_size_avg = np.mean(flow_dir.get('Pkt Len List', [])) if flow_dir.get('Pkt Len List', []) else 0

    # 블록당 바이트 및 패킷 평균 (512바이트 블록 기준)
    fwd_byts_per_blk = (tot_len_fwd_pkts / BLOCK_SIZE) if BLOCK_SIZE > 0 else 0
    fwd_pkts_per_blk = (tot_fwd_pkts / BLOCK_SIZE) if BLOCK_SIZE > 0 else 0
    bwd_byts_per_blk = (tot_len_bwd_pkts / BLOCK_SIZE) if BLOCK_SIZE > 0 else 0
    bwd_pkts_per_blk = (tot_bwd_pkts / BLOCK_SIZE) if BLOCK_SIZE > 0 else 0

    return down_up_ratio, pkt_size_avg, fwd_seg_size_avg, bwd_seg_size_avg, fwd_byts_per_blk, fwd_pkts_per_blk, bwd_byts_per_blk, bwd_pkts_per_blk


def preprocess_packet(packet):
    global flow_stats
    if scapy.IP in packet and scapy.TCP in packet:
        flow_id = (packet[scapy.IP].src, packet[scapy.TCP].sport, packet[scapy.IP].dst, packet[scapy.TCP].dport)
        # flow_id = (packet[scapy.IP].src, packet[scapy.IP].dst)
        reverse_flow_id = (packet[scapy.IP].dst, packet[scapy.TCP].dport, packet[scapy.IP].src, packet[scapy.TCP].sport)
        # reverse_flow_id = (packet[scapy.IP].dst, packet[scapy.IP].src)
        current_time = packet.time

        if flow_id not in flow_stats and reverse_flow_id not in flow_stats:
            if scapy.TCP in packet and packet[scapy.TCP].flags.F:
                return None  # 첫 번째 패킷이며 FIN 패킷이 없는 경우 무시

            flow_stats[flow_id] = {
                'Tot Fwd Pkts': 0, 'Tot Bwd Pkts': 0,
                'TotLen Fwd Pkts': 0, 'TotLen Bwd Pkts': 0,
                'Fwd Pkt Len List': [], 'Bwd Pkt Len List': [],
                'Packet Times Fwd': [], 'Packet Times Bwd': [],
                'Pkt Len List': [],  # 전체 패킷 길이 리스트 추가
                'Fwd PSH Flags': 0, 'Bwd PSH Flags': 0,
                'Fwd URG Flags': 0, 'Bwd URG Flags': 0,
                'Fwd Header Len': 0, 'Bwd Header Len': 0,
                'FIN Flag Cnt': 0, 'SYN Flag Cnt': 0, 'RST Flag Cnt': 0,
                'PSH Flag Cnt': 0, 'ACK Flag Cnt': 0, 'URG Flag Cnt': 0,
                'CWE Flag Count': 0, 'ECE Flag Cnt': 0,  # Placeholder 플래그
                'Flow Start Time': current_time, 'Flow End Time': current_time,
                'Active Times': [], 'Idle Times': []
            }
        flow_dir = flow_stats[flow_id] if flow_id in flow_stats else flow_stats[reverse_flow_id]
        direction = "fwd" if flow_id in flow_stats else "bwd"

        packet_len = len(packet)

        # 패킷 길이 리스트 업데이트
        flow_dir['Pkt Len List'].append(packet_len)

        # TCP 플래그 업데이트
        if packet.haslayer(scapy.TCP):
            tcp_flags = packet[scapy.TCP].flags
            flow_dir['FIN Flag Cnt'] += 1 if tcp_flags & 0x01 else 0
            flow_dir['SYN Flag Cnt'] += 1 if tcp_flags & 0x02 else 0
            flow_dir['RST Flag Cnt'] += 1 if tcp_flags & 0x04 else 0
            flow_dir['PSH Flag Cnt'] += 1 if tcp_flags & 0x08 else 0
            flow_dir['ACK Flag Cnt'] += 1 if tcp_flags & 0x10 else 0
            flow_dir['URG Flag Cnt'] += 1 if tcp_flags & 0x20 else 0

        # PSH 및 URG 플래그 카운트
        if direction == 'fwd':
            if packet.haslayer(scapy.TCP):
                flow_dir['Fwd PSH Flags'] += 1 if tcp_flags & 0x08 else 0
                flow_dir['Fwd URG Flags'] += 1 if tcp_flags & 0x20 else 0
            flow_dir['Fwd Header Len'] += len(packet[scapy.IP]) if packet.haslayer(scapy.IP) else 0
            flow_dir['Tot Fwd Pkts'] += 1
            flow_dir['TotLen Fwd Pkts'] += packet_len
            flow_dir['Fwd Pkt Len List'].append(packet_len)
            flow_dir['Packet Times Fwd'].append(current_time)
        else:
            if packet.haslayer(scapy.TCP):
                flow_dir['Bwd PSH Flags'] += 1 if tcp_flags & 0x08 else 0
                flow_dir['Bwd URG Flags'] += 1 if tcp_flags & 0x20 else 0
            flow_dir['Bwd Header Len'] += len(packet[scapy.IP]) if packet.haslayer(scapy.IP) else 0
            flow_dir['Tot Bwd Pkts'] += 1
            flow_dir['TotLen Bwd Pkts'] += packet_len
            flow_dir['Bwd Pkt Len List'].append(packet_len)
            flow_dir['Packet Times Bwd'].append(current_time)

        # Idle 및 Active Time 업데이트
        flow_dir['Flow End Time'] = current_time

        # Check if flow should be terminated
        if scapy.TCP in packet and (packet[scapy.TCP].flags.F or current_time - flow_dir['Flow Start Time'] > 120):
            return finalize_flow(flow_id, packet)

        return None


def finalize_flow(flow_id, packet):
    if flow_id not in flow_stats:
        return  # TODO 예외처리

    flow_dir = flow_stats.pop(flow_id)

    # IAT 계산
    fwd_iat_tot, fwd_iat_mean, fwd_iat_std, fwd_iat_max, fwd_iat_min = calculate_iat(flow_dir, 'Fwd')
    bwd_iat_tot, bwd_iat_mean, bwd_iat_std, bwd_iat_max, bwd_iat_min = calculate_iat(flow_dir, 'Bwd')

    # Active 및 Idle 통계 계산
    active_mean, active_std, active_max, active_min, idle_mean, idle_std, idle_max, idle_min = calculate_active_idle(flow_dir)

    # 패킷 길이 통계 계산
    pkt_len_min, pkt_len_max, pkt_len_mean, pkt_len_std, pkt_len_var = calculate_pkt_len_stats(flow_dir)

    # 추가 피처 계산
    down_up_ratio, pkt_size_avg, fwd_seg_size_avg, bwd_seg_size_avg, fwd_byts_per_blk, fwd_pkts_per_blk, bwd_byts_per_blk, bwd_pkts_per_blk = calculate_additional_features(flow_dir)

    # flow_id가 존재하지 않을 경우 빈 리스트로 기본값 제공
    def get_pkt_len_stats(direction):
        pkt_list = flow_dir.get(f'{direction.capitalize()} Pkt Len List', [])
        return (max(pkt_list, default=0), min(pkt_list, default=0), np.mean(pkt_list) if pkt_list else 0,
                np.std(pkt_list) if pkt_list else 0)

    fwd_max, fwd_min, fwd_mean, fwd_std = get_pkt_len_stats('fwd')
    bwd_max, bwd_min, bwd_mean, bwd_std = get_pkt_len_stats('bwd')

    tot_fwd_pkts, tot_bwd_pkts = flow_dir.get('Tot Fwd Pkts', 0), flow_dir.get('Tot Bwd Pkts', 0)
    tot_len_fwd_pkts, tot_len_bwd_pkts = flow_dir.get('TotLen Fwd Pkts', 0), flow_dir.get('TotLen Bwd Pkts', 0)
    flow_duration = (flow_dir.get('Flow End Time', 0) - flow_dir.get('Flow Start Time', 0)) * 1000
    flow_byts_per_s = (tot_len_fwd_pkts + tot_len_bwd_pkts) / flow_duration if flow_duration > 0 else 0
    flow_fwd_pkts_per_s = tot_fwd_pkts / flow_duration if flow_duration > 0 else 0
    flow_bwd_pkts_per_s = tot_bwd_pkts / flow_duration if flow_duration > 0 else 0

    pkt_data = {
        'Src Port': packet[scapy.TCP].sport, 'Dst Port': packet[scapy.TCP].dport,
        'Protocol': packet[scapy.IP].proto, 'Flow Duration': flow_duration,
        'Tot Fwd Pkts': tot_fwd_pkts, 'Tot Bwd Pkts': tot_bwd_pkts,
        'TotLen Fwd Pkts': tot_len_fwd_pkts, 'TotLen Bwd Pkts': tot_len_bwd_pkts,
        'Fwd Pkt Len Max': fwd_max, 'Fwd Pkt Len Min': fwd_min, 'Fwd Pkt Len Mean': fwd_mean, 'Fwd Pkt Len Std': fwd_std,
        'Bwd Pkt Len Max': bwd_max, 'Bwd Pkt Len Min': bwd_min, 'Bwd Pkt Len Mean': bwd_mean, 'Bwd Pkt Len Std': bwd_std,
        'Flow Byts/s': flow_byts_per_s, 'Fwd Pkts/s': flow_fwd_pkts_per_s, 'Bwd Pkts/s': flow_bwd_pkts_per_s,
        'Fwd IAT Tot': fwd_iat_tot, 'Fwd IAT Mean': fwd_iat_mean, 'Fwd IAT Std': fwd_iat_std,
        'Fwd IAT Max': fwd_iat_max, 'Fwd IAT Min': fwd_iat_min,
        'Bwd IAT Tot': bwd_iat_tot, 'Bwd IAT Mean': bwd_iat_mean, 'Bwd IAT Std': bwd_iat_std,
        'Bwd IAT Max': bwd_iat_max, 'Bwd IAT Min': bwd_iat_min,
        'Active Mean': active_mean, 'Active Std': active_std, 'Active Max': active_max, 'Active Min': active_min,
        'Idle Mean': idle_mean, 'Idle Std': idle_std, 'Idle Max': idle_max, 'Idle Min': idle_min,
        'Fwd PSH Flags': flow_dir.get('Fwd PSH Flags', 0), 'Bwd PSH Flags': flow_dir.get('Bwd PSH Flags', 0),
        'Fwd URG Flags': flow_dir.get('Fwd URG Flags', 0), 'Bwd URG Flags': flow_dir.get('Bwd URG Flags', 0),
        'Fwd Header Len': flow_dir.get('Fwd Header Len', 0), 'Bwd Header Len': flow_dir.get('Bwd Header Len', 0),
        'FIN Flag Cnt': flow_dir.get('FIN Flag Cnt', 0), 'SYN Flag Cnt': flow_dir.get('SYN Flag Cnt', 0),
        'RST Flag Cnt': flow_dir.get('RST Flag Cnt', 0), 'PSH Flag Cnt': flow_dir.get('PSH Flag Cnt', 0),
        'ACK Flag Cnt': flow_dir.get('ACK Flag Cnt', 0), 'URG Flag Cnt': flow_dir.get('URG Flag Cnt', 0),
        'CWE Flag Count': flow_dir.get('CWE Flag Count', 0), 'ECE Flag Cnt': flow_dir.get('ECE Flag Cnt', 0),
        'Pkt Len Min': pkt_len_min, 'Pkt Len Max': pkt_len_max, 'Pkt Len Mean': pkt_len_mean,
        'Pkt Len Std': pkt_len_std, 'Pkt Len Var': pkt_len_var,
        'Down/Up Ratio': down_up_ratio, 'Pkt Size Avg': pkt_size_avg,
        'Fwd Seg Size Avg': fwd_seg_size_avg, 'Bwd Seg Size Avg': bwd_seg_size_avg,
        'Fwd Byts/b Avg': fwd_byts_per_blk, 'Fwd Pkts/b Avg': fwd_pkts_per_blk, 'Fwd Blk Rate Avg': fwd_pkts_per_blk,
        'Bwd Byts/b Avg': bwd_byts_per_blk, 'Bwd Pkts/b Avg': bwd_pkts_per_blk, 'Bwd Blk Rate Avg': bwd_pkts_per_blk
    }
    
    # Store or process pkt_data as needed (e.g., save to CSV)
    # print(pkt_data)
    return pd.DataFrame([pkt_data], columns=feature_columns)


# # Sniff packets and process
# scapy.sniff(prn=preprocess_packet, filter="ip")
