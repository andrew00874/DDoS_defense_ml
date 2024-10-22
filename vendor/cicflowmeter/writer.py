import csv
import os
import sys
from typing import Protocol

import joblib
import pandas as pd
import requests
from sklearn.preprocessing import StandardScaler

current_project_directory = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(current_project_directory)

from module.firewall import get_firewall

if getattr(sys, 'frozen', False):
    # PyInstaller로 패키징된 경우
    base_path = sys._MEIPASS
else:
    # 개발 환경에서 실행되는 경우
    base_path = os.path.abspath(".")

model_path = os.path.join(base_path, 'ddos_random_forest_model_with_features.pkl')

# 모델과 피처 목록 불러오기
model_data = joblib.load(model_path)
model = model_data['model']
feature_columns = model_data['features']  # 자동으로 피처 목록을 불러옴


class OutputWriter(Protocol):
    def write(self, data: dict) -> None:
        raise NotImplementedError


class StdoutWriter(OutputWriter):
    def write(self, data: dict) -> None:
        print(data)


class DDosVerifiWriter(OutputWriter):
    def write(self, data: dict) -> None:
        # pandas DataFrame으로 변환
        df = pd.DataFrame([data])

        # 피처 순서 맞추기 (모델에서 학습한 피처 순서에 맞춰야 함)
        df = df[feature_columns]  # feature_columns에 따라 열을 정렬

        # 스케일링 처리 (필요에 따라 스케일링)
        scaler = StandardScaler()
        df_scaled = scaler.fit_transform(df)

        # 다시 DataFrame으로 변환하여 피처 이름 복원
        df_scaled = pd.DataFrame(df, columns=feature_columns)
        prediction = model.predict(df_scaled)
        if prediction == 1 or (data["Flow Duration"] == 0.0 and data["Protocol"] == 6):
            print("[!] DDoS 공격 탐지 : src ip: %s, src port: %s, dst ip: %s, dst port: %s" % (data["Src IP"], data["Src Port"], data["Dst IP"], data["Dst Port"]))
            print(f"src IP를 차단합니다... {data['Src IP']}")
            firewall = get_firewall()
            firewall.block_ip(data["Src IP"])
        else:
            print("정상 트래픽 : src ip: %s, src port: %s, dst ip: %s, dst port: %s" % (data["Src IP"], data["Src Port"], data["Dst IP"], data["Dst Port"]))


class CSVWriter(OutputWriter):
    def __init__(self, output_file) -> None:
        self.file = open(output_file, "w")
        self.line = 0
        self.writer = csv.writer(self.file)

    def write(self, data: dict) -> None:
        if self.line == 0:
            self.writer.writerow(data.keys())

        self.writer.writerow(data.values())
        self.file.flush()
        self.line += 1

    def __del__(self):
        self.file.close()


class HttpWriter(OutputWriter):
    def __init__(self, output_url) -> None:
        self.url = output_url
        self.session = requests.Session()

    def write(self, data: dict) -> None:
        self.session.post(self.url, json=data)

    def __del__(self):
        self.session.close()


def output_writer_factory(output_mode, output) -> OutputWriter:
    match output_mode:
        case "url":
            return HttpWriter(output)
        case "csv":
            return CSVWriter(output)
        case "stdout":
            return StdoutWriter()
        case "ddos_verifi":
            return DDosVerifiWriter()
        case _:
            raise RuntimeError("no output_mode provided")
