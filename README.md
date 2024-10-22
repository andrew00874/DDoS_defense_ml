# 네트워크 트래픽 분석 및 DDoS 탐지 시스템

이 프로젝트는 네트워크 트래픽을 실시간으로 캡처하고 분석하여 DDoS 공격을 탐지하는 시스템입니다. Scapy를 사용하여 패킷을 캡처하고, 머신러닝 모델을 통해 트래픽을 분석합니다. DDoS 공격이 탐지되면, 방화벽을 통해 공격 IP를 차단합니다.

## 주요 기능

- **실시간 패킷 캡처**: 네트워크 인터페이스에서 실시간으로 패킷을 캡처합니다.
- **트래픽 분석**: 캡처된 패킷을 분석하여 다양한 네트워크 플로우 특징을 추출합니다.
- **DDoS 탐지**: 머신러닝 모델을 사용하여 DDoS 공격을 탐지합니다.
- **자동 IP 차단**: DDoS 공격이 탐지되면, 해당 IP를 방화벽을 통해 자동으로 차단합니다.

### DDos 공격 탐지 알고리즘
DDoS 공격 탐지 알고리즘은 머신러닝 모델을 기반으로 하며, 주로 랜덤 포레스트(Random Forest) 알고리즘 혹은 SGB 모델을 사용합니다. 머신러닝 모델은 사전에 학습된 모델을 사용하며, 학습 데이터는 CICIDS 2017-2018 데이터셋을 사용합니다.

트래픽을 실시간 분석하여, CICIDS 데이터 셋과 동일한 유형의 데이터를 생성하여, 머신러닝 모델을 통해 DDoS 공격을 탐지합니다.


## 주의 사항
- **관리자 권한으로 실행 필요**: 패킷 스니핑과 방화벽 제어를 위해 관리자 권한이 필요합니다.
- **Npcap 설치 (Windows)**: Windows에서 패킷 캡처를 위해 Npcap을 설치해야 합니다. (하단의 사전 요구 사항 참조)
- **트래픽 패턴 수집 필요**: 머신러닝 모델을 학습시키기 위해서는 트래픽 패턴을 수집해야 합니다. 이 작업에는 4분~5분 정도의 시간이 소요됩니다.

## 설치 및 실행 방법

### 사전 요구 사항

- Python 3.12.x
- Npcap 설치 (Windows의 경우) [다운로드 링크](https://npcap.com/#download)

### 설치

1. 프로젝트를 클론하거나, 프로젝트 압축 파일을 다운로드 후 압축을 해제합니다.

```bash
git clone https://github.com/andrew00874/DDoS_defense_ml
cd ddos-defense-ml
```

2. (선택) 가상 환경을 생성합니다.

```bash
python -m venv venv
source venv/bin/activate
```

3. 필요한 패키지를 설치합니다.

```bash
pip install -r requirements.txt
```

### 모델 학습 방법

1. final_dataset.csv 파일을 준비합니다. [이 데이터셋](https://www.kaggle.com/datasets/devendra416/ddos-datasets/data)에서 구할 수 있습니다.

2. 데이터 전처리를 위해 다음 명령어를 실행합니다.
```bash
python data_preprocessing.py
```

### 테스트 방법 (hping3)

공격자 PC와 피해자 PC를 준비한 후, DDoS 공격을 시뮬레이션합니다.

1. (피해자) python을 사용해서 web server를 실행합니다.

```bash
python -m http.server 8888 --bind 0.0.0.0
```

2. (공격자) curl을 이용해서 피해자 PC에 접속되는지 확인합니다.

```bash
curl <target ip>:8888
```

3. (공격자) hping3를 설치합니다.

```bash
sudo apt-get install hping3
```

4. (피해자) DDos 방어 프로그램을 실행한 후, DDoS 공격을 시뮬레이션하기 위해 다음 명령어를 실행합니다.

```bash
sudo hping3 -S <target ip> -p 8888 --flood
```

5. (피해자) DDoS 공격이 탐지되면, 해당 IP가 방화벽에 의해 차단됩니다. 방화벽에 의해 차단된 IP를 확인하려면 Powershell을 관리자 권한으로 실행 후 다음 명령어를 실행합니다.

```bash
netsh advfirewall firewall show rule name=all
```

6. (공격자) DDoS 공격이 차단되었는지 확인합니다.

```bash
curl <target ip>:8888
```

7. (피해자) 테스트 종료 후 차단된 방화벽을 해제하려면 다음 명령어를 실행합니다.

```bash
netsh advfirewall firewall delete rule name="Block IP <attacker ip> remoteip=<attacker ip>"
```


## 코드 구조

- `main.py`: 프로그램의 진입점으로, 패킷 캡처 및 분석을 시작합니다.
- `vendor/cicflowmeter/`: 패킷 캡처 및 네트워크 플로우 분석을 위한 모듈입니다.
- `module/firewall.py`: 플랫폼별 방화벽 제어를 위한 모듈입니다.
- `data_preprocessing.py`: 머신러닝 모델을 학습시키기 위한 데이터 전처리 코드입니다.

## 윈도우 실행파일 패키징 방법
    
```bash
pyinstaller main.spec
```

## 참고 링크
- [학습에 사용된 데이터셋](https://www.kaggle.com/datasets/devendra416/ddos-datasets/data)
- [관련 논문](https://www.ijcseonline.org/pdf_paper_view.php?paper_id=4011&28-IJCSE-06600.pdf)
- [cicflowmeter 패킷 분석 알고리즘 참고 소스](https://github.com/hieulw/cicflowmeter)
