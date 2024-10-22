import pandas as pd

# CSV 파일 로드
file_path = 'final_dataset.csv'  # 파일 경로를 지정하세요
df = pd.read_csv(file_path)

# 데이터의 기본 정보 확인
print("데이터셋의 기본 정보:")
print(df.info())  # 데이터 타입 및 널 값 확인

# 데이터셋의 상위 5개 행 확인
print("\n데이터셋의 상위 5개 행:")
print(df.head())  # 상위 5개 데이터 미리보기

# 데이터셋의 통계 요약 확인
print("\n데이터셋의 통계 요약:")
print(df.describe())  # 수치형 데이터의 통계 정보 제공

# 결측값 확인
print("\n각 열의 결측값 개수:")
print(df.isnull().sum())