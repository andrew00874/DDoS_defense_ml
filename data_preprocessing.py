import dask.dataframe as dd
import joblib
import numpy as np
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split

# CSV 파일 로드
# Dask를 사용한 데이터 로드
file_path = 'final_dataset.csv'
df = dd.read_csv(file_path)
df = df.compute()  # Dask 데이터프레임을 pandas 데이터프레임으로 변환

# 데이터 샘플링 (예: 10% 샘플링)
df = df.sample(frac=0.1, random_state=42)  # 데이터의 10%만 사용

# 불필요한 열 제거
df = df.drop(['Unnamed: 0', 'Flow ID', 'Src IP', 'Src Port', 'Dst IP', 'Dst Port', 'Timestamp'], axis=1)

# Label 열을 숫자로 변환 (ddos -> 1, 정상 -> 0)
df['Label'] = df['Label'].map({'ddos': 1, 'Benign': 0})

# 결측값 처리
df = df.fillna(0)

# 무한대 값과 너무 큰 값 처리
df.replace([np.inf, -np.inf], np.nan, inplace=True)  # 무한대를 NaN으로 바꿈
df = df.fillna(df.median())  # NaN 값을 각 열의 최대값으로 대체

# 특성과 레이블 나누기
X = df.drop('Label', axis=1)
y = df['Label']

# 학습 데이터와 테스트 데이터로 분리
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Gradient Boosting 모델
model = GradientBoostingClassifier()

# 모델 학습
model.fit(X_train, y_train)

# 테스트 데이터에 대한 예측
y_pred = model.predict(X_test)

# 모델 평가
print("혼동 행렬 (Confusion Matrix):")
print(confusion_matrix(y_test, y_pred))

print("\n분류 보고서 (Classification Report):")
print(classification_report(y_test, y_pred))

# 모델과 피처 목록 함께 저장
model_data = {
    'model': model,
    'features': X_train.columns.tolist()  # 사용된 피처 목록 저장
}

joblib.dump(model_data, 'ddos_sgb_model_with_features.pkl')