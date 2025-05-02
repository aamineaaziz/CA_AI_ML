import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder
from sklearn.feature_selection import SelectKBest, f_classif
from sklearn.preprocessing import StandardScaler
from sklearn.impute import SimpleImputer
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense
from tensorflow.keras.metrics import AUC
from sklearn.metrics import roc_curve, auc
from imblearn.over_sampling import SMOTE
from sklearn.ensemble import RandomForestClassifier
import shap
import matplotlib.pyplot as plt

f1 = pd.read_csv('/kaggle/input/network-intrusion-dataset/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv')
# f2 = pd.read_csv('/kaggle/input/network-intrusion-dataset/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv')
# f3 = pd.read_csv('/kaggle/input/network-intrusion-dataset/Friday-WorkingHours-Morning.pcap_ISCX.csv')
# f4 = pd.read_csv('/kaggle/input/network-intrusion-dataset/Monday-WorkingHours.pcap_ISCX.csv')
# f5 = pd.read_csv('/kaggle/input/network-intrusion-dataset/Monday-WorkingHours.pcap_ISCX.csv')
# f6 = pd.read_csv('/kaggle/input/network-intrusion-dataset/Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv')
# f7 = pd.read_csv('/kaggle/input/network-intrusion-dataset/Tuesday-WorkingHours.pcap_ISCX.csv')
# f8 = pd.read_csv('/kaggle/input/network-intrusion-dataset/Wednesday-workingHours.pcap_ISCX.csv')

combine_df = pd.concat([f1], ignore_index=True)
combine_df.head()

combine_df.tail()
combine_df.columns
combine_df[' Label'].value_countencoder = LabelEncoder()
combine_df[' Label']= encoder.fit_transform(combine_df[' Label'])s().sum
combine_df.head()

df = combine_df.fillna(0)  # Replace NaN with 0
df

nan_mask = df.isna()
print("NaNs in DataFrame:\n", df[nan_mask].sum())

inf_mask = df.isin([np.inf, -np.inf])
print("Infs in DataFrame:\n", df[inf_mask].sum())

df.replace([np.inf, -np.inf], np.nan, inplace=True)  # Replace infinities with NaN
df.fillna(0, inplace=True)  # Replace NaNs with 0

df.replace([np.inf, -np.inf], np.nan, inplace=True)  # Replace infinities with NaN
df.dropna(inplace=True)

df=df.astype(int)
df

X = df.drop(' Label',axis=1)
y = df[' Label']

scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

new_columns=[' Destination Port', ' Bwd Packet Length Min',
       ' Bwd Packet Length Mean', ' Bwd Packets/s', ' Min Packet Length',
       ' PSH Flag Count', ' URG Flag Count', ' Avg Fwd Segment Size',
       ' Avg Bwd Segment Size', ' min_seg_size_forward']

df_new=X[new_columns]
df_new

df_new['label']=df[' Label']
df_new['label']
X1=df_new.iloc[:,:-1].values
y1=df_new.iloc[:,-1].values

X_train, X_test, y_train, y_test = train_test_split(X1, y1, test_size=0.3, random_state=42)
# Scale numerical features
numerical_cols = X.select_dtypes(include=['int64', 'float64']).columns
X[numerical_cols] = scaler.fit_transform(X[numerical_cols])

#this wasnt possible with those DataSets
smote = SMOTE(random_state=42)
X_smote, y_smote = smote.fit_resample(X, y)


LR_model = LogisticRegression()

# Train the model
LR_model.fit(X_train, y_train)

LR_y_pred = LR_model.predict(X_test)

LR_y_prob = LR_model.decision_function(X_test)

LR_roc_auc = roc_auc_score(y_test, LR_y_prob)
print(f'ROC-AUC Score: {LR_roc_auc:.2f}')
