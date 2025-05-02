#Disclaimer, many code lines were from a combination fo Kaggle sources


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
LR_conf_matrix = confusion_matrix(y_test, LR_y_pred)
df_conf_matrix = pd.DataFrame(LR_conf_matrix, index=['Actual Negative', 'Actual Positive'], columns=['Predicted Negative', 'Predicted Positive'])
print("Logistic Regresion Confusion Matrix:")
print(df_conf_matrix)

#randomforest
rf_model = RandomForestClassifier(n_estimators=100, random_state=42)  # You can adjust hyperparameters as needed

# Train the model
rf_model.fit(X_train, y_train)

# Predict class labels
rf_y_pred = rf_model.predict(X_test)

# Predict probabilities for ROC-AUC
rf_y_prob = rf_model.predict_proba(X_test)[:, 1]  # Assuming binary classification; for multiclass, adjust accordingly
# Classification Report
print("Classification Report:")
print(classification_report(y_test, rf_y_pred))

# Confusion Matrix
rf_conf_matrix = confusion_matrix(y_test, rf_y_pred)
df_conf_matrix = pd.DataFrame(rf_conf_matrix, index=['Actual Negative', 'Actual Positive'], columns=['Predicted Negative', 'Predicted Positive'])
print("Random Forest Confusion Matrix:")
print(df_conf_matrix)


#DeepNeuralNetwork
dnn_model = Sequential()
dnn_model.add(Dense(128, input_dim=X_train.shape[1], activation='relu'))
dnn_model.add(Dense(64, activation='relu'))
dnn_model.add(Dense(32, activation='relu'))
dnn_model.add(Dense(1, activation='sigmoid'))


dnn_model.compile(optimizer='Amine', loss='binary_crossentropy', metrics=['accuracy', AUC()])

history = dnn_model.fit(X_train, y_train, epochs=100, batch_size=32, validation_split=0.2, verbose=1)

dnn_y_pred = (dnn_model.predict(X_test) > 0.5).astype(int)
dnn_y_prob = dnn_model.predict(X_test).ravel()  # Flatten array for binary classification

# Classification Report
print("Classification Report:")
print(classification_report(y_test, dnn_y_pred))
# ROC-AUC Score
dnn_roc_auc = roc_auc_score(y_test, dnn_y_prob)
print(f'ROC-AUC Score: {dnn_roc_auc:.2f}')
dnn_conf_matrix = confusion_matrix(y_test, dnn_y_pred)
df_conf_matrix = pd.DataFrame(dnn_conf_matrix, index=['Actual Negative', 'Actual Positive'], columns=['Predicted Negative', 'Predicted Positive'])
print("Deep learning Confusion Matrix:")
print(df_conf_matrix)



# Define predictions and true values (Replace these with your actual data)
models = {
    'Logistic Regresion': LR_model,
    'Random Forest': rf_model
}

y_probs = {
    'Logistic Regresion': LR_y_prob,
    'Random Forest': rf_y_prob
}

# Plot ROC Curves
def plot_roc_curves(models, y_test, y_probs):
    plt.figure(figsize=(10, 6))
    
    for label, y_prob in y_probs.items():
        fpr, tpr, _ = roc_curve(y_test, y_prob)
        roc_auc = auc(fpr, tpr)
        plt.plot(fpr, tpr, lw=2, label=f'ROC curve ({label}) (area = {roc_auc:.2f})')
    
    plt.plot([0, 1], [0, 1], 'k--')
    plt.xlim([0.0, 1.0])
    plt.ylim([0.0, 1.05])
    plt.xlabel('False Positive Rate')
    plt.ylabel('True Positive Rate')
    plt.title('Receiver Operating Characteristic (ROC)')
    plt.legend(loc="lower right")
    plt.show()

# Plot Confusion Matrices
def plot_confusion_matrices(models, X_test, y_test):
    for label, model in models.items():
        y_pred = model.predict(X_test)  # Get predictions from the model
        cm = confusion_matrix(y_test, y_pred)
        
        plt.figure(figsize=(8, 6))
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
                    xticklabels=['Negative', 'Positive'], 
                    yticklabels=['Negative', 'Positive'])
        plt.title(f'Confusion Matrix for {label}')
        plt.xlabel('Predicted')
        plt.ylabel('True')
        plt.show()
# Call the functions with your data
plot_roc_curves(models, y_test, y_probs)
plot_confusion_matrices(models, X_test, y_test)

plt.figure(figsize=(8, 6))
sns.heatmap(dnn_conf_matrix, annot=True, fmt='d', cmap='Blues',
            xticklabels=['Negative', 'Positive'],
            yticklabels=['Negative', 'Positive'])
plt.title('Confusion Matrix for Deep learning')
plt.xlabel('Predicted')
plt.ylabel('True')
plt.show()

def compute_metrics(y_true, y_pred):
    report = classification_report(y_true, y_pred, output_dict=True)
    metrics = {
        'accuracy': report['accuracy'],
        'precision': report['weighted avg']['precision'],
        'recall': report['weighted avg']['recall'],
        'f1_score': report['weighted avg']['f1-score']
    }
    return metrics

def prepare_metrics_df(metrics_dict):
    df = pd.DataFrame(metrics_dict).T
    df.reset_index(inplace=True)
    df.rename(columns={'index': 'Model'}, inplace=True)
    return df

import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
from sklearn.metrics import classification_report

y_pred_model1 = LR_y_pred
y_pred_model2 = rf_y_pred
y_pred_model3 = dnn_y_pred

# Compute metrics
metrics_model1 = compute_metrics(y_test, y_pred_model1)
metrics_model2 = compute_metrics(y_test, y_pred_model2)
metrics_model3 = compute_metrics(y_test, y_pred_model3)

# Prepare metrics for plotting
metrics_dict = {
    'Logistic Regresion': metrics_model1,
    'Random Forest': metrics_model2,
    'Deep learning': metrics_model3
}
metrics_df = prepare_metrics_df(metrics_dict)

# Plot the metrics
plt.figure(figsize=(12, 8))

# Plot Accuracy, Precision, Recall, and F1-Score
metrics_df.set_index('Model').plot(kind='bar', figsize=(12, 8), rot=45)
plt.title('Comparison of Models')
plt.ylabel('Score')
plt.xlabel('Model')
plt.ylim(0, 1)  # Assuming all metrics are normalized between 0 and 1
plt.legend(loc='best')
plt.grid(axis='y')
plt.show()



