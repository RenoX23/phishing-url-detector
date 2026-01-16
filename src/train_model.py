import pandas as pd
import numpy as np
import joblib
import os
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report, roc_auc_score
)
import matplotlib.pyplot as plt
import seaborn as sns

# ============================================================
# SETUP PATHS (ABSOLUTE PATHS TO AVOID CONFUSION)
# ============================================================
script_dir = os.path.dirname(os.path.abspath(__file__))
project_dir = os.path.dirname(script_dir)
models_dir = os.path.join(project_dir, 'models')
data_dir = os.path.join(project_dir, 'data', 'raw')

print("="*70)
print(" PATH VERIFICATION")
print("="*70)
print(f"Script directory: {script_dir}")
print(f"Project directory: {project_dir}")
print(f"Models directory: {models_dir}")
print(f"Data directory: {data_dir}")

# Create models directory
os.makedirs(models_dir, exist_ok=True)
print(f"\n✓ Models directory created/verified")
print(f"✓ Current contents: {os.listdir(models_dir)}")

print("\n" + "="*70)
print(" TRAINING PHISHING DETECTION MODEL")
print("="*70)

# Load data
dataset_path = os.path.join(data_dir, 'dataset_phishing.csv')
print(f"\nLoading dataset from: {dataset_path}")
df = pd.read_csv(dataset_path)

# Encode target
if df['status'].dtype == 'object':
    df['status'] = df['status'].map({'legitimate': 0, 'phishing': 1})

print(f"Dataset shape: {df.shape}")
print(f"Class distribution:\n{df['status'].value_counts()}")

# Features
url_features = [
    'length_url', 'length_hostname', 'ip', 'nb_dots', 'nb_hyphens',
    'nb_at', 'nb_qm', 'nb_and', 'nb_or', 'nb_eq', 'nb_underscore',
    'nb_tilde', 'nb_percent', 'nb_slash', 'nb_star', 'nb_colon',
    'nb_comma', 'nb_semicolumn', 'nb_dollar', 'nb_space', 'nb_www',
    'nb_com', 'nb_dslash', 'http_in_path', 'https_token',
    'ratio_digits_url', 'ratio_digits_host', 'punycode', 'port',
    'tld_in_path', 'tld_in_subdomain', 'abnormal_subdomain',
    'nb_subdomains', 'prefix_suffix', 'shortening_service',
    'path_extension', 'shortest_word_host', 'shortest_word_path',
    'longest_word_host', 'longest_word_path', 'avg_word_host',
    'avg_word_path'
]

# Prepare data
X = df[url_features].fillna(0).replace([np.inf, -np.inf], 0)
y = df['status']

print(f"\nFeatures: {X.shape[1]}")
print(f"Samples: {len(X)}")

# Split
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

print(f"Training set: {X_train.shape}")
print(f"Test set: {X_test.shape}")

# Train
print("\n" + "="*70)
print(" TRAINING MODEL")
print("="*70)

model = RandomForestClassifier(
    n_estimators=200,
    max_depth=25,
    min_samples_split=5,
    min_samples_leaf=2,
    random_state=42,
    n_jobs=-1
)

print("Training...")
model.fit(X_train, y_train)
print("✓ Training complete!")

# Evaluate
y_pred = model.predict(X_test)
y_pred_proba = model.predict_proba(X_test)[:, 1]

acc = accuracy_score(y_test, y_pred)
prec = precision_score(y_test, y_pred)
rec = recall_score(y_test, y_pred)
f1 = f1_score(y_test, y_pred)
roc_auc = roc_auc_score(y_test, y_pred_proba)

print("\n" + "="*70)
print(" PERFORMANCE METRICS")
print("="*70)
print(f"Accuracy:  {acc:.4f} ({acc*100:.2f}%)")
print(f"Precision: {prec:.4f} ({prec*100:.2f}%)")
print(f"Recall:    {rec:.4f} ({rec*100:.2f}%)")
print(f"F1-Score:  {f1:.4f} ({f1*100:.2f}%)")
print(f"ROC-AUC:   {roc_auc:.4f}")

# ============================================================
# SAVE MODEL FILES (WITH ABSOLUTE PATHS)
# ============================================================
print("\n" + "="*70)
print(" SAVING MODEL FILES")
print("="*70)

model_path = os.path.join(models_dir, 'phishing_detector_model.pkl')
features_path = os.path.join(models_dir, 'feature_names.pkl')
metrics_path = os.path.join(models_dir, 'model_metrics.pkl')

joblib.dump(model, model_path)
print(f"✓ Model saved to:\n  {model_path}")

joblib.dump(url_features, features_path)
print(f"✓ Features saved to:\n  {features_path}")

metrics = {'accuracy': acc, 'precision': prec, 'recall': rec, 'f1_score': f1, 'roc_auc': roc_auc}
joblib.dump(metrics, metrics_path)
print(f"✓ Metrics saved to:\n  {metrics_path}")

# ============================================================
# VERIFY FILES WERE SAVED
# ============================================================
print("\n" + "="*70)
print(" VERIFICATION")
print("="*70)

saved_files = os.listdir(models_dir)
print(f"Files in models directory: {len(saved_files)}")
for f in saved_files:
    filepath = os.path.join(models_dir, f)
    size = os.path.getsize(filepath) / 1024  # KB
    print(f"  - {f} ({size:.1f} KB)")

# Check critical files
critical_files = ['phishing_detector_model.pkl', 'feature_names.pkl', 'model_metrics.pkl']
all_exist = all(f in saved_files for f in critical_files)

if all_exist:
    print("\n✅ SUCCESS! All critical files saved successfully!")
else:
    print("\n❌ ERROR! Some files missing:")
    for f in critical_files:
        status = "✓" if f in saved_files else "✗"
        print(f"  {status} {f}")

# ============================================================
# GENERATE VISUALIZATIONS
# ============================================================
print("\n" + "="*70)
print(" GENERATING VISUALIZATIONS")
print("="*70)

try:
    cm = confusion_matrix(y_test, y_pred)
    plt.figure(figsize=(8, 6))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
                xticklabels=['Legitimate', 'Phishing'],
                yticklabels=['Legitimate', 'Phishing'])
    plt.title('Confusion Matrix', fontweight='bold')
    plt.ylabel('Actual')
    plt.xlabel('Predicted')
    plt.tight_layout()
    cm_path = os.path.join(models_dir, 'final_confusion_matrix.png')
    plt.savefig(cm_path, dpi=150, bbox_inches='tight')
    plt.close()
    print(f"✓ Confusion matrix saved to:\n  {cm_path}")
except Exception as e:
    print(f"⚠ Could not save confusion matrix: {e}")

try:
    feature_importance = pd.DataFrame({
        'feature': url_features,
        'importance': model.feature_importances_
    }).sort_values('importance', ascending=False)

    plt.figure(figsize=(10, 8))
    sns.barplot(data=feature_importance.head(20), x='importance', y='feature')
    plt.title('Top 20 Features', fontweight='bold')
    plt.tight_layout()
    fi_path = os.path.join(models_dir, 'feature_importance.png')
    plt.savefig(fi_path, dpi=150, bbox_inches='tight')
    plt.close()
    print(f"✓ Feature importance saved to:\n  {fi_path}")
except Exception as e:
    print(f"⚠ Could not save feature importance: {e}")

print("\n" + "="*70)
print(" TRAINING COMPLETE")
print("="*70)
