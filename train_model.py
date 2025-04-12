import pandas as pd
import xgboost as xgb
import pickle
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix

# Load dataset
df = pd.read_csv("phishing_dataset1.csv")

# Define features and target
X = df.drop(columns=["Result"])
y = df["Result"]

# Train-test split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Train XGBoost model
model = xgb.XGBClassifier(use_label_encoder=False, eval_metric="logloss")
model.fit(X_train, y_train)

# Predict on test set
y_pred = model.predict(X_test)

# Evaluate the model
accuracy = accuracy_score(y_test, y_pred)
precision = precision_score(y_test, y_pred)
recall = recall_score(y_test, y_pred)
f1 = f1_score(y_test, y_pred)
cm = confusion_matrix(y_test, y_pred)

print("\n🔍 Model Evaluation Metrics:")
print(f"✅ Accuracy : {accuracy:.4f}")
print(f"✅ Precision: {precision:.4f}")
print(f"✅ Recall   : {recall:.4f}")
print(f"✅ F1 Score : {f1:.4f}")
print("🧮 Confusion Matrix:")
print(cm)

# Save model as JSON (for use in Flask app)
model.get_booster().save_model("xgboost_model.json")

# Optional: Save model as Pickle
with open("xgboost_model.pkl", "wb") as f:
    pickle.dump(model, f)

print("\n🎉 Model trained and saved as both JSON and PKL successfully!")
