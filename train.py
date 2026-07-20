import pandas as pd
from sklearn.ensemble import RandomForestClassifier
import joblib
import numpy as np

print("Loading dataset...")
df = pd.read_csv("final_dataset.csv")
df = df.sample(frac=1).reset_index(drop=True)  # shuffle
df = df.head(100000)  # first 1 lakh AFTER shuffle
# Clean column names
df.columns = df.columns.str.strip()

print("Cleaning data...")

# Replace infinity with NaN
df.replace([np.inf, -np.inf], np.nan, inplace=True)

# Drop NaN rows
df = df.dropna()

# Create feature
df["Total Packets"] = df["Tot Fwd Pkts"] + df["Tot Bwd Pkts"]

# Select features
X = df[["Flow Duration", "Total Packets", "Flow Pkts/s"]]

# Label convert
y = df["Label"].apply(lambda x: 1 if "ddos" in str(x).lower() else 0)

print("Training model...")
model = RandomForestClassifier(n_estimators=100)
model.fit(X, y)

print("Saving model...")
joblib.dump(model, "model.pkl")

print("✅ Model trained successfully 🚀")