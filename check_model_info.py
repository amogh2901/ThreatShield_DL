import pickle
from pathlib import Path

MODEL = Path("model") / "model_info.pkl"

with open(MODEL, "rb") as f:
    data = pickle.load(f)

print(type(data))
print(data)