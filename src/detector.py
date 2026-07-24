import os
from pathlib import Path
import pickle
import numpy as np
import tensorflow as tf

# Cache for loaded resources
_resources = None

def load_resources():
    """
    Loads model, tokenizer, label encoder, classes, and max_sequence_length.
    Uses project root directory to locate the 'model' folder.
    Caches resources to avoid reloading.
    """
    global _resources

    # Initialize variables to prevent UnboundLocalError
    model = None
    tokenizer = None
    label_encoder = None
    classes = None
    max_sequence_length = 200

    if _resources is not None:
        return _resources

    # Determine project root directory
    PROJECT_ROOT = Path(__file__).resolve().parent.parent
    MODEL_DIR = PROJECT_ROOT / "model"

    # Define file paths
    threat_model_path = MODEL_DIR / "threat_model.h5"
    if not threat_model_path.exists():
        threat_model_path = MODEL_DIR / "threat_model.keras"
    tokenizer_path = MODEL_DIR / "tokenizer.pkl"
    label_encoder_path = MODEL_DIR / "label_encoder.pkl"
    model_info_path = MODEL_DIR / "model_info.pkl"
    classes_path = MODEL_DIR / "classes.pkl"

    # Print paths for debugging
    print("\n========== MODEL PATHS ==========")
    print("Model:", threat_model_path)
    print("Tokenizer:", tokenizer_path)
    print("Label Encoder:", label_encoder_path)
    print("Classes:", classes_path)
    print("Model Info:", model_info_path)
    print("=================================\n")

    # Check existence
    print(threat_model_path.exists())
    print(tokenizer_path.exists())
    print(label_encoder_path.exists())
    print(model_info_path.exists())
    print(classes_path.exists())

    # Verify all files exist
    for path in [threat_model_path, tokenizer_path, label_encoder_path, model_info_path, classes_path]:
        if not path.exists():
            raise FileNotFoundError(f"Required file not found: {path}")

    errors = []

    # Load model
    try:
        model = tf.keras.models.load_model(str(threat_model_path))
        print("✓ Model Loaded")
    except Exception as e:
        errors.append(f"Failed to load model from {threat_model_path}: {e}")

    # Load tokenizer
    try:
        with open(tokenizer_path, 'rb') as f:
            tokenizer = pickle.load(f)
        print("✓ Tokenizer Loaded")
    except Exception as e:
        errors.append(f"Failed to load tokenizer from {tokenizer_path}: {e}")

    # Load label encoder
    try:
        with open(label_encoder_path, 'rb') as f:
            label_encoder = pickle.load(f)
        print("✓ Label Encoder Loaded")
    except Exception as e:
        errors.append(f"Failed to load label encoder from {label_encoder_path}: {e}")

    # Load classes
    try:
        if classes_path.exists():
            with open(classes_path, 'rb') as f:
                classes = pickle.load(f)
            print("✓ Classes Loaded from classes.pkl")
        elif label_encoder is not None:
            classes = label_encoder.classes_
            print("✓ Classes Derived from Label Encoder")
        else:
            raise RuntimeError("Label encoder not loaded; cannot derive classes.")
    except Exception as e:
        errors.append(f"Failed to load classes: {e}")

    # Load model info for max_sequence_length
    try:
        with open(model_info_path, 'rb') as f:
            model_info = pickle.load(f)
        max_sequence_length = model_info.get("max_sequence_length", 200)
        print("✓ Model Info Loaded")
    except Exception as e:
        errors.append(f"Failed to load model info from {model_info_path}: {e}")

    # Check for critical resources
    critical_resources = [model, tokenizer, label_encoder]
    if any(r is None for r in critical_resources):
        # Show all errors for debugging
        print("\nERRORS during resource loading:")
        print("\n".join(errors))
        raise RuntimeError("\n".join(errors))

    _resources = (model, tokenizer, label_encoder, classes, max_sequence_length)
    return _resources

def detect_attack(payload):
    """
    Detect attack type from payload using loaded model and tokenizer.
    Returns:
        attack_type (str), confidence (float), probabilities (dict)
    """
    # Load resources
    (model,
     tokenizer,
     label_encoder,
     classes,
     max_sequence_length) = load_resources()

    if tokenizer is None or model is None or classes is None:
        safe_classes = ["LEGAL", "SQL", "XSS", "SHELL", "PHISHING"]
        return ("Normal", 1.0, {cls: 0.0 for cls in safe_classes})

    # User-friendly attack names
    DISPLAY_NAMES = {
        "LEGAL": "Normal",
        "SQL": "SQL Injection",
        "XSS": "Cross Site Scripting",
        "SHELL": "Path Traversal",
        "PHISHING": "Phishing URL"
    }

    # Convert payload to string
    if not isinstance(payload, str):
        payload = str(payload)
    payload = payload.strip()

    # Handle empty payload
    if not payload:
        safe_classes = classes if classes else ["LEGAL", "SQL", "XSS", "SHELL", "PHISHING"]
        return ("Normal", 1.0, {cls: 0.0 for cls in safe_classes})

    # Tokenize and pad
    try:
        sequences = tokenizer.texts_to_sequences([payload])
        padded_seq = tf.keras.preprocessing.sequence.pad_sequences(
            sequences,
            maxlen=max_sequence_length,
            padding='post',
            truncating='post'
        )
    except Exception as e:
        print(f"Tokenization error: {e}")
        safe_classes = classes if classes else ["LEGAL", "SQL", "XSS", "SHELL", "PHISHING"]
        return ("Normal", 1.0, {cls: 0.0 for cls in safe_classes})

    # Model inference
    try:
        preds = model(padded_seq, training=False).numpy()
    except Exception as e:
        print(f"Inference error: {e}")
        safe_classes = classes if classes else ["LEGAL", "SQL", "XSS", "SHELL", "PHISHING"]
        return ("Normal", 1.0, {cls: 0.0 for cls in safe_classes})

    # Validate output shape
    if preds.ndim != 2 or preds.shape[1] != len(classes):
        print(f"Unexpected prediction shape: {preds.shape}")
        safe_classes = classes if classes else ["LEGAL", "SQL", "XSS", "SHELL", "PHISHING"]
        return ("Normal", 1.0, {cls: 0.0 for cls in safe_classes})

    # Extract probabilities
    probs = np.squeeze(preds)

    if not np.isfinite(probs).all():
        raise RuntimeError("Model produced invalid probability values.")

    if probs.ndim != 1 or len(probs) != len(classes):
        print("Mismatch between model output and number of classes.")
        safe_classes = classes if classes else ["LEGAL", "SQL", "XSS", "SHELL", "PHISHING"]
        return ("Normal", 1.0, {cls: 0.0 for cls in safe_classes})

    # Determine max probability class
    max_idx = np.argmax(probs)
    attack_class = str(classes[max_idx])
    confidence = float(probs[max_idx])

    # Map to user-friendly name
    attack_type = DISPLAY_NAMES.get(attack_class, attack_class)

    # Build probabilities dictionary
    class_probs = {cls: float(probs[i]) for i, cls in enumerate(classes)}

    return attack_type, confidence, class_probs

# Run standalone test
if __name__ == "__main__":
    test_payloads = [
        "SELECT * FROM users WHERE username='admin' --",
        "<script>alert(1)</script>",
        "../../etc/passwd",
        "https://secure-login.com/verify?token=abc123",
        ""
    ]
    for payload in test_payloads:
        attack, conf, probs = detect_attack(payload)
        print(f"Payload: {payload}\nAttack: {attack}\nConfidence: {conf:.4f}\nProbs: {probs}\n{'-'*50}")