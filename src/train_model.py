import os
import pickle
import time
from datetime import datetime
import logging
import tensorflow as tf
from keras.models import load_model
from keras.callbacks import EarlyStopping, ModelCheckpoint, ReduceLROnPlateau
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
import pandas as pd
from sklearn.metrics import classification_report, confusion_matrix

# Configure logging for better traceability
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Set seed for reproducibility
SEED = 42
tf.keras.utils.set_random_seed(SEED)

# Define paths and constants
MODEL_DIR = "model"
os.makedirs(MODEL_DIR, exist_ok=True)
MODEL_PATH = os.path.join(MODEL_DIR, "threat_model.keras")

# Hyperparameters
BATCH_SIZE = 64
EPOCHS = 20
PATIENCE = 4
LEARNING_RATE = 0.001
MODEL_NAME = "threat_model.keras"

# Dataset path
DATASET_PATH = "dataset/payloads.csv"

# Define dataset parameters
MAX_SEQUENCE_LENGTH = 200
EMBEDDING_DIM = 128

def load_dataset(filepath):
    try:
        data = pd.read_csv(filepath)
        data = data.dropna(subset=["payload"])
        data["payload"] = data["payload"].astype(str)
        return data
    except Exception as e:
        logging.error(f"Failed to load dataset: {e}")
        raise

def generate_synthetic_phishing_links(n_samples=5000):
    brands = ["paypal", "secure-bank", "verify-paypal", "chase-login", "secure-login",
              "wells-fargo", "amazon-login", "google-security", "facebook-verify",
              "apple-id-verify", "netflix-update"]
    tlds = [".com", ".net", ".org", ".info", ".xyz", ".cc", ".biz", ".security-update.com", ".login-verify.net"]
    paths = ["/login", "/signin", "/verify", "/update", "/secure/login.php",
             "/account/update.html", "/auth/login"]
    queries = ["?cmd=_login-run", "?ref=login", "?verify=1", "?sec=secure", "?id=123"]
    samples = []
    for _ in range(n_samples):
        parts = []
        if np.random.rand() > 0.5:
            parts.append(np.random.choice(brands))
            parts.append(".")
        parts.append(np.random.choice(brands))
        parts.append(np.random.choice(tlds))
        if np.random.rand() > 0.3:
            parts.append(np.random.choice(paths))
        if np.random.rand() > 0.5:
            parts.append(np.random.choice(queries))
        url = "http://" + "".join(parts)
        if np.random.rand() > 0.5:
            url = url.replace("http://", "https://")
        samples.append(url)
    return samples

def prepare_dataset(data):
    logging.info("Generating synthetic phishing URLs...")
    phishing_payloads = generate_synthetic_phishing_links(5000)
    phishing_df = pd.DataFrame({
        'payload': phishing_payloads,
        'is_malicious': [1] * len(phishing_payloads),
        'injection_type': ['PHISHING'] * len(phishing_payloads)
    })
    data = pd.concat([data, phishing_df], ignore_index=True)
    logging.info(f"Dataset size after augmentation: {len(data)}")
    logging.info(f"Injection type distribution:\n{data['injection_type'].value_counts()}")
    return data

def encode_labels(data):
    from sklearn.preprocessing import LabelEncoder
    encoder = LabelEncoder()
    data['label'] = encoder.fit_transform(data['injection_type'])
    # Save encoder and class list
    try:
        with open(os.path.join(MODEL_DIR, "label_encoder.pkl"), "wb") as f:
            pickle.dump(encoder, f, protocol=pickle.HIGHEST_PROTOCOL)
        with open(os.path.join(MODEL_DIR, "classes.pkl"), "wb") as f:
            pickle.dump(list(encoder.classes_), f, protocol=pickle.HIGHEST_PROTOCOL)
        logging.info("✓ label_encoder.pkl and classes.pkl saved")
    except Exception as e:
        logging.error(f"Failed to save label encoder/class list: {e}")
        raise
    return data, encoder

def tokenize_texts(texts, max_len=MAX_SEQUENCE_LENGTH):
    from keras.preprocessing.text import Tokenizer
    tokenizer = Tokenizer(char_level=True, lower=True, oov_token="<OOV>")
    tokenizer.fit_on_texts(texts)
    # Save tokenizer
    try:
        with open(os.path.join(MODEL_DIR, "tokenizer.pkl"), "wb") as f:
            pickle.dump(tokenizer, f, protocol=pickle.HIGHEST_PROTOCOL)
        logging.info("✓ tokenizer.pkl saved")
    except Exception as e:
        logging.error(f"Failed to save tokenizer: {e}")
        raise
    sequences = tokenizer.texts_to_sequences(texts)
    padded_seq = tf.keras.preprocessing.sequence.pad_sequences(
        sequences, maxlen=max_len, padding='post', truncating='post'
    )
    return padded_seq, tokenizer

def build_model(vocab_size, num_classes):
    from keras.models import Sequential
    from keras.layers import Embedding, Bidirectional, LSTM, Dense, Dropout
    model = Sequential([
        Embedding(input_dim=vocab_size, output_dim=EMBEDDING_DIM, input_length=MAX_SEQUENCE_LENGTH),
        Bidirectional(LSTM(128, return_sequences=True, dropout=0.3, recurrent_dropout=0.3)),
        Bidirectional(LSTM(64, dropout=0.3, recurrent_dropout=0.3)),
        Dropout(0.5),
        Dense(64, activation='relu'),
        Dropout(0.3),
        Dense(32, activation='relu'),
        Dense(num_classes, activation='softmax')
    ])
    model.compile(
        optimizer=tf.keras.optimizers.Adam(learning_rate=LEARNING_RATE),
        loss='sparse_categorical_crossentropy',
        metrics=['accuracy']
    )
    # Save model summary
    try:
        with open(os.path.join(MODEL_DIR, "model_summary.txt"), "w") as f:
            model.summary(print_fn=lambda x: f.write(x + "\n"))
        logging.info("✓ model_summary.txt saved")
    except Exception as e:
        logging.error(f"Failed to save model summary: {e}")
        raise
    return model

def save_plot(history, filename_prefix):
    """Save accuracy and loss plots."""
    try:
        plt.figure(figsize=(12, 5))
        plt.subplot(1, 2, 1)
        plt.plot(history.history['accuracy'], label='Train Accuracy')
        plt.plot(history.history['val_accuracy'], label='Val Accuracy')
        plt.xlabel('Epoch')
        plt.ylabel('Accuracy')
        plt.legend()
        plt.title('Training & Validation Accuracy')
        plt.savefig(os.path.join(MODEL_DIR, f"{filename_prefix}_accuracy.png"))

        plt.subplot(1, 2, 2)
        plt.plot(history.history['loss'], label='Train Loss')
        plt.plot(history.history['val_loss'], label='Val Loss')
        plt.xlabel('Epoch')
        plt.ylabel('Loss')
        plt.legend()
        plt.title('Training & Validation Loss')
        plt.savefig(os.path.join(MODEL_DIR, f"{filename_prefix}_loss.png"))
        plt.close()

        # Save only loss curve separately if needed
        plt.figure()
        plt.plot(history.history['loss'], label='Loss')
        plt.xlabel('Epoch')
        plt.ylabel('Loss')
        plt.legend()
        plt.title('Training Loss')
        plt.savefig(os.path.join(MODEL_DIR, f"{filename_prefix}_loss_only.png"))
        plt.close()
        logging.info("✓ training curves saved")
    except Exception as e:
        logging.error(f"Failed to save plots: {e}")

def save_evaluation_metrics(model, X_test, y_test, classes):
    """Evaluate the model and save classification report and confusion matrix."""
    try:
        loss, accuracy = model.evaluate(X_test, y_test, verbose=0)
        print(f"Testing Accuracy: {accuracy:.4f}")
        print(f"Testing Loss: {loss:.4f}")

        y_pred_probs = model.predict(X_test)
        y_pred = np.argmax(y_pred_probs, axis=1)

        # Save classification report
        report = classification_report(y_test, y_pred, target_names=classes)
        with open(os.path.join(MODEL_DIR, "classification_report.txt"), "w") as f:
            f.write(str(report))
        logging.info("✓ classification_report.txt saved")

        # Save confusion matrix plot
        cm = confusion_matrix(y_test, y_pred)
        plt.figure(figsize=(8, 6))
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', xticklabels=classes, yticklabels=classes)
        plt.xlabel('Predicted')
        plt.ylabel('Actual')
        plt.title('Confusion Matrix')
        plt.savefig(os.path.join(MODEL_DIR, "confusion_matrix.png"))
        plt.close()
        logging.info("✓ confusion_matrix.png saved")
        return accuracy, loss
    except Exception as e:
        logging.error(f"Error during evaluation: {e}")
        raise

def save_model_and_history(model, history):
    """Save the model, model info, and training history."""
    try:
        # Save model in .keras format and legacy .h5 format
        model.save(MODEL_PATH)
        h5_path = os.path.join(MODEL_DIR, "threat_model.h5")
        model.save(h5_path)
        
        # Save training history
        with open(os.path.join(MODEL_DIR, "history.pkl"), "wb") as f:
            pickle.dump(history.history, f, protocol=pickle.HIGHEST_PROTOCOL)

        # Save model info
        model_info = {"max_sequence_length": MAX_SEQUENCE_LENGTH}
        with open(os.path.join(MODEL_DIR, "model_info.pkl"), "wb") as f:
            pickle.dump(model_info, f, protocol=pickle.HIGHEST_PROTOCOL)

        logging.info("✓ Model (.keras, .h5), history.pkl, and model_info.pkl saved")
    except Exception as e:
        logging.error(f"Failed to save model or history: {e}")

def verify_files():
    """Verify all required files exist and print status."""
    required_files = [
        "threat_model.keras",
        "tokenizer.pkl",
        "label_encoder.pkl",
        "classes.pkl",
        "history.pkl",
        "model_info.pkl",
        "dataset_stats.pkl",
        "training_stats.pkl",
        "classification_report.txt",
        "model_summary.txt",
        "accuracy.png",
        "loss.png",
        "confusion_matrix.png"
    ]
    for filename in required_files:
        path = os.path.join(MODEL_DIR, filename)
        if os.path.exists(path):
            print(f"✓ {filename}")
        else:
            print(f"✗ Missing: {filename}")

def print_time(seconds):
    minutes = int(seconds // 60)
    sec = int(seconds % 60)
    return f"{minutes} min {sec} sec"

def main():
    start_time = time.time()
    print("""
====================================
ThreatShield Training
====================================
""")
    print("Loading Dataset...")
    data = load_dataset(DATASET_PATH)

    print("Preparing Dataset...")
    data = prepare_dataset(data)

    print("Encoding Labels...")
    data, label_encoder = encode_labels(data)

    X_raw = data['payload'].values
    y = data['label'].values

    print("Building Character Tokenizer...")
    X, tokenizer = tokenize_texts(X_raw, max_len=MAX_SEQUENCE_LENGTH)
    vocab_size = len(tokenizer.word_index) + 1

    # Save tokenizer
    try:
        with open(os.path.join(MODEL_DIR, "tokenizer.pkl"), "wb") as f:
            pickle.dump(tokenizer, f)
        print("✓ tokenizer.pkl saved")
    except Exception as e:
        print(f"Error saving tokenizer: {e}")
        return

    # Split dataset
    from sklearn.model_selection import train_test_split
    X_train, X_temp, y_train, y_temp = train_test_split(
        X, y, test_size=0.2, random_state=SEED, stratify=y
    )
    X_val, X_test, y_val, y_test = train_test_split(
        X_temp, y_temp, test_size=0.5, random_state=SEED, stratify=y_temp
    )

    print("Splitting Dataset...")
    print(f"Training samples: {len(X_train)}")
    print(f"Validation samples: {len(X_val)}")
    print(f"Testing samples: {len(X_test)}")

    # Load class names
    with open(os.path.join(MODEL_DIR, "classes.pkl"), "rb") as f:
        classes = pickle.load(f)

    print("Building Bi-LSTM...")
    model = build_model(vocab_size, len(classes))

    print("Training...")
    # Callbacks
    early_stop = EarlyStopping(monitor='val_loss', patience=PATIENCE, restore_best_weights=True)
    checkpoint = ModelCheckpoint(filepath=MODEL_PATH, monitor='val_accuracy', save_best_only=True, mode='max')
    reduce_lr = ReduceLROnPlateau(monitor='val_loss', factor=0.2, patience=2, min_lr=1e-6, verbose=1)

    history = model.fit(
        X_train,
        y_train,
        epochs=EPOCHS,
        batch_size=BATCH_SIZE,
        validation_split=0.1,
        callbacks=[early_stop, checkpoint, reduce_lr],
        verbose=1
    )

    print("Evaluating...")
    test_accuracy, test_loss = save_evaluation_metrics(model, X_test, y_test, classes)

    print("Saving Model...")
    save_model_and_history(model, history)

    # Save class labels for new features
    with open(os.path.join(MODEL_DIR, "classes.pkl"), "wb") as f:
        pickle.dump(list(label_encoder.classes_), f)

    # Verify files
    print("Verifying output files...")
    verify_files()

    total_time_seconds = time.time() - start_time
    print(f"\nTraining Time : {print_time(total_time_seconds)}\n")

    # Final summary
    print("""
====================================
ThreatShield Training Completed
====================================
""")
    print(f"Training Accuracy : {history.history['accuracy'][-1]:.4f}")
    print(f"Validation Accuracy : {history.history['val_accuracy'][-1]:.4f}")
    print(f"Testing Accuracy : {test_accuracy:.4f}")
    print(f"Loss : {test_loss:.4f}")
    print(f"Training Time : {print_time(total_time_seconds)}")
    print(f"Model Saved : {MODEL_PATH}")
    print("====================================")

if __name__ == "__main__":
    main()