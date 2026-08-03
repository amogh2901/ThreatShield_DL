import os
import pickle
import time
import logging
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.utils.class_weight import compute_class_weight
import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Embedding, Bidirectional, LSTM, Dense, Dropout
from tensorflow.keras.callbacks import EarlyStopping, ModelCheckpoint, ReduceLROnPlateau
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import classification_report, confusion_matrix

# Setup Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Constants & Paths
SEED = 42
np.random.seed(SEED)
tf.keras.utils.set_random_seed(SEED)

MODEL_DIR = "model"
os.makedirs(MODEL_DIR, exist_ok=True)

DATASET_PATH = "dataset/payloads.csv"

MAX_SEQUENCE_LENGTH = 200
EMBEDDING_DIM = 128
BATCH_SIZE = 256
EPOCHS = 10
PATIENCE = 4
LEARNING_RATE = 0.001

MODEL_PATH = os.path.join(MODEL_DIR, "threat_model.keras")


# 1. Load Dataset
def load_dataset(filepath):
    try:
        data = pd.read_csv(filepath)
        data = data.dropna(subset=["payload"])
        data["payload"] = data["payload"].astype(str)
        return data
    except Exception as e:
        logging.error(f"Failed to load dataset: {e}")
        raise

# 2. Generate synthetic phishing URLs
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

import random

# -------------------------------------------------------
# Generate normal (LEGAL) payloads
# -------------------------------------------------------
def generate_normal_payloads():
    greetings = [
        "hello", "hi", "hey", "good morning", "good evening",
        "welcome", "welcome user", "welcome admin",
        "welcome to ThreatShield", "welcome to dashboard",
        "thank you", "good job"
    ]

    pages = [
        "home", "dashboard", "profile", "settings",
        "about us", "contact us", "products", "services",
        "faq", "support", "privacy policy", "terms of service"
    ]

    searches = [
        "search products",
        "search books",
        "search laptops",
        "search mobiles",
        "search shoes",
        "search electronics",
        "search users",
        "search dashboard"
    ]

    actions = [
        "login successful",
        "logout successful",
        "registration successful",
        "password changed",
        "profile updated",
        "email verified",
        "payment successful",
        "order placed successfully"
    ]

    users = [
        "admin",
        "john",
        "alice",
        "michael",
        "rahul",
        "amogh",
        "guest",
        "testuser"
    ]

    domains = [
        "google.com",
        "github.com",
        "amazon.com",
        "flipkart.com",
        "openai.com",
        "microsoft.com",
        "apple.com"
    ]

    api_paths = [
        "/api/users",
        "/api/products",
        "/api/orders",
        "/api/profile",
        "/api/login",
        "/api/logout",
        "/api/search"
    ]

    payloads = []

    # Greetings
    payloads.extend(greetings)

    # Pages
    payloads.extend(pages)

    # Searches
    payloads.extend(searches)

    # Actions
    payloads.extend(actions)

    # Generate thousands of normal requests
    for _ in range(4000):

        username = random.choice(users)

        payloads.extend([

            f"GET /{random.choice(pages).replace(' ','_')} HTTP/1.1",

            f"POST /login HTTP/1.1 username={username}",

            f"POST /register HTTP/1.1 username={username}",

            f"GET {random.choice(api_paths)}",

            f"POST {random.choice(api_paths)}",

            f"username={username}",

            f"email={username}@gmail.com",

            f"user={username}",

            f"page={random.choice(pages)}",

            f"category={random.choice(['books','mobiles','electronics','fashion'])}",

            f"product={random.choice(['laptop','phone','tv','mouse'])}",

            f"https://{random.choice(domains)}",

            f"https://www.{random.choice(domains)}",

            f"Welcome {username}",

            f"Welcome to ThreatShield",

            f"Search {random.choice(['products','books','mobiles'])}",

            f"View {random.choice(['profile','dashboard','orders'])}",

            f"Order #{random.randint(1000,9999)}",

            f"Invoice {random.randint(1000,9999)}",

            f"Customer ID {random.randint(10000,99999)}"

        ])
        # ----------------------------
    # ThreatShield-specific normal requests
    # ----------------------------
    payloads.extend([
        "Welcome to ThreatShield",
        "Welcome to ThreatShield DL",
        "Welcome to ThreatShield Security Platform",
        "Welcome to ThreatShield Dashboard",
        "Welcome to ThreatShield Home",
        "Welcome ThreatShield",
        "ThreatShield Dashboard",
        "ThreatShield Home",
        "ThreatShield Login",
        "ThreatShield Portal",
    ] * 300)
    payloads.extend([
        "login?user=admin",
        "login?user=john",
        "login?username=test",
        "search?q=laptop",
        "profile?id=123",
        "products?page=2",
        "category=books",
        "page=home",
        "user=admin",
        "id=1001",
    ] * 300)
    # ----------------------------
    # UI text
    # ----------------------------
    payloads.extend([
        "Analyze HTTP requests",
        "Analyze Request",
        "Attack Detection",
        "Security Dashboard",
        "Threat Intelligence",
        "Explainable AI",
        "Welcome User",
        "User Profile",
        "Contact Us",
        "About Us",
        "Home Page",
        "Dashboard",
    ] * 300)

    payloads.extend([

        "Login",
        "Register",
        "Forgot Password",
        "Reset Password",
        "Username",
        "Password",
        "Search",
        "Home",
        "Dashboard",
        "My Account",
        "My Orders",
        "Settings",
        "Notifications",
        "Logout",
        "Sign In",
        "Sign Up",
        "Contact",
        "About",
        "Support",
        "Profile"

    ] * 300)

    # ----------------------------
    # Important benign phrases
    # ----------------------------
    payloads.extend([
        "Welcome to ThreatShield",
        "Welcome to ThreatShield",
        "Welcome to ThreatShield",
        "Welcome to ThreatShield",
        "Welcome to ThreatShield",
    ] * 500)

    random.shuffle(payloads)
    return payloads

# 3. Prepare Dataset (augment with synthetic phishing)
def prepare_dataset(data):
    logging.info("Generating synthetic phishing URLs...")
    phishing_payloads = generate_synthetic_phishing_links(5000)
    phishing_df = pd.DataFrame({
        'payload': phishing_payloads,
        'is_malicious': [1] * len(phishing_payloads),
        'injection_type': ['PHISHING'] * len(phishing_payloads)
    })
    normal_payloads = generate_normal_payloads()

    normal_df = pd.DataFrame({
        "payload": normal_payloads,
        "is_malicious": [0] * len(normal_payloads),
        "injection_type": ["LEGAL"] * len(normal_payloads)
    })
    # Combine both
    data = pd.concat(
    [data, phishing_df, normal_df],
    ignore_index=True
    )
    logging.info(f"Dataset size after augmentation: {len(data)}")
    logging.info(f"Injection type distribution:\n{data['injection_type'].value_counts()}")
    return data

# 4. Encode Labels
def encode_labels(data):
    from sklearn.preprocessing import LabelEncoder
    encoder = LabelEncoder()
    data['label'] = encoder.fit_transform(data['injection_type'])
    # Save encoder and classes
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

# 5. Tokenize Texts
def tokenize_texts(texts, max_len=MAX_SEQUENCE_LENGTH):
    from tensorflow.keras.preprocessing.text import Tokenizer
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

# 6. Build Model
def build_model(vocab_size, num_classes):
    model = Sequential([
        Embedding(input_dim=vocab_size,output_dim=EMBEDDING_DIM),
        Bidirectional(
            LSTM(
                128,
                return_sequences=True,
                dropout=0.3
            )
        ),
        Bidirectional(
            LSTM(
                64,
                dropout=0.3
            )
        ),
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
        with open(
            os.path.join(MODEL_DIR, "model_summary.txt"),
            "w",
            encoding="utf-8"
        ) as f:
            model.summary(print_fn=lambda x: f.write(x + "\n"))
    except Exception as e:
        print("Couldn't save model summary:", e)

    return model 

# 7. Save plots
def save_plot(history, prefix):
    try:
        # Accuracy graph
        plt.figure(figsize=(8,5))
        plt.plot(history.history["accuracy"], label="Train")
        plt.plot(history.history["val_accuracy"], label="Validation")
        plt.title("Training Accuracy")
        plt.xlabel("Epoch")
        plt.ylabel("Accuracy")
        plt.legend()
        plt.savefig(os.path.join(MODEL_DIR, f"{prefix}_accuracy.png"))
        plt.close()

        # Loss graph
        plt.figure(figsize=(8,5))
        plt.plot(history.history["loss"], label="Train")
        plt.plot(history.history["val_loss"], label="Validation")
        plt.title("Training Loss")
        plt.xlabel("Epoch")
        plt.ylabel("Loss")
        plt.legend()
        plt.savefig(os.path.join(MODEL_DIR, f"{prefix}_loss.png"))
        plt.close()

        logging.info("OK training curves saved")

    except Exception as e:
        logging.error(f"Failed to save plots: {e}")

# 8. Save evaluation metrics
def save_evaluation_metrics(model, X_test, y_test, class_names):
    try:
        loss, accuracy = model.evaluate(X_test, y_test, verbose=0)
        y_pred_probs = model.predict(X_test)
        y_pred = np.argmax(y_pred_probs, axis=1)

        # Save classification report
        report = classification_report(y_test, y_pred, target_names=class_names)
        with open(os.path.join(MODEL_DIR, "classification_report.txt"), "w") as f:
            f.write(report)
        logging.info("OK classification_report.txt saved")

        # Save confusion matrix plot
        cm = confusion_matrix(y_test, y_pred)
        plt.figure(figsize=(8, 6))
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', xticklabels=class_names, yticklabels=class_names)
        plt.xlabel('Predicted')
        plt.ylabel('Actual')
        plt.title('Confusion Matrix')
        plt.savefig(os.path.join(MODEL_DIR, "confusion_matrix.png"))
        plt.close()

        return accuracy, loss
    except Exception as e:
        logging.error(f"Error during evaluation: {e}")
        raise

# 9. Save model and related info
def save_model_and_info(model, history, max_sequence_length, classes, vocab_size, embedding_dim):
    try:
        model.save(MODEL_PATH)
        # Save h5 as legacy
        model.save(os.path.join(MODEL_DIR, "threat_model.h5"))
        # Save history
        with open(os.path.join(MODEL_DIR, "history.pkl"), "wb") as f:
            pickle.dump(history.history, f, protocol=pickle.HIGHEST_PROTOCOL)
        # Save model info
        model_info = {
            "max_sequence_length": max_sequence_length,
            "classes": classes,
            "num_classes": len(classes),
            "vocab_size": vocab_size,
            "embedding_dim": embedding_dim
        }
        with open(os.path.join(MODEL_DIR, "model_info.pkl"), "wb") as f:
            pickle.dump(model_info, f, protocol=pickle.HIGHEST_PROTOCOL)
        logging.info("OK Model, history, and info saved")
    except Exception as e:
        logging.error(f"Failed to save model or info: {e}")

# 10. Verify files
def verify_files():
    required_files = [
        "threat_model.keras",
        "tokenizer.pkl",
        "label_encoder.pkl",
        "classes.pkl",
        "history.pkl",
        "model_info.pkl",
        "classification_report.txt",
        "model_summary.txt",
        "confusion_matrix.png",
        "training_accuracy.png",
        "training_loss.png"
    ]
    for filename in required_files:
        path = os.path.join(MODEL_DIR, filename)
        if os.path.exists(path):
            print(f"OK {filename}")
        else:
            print(f"Missing: {filename}")

# 11. Main training function
def main():
    start_time = time.time()
    print("\n====================================")
    print("ThreatShield Training")
    print("====================================\n")

    # 11.1 Load dataset
    data = load_dataset(DATASET_PATH)

    # 11.2 Augment dataset with synthetic phishing
    data = prepare_dataset(data)

    # 11.3 Encode labels
    data, encoder = encode_labels(data)
    class_names = list(encoder.classes_)

    X_raw = data['payload'].values
    y = data['label'].values

    # 11.4 Tokenize texts
    X, tokenizer = tokenize_texts(X_raw, max_len=MAX_SEQUENCE_LENGTH)
    vocab_size = len(tokenizer.word_index) + 1

    # Save tokenizer again (redundant, but for safety)
    with open(os.path.join(MODEL_DIR, "tokenizer.pkl"), "wb") as f:
        pickle.dump(tokenizer, f, protocol=pickle.HIGHEST_PROTOCOL)

    # 11.5 Split dataset
    X_train, X_temp, y_train, y_temp = train_test_split(
        X, y, test_size=0.2, random_state=SEED, stratify=y
    )
    X_val, X_test, y_val, y_test = train_test_split(
        X_temp, y_temp, test_size=0.5, random_state=SEED, stratify=y_temp
    )

    print(f"Training samples: {len(X_train)}")
    print(f"Validation samples: {len(X_val)}")
    print(f"Testing samples: {len(X_test)}")

    # 11.6 Build model
    model = build_model(vocab_size, len(class_names))
    print("MODEL =", model)
    print("TYPE =", type(model))

    # 11.7 Compute class weights for imbalance
    class_weights_array = compute_class_weight(
    class_weight="balanced",
    classes=np.unique(y_train),
    y=y_train
)
    class_weights = dict(enumerate(class_weights_array))
    print("Class weights:", class_weights)

    # 11.8 Callbacks
    early_stop = EarlyStopping(monitor='val_loss', patience=PATIENCE, restore_best_weights=True)
    checkpoint = ModelCheckpoint(filepath=MODEL_PATH, monitor='val_accuracy', save_best_only=True, mode='max')
    reduce_lr = ReduceLROnPlateau(monitor='val_loss', factor=0.2, patience=2, min_lr=1e-6, verbose=1)

    # 11.9 Train
    history = model.fit(
    X_train,
    y_train,
    validation_data=(X_val, y_val),
    epochs=EPOCHS,
    batch_size=BATCH_SIZE,
    class_weight=class_weights,
    callbacks=[early_stop, checkpoint, reduce_lr],
    verbose=1
    )

    # Save training graphs
    save_plot(history, "training")

    # 11.10 Evaluate
    accuracy, loss = save_evaluation_metrics(
        model,
    X_test, 
    y_test,
    class_names
    )

    # 11.11 Save model
    save_model_and_info(model, history, MAX_SEQUENCE_LENGTH, class_names, vocab_size, EMBEDDING_DIM)

    # 11.12 Verify files
    print("Verifying output files...")
    verify_files()

    total_time = time.time() - start_time
    print(f"\nTotal Training Time: {int(total_time // 60)} min {int(total_time % 60)} sec\n")
    print("====================================")
    print("ThreatShield Training Completed")
    print(f"Training Accuracy: {history.history['accuracy'][-1]:.4f}")
    print(f"Validation Accuracy: {history.history['val_accuracy'][-1]:.4f}")
    print(f"Test Accuracy: {accuracy:.4f}")
    print(f"Test Loss: {loss:.4f}")
    print(f"Total Time: {int(total_time // 60)} min {int(total_time % 60)} sec")
    print("Model saved as:", MODEL_PATH)
    print("====================================")

if __name__ == "__main__":
    main()