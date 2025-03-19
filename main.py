import os
import ember
import lief
import joblib
import tensorflow as tf
import numpy as np
import pandas as pd

# Tampilan ASCII Header
print(
    '''
  __  __       ____      ________     ________   
 |  \/  |     | | |     |  ____\ \   / /  ____| 
 | \  / | __ _| | |___  | |__   \ \_/ /| |__    
 | |\/| |/ _` | | / __| |  __|   \   / |  __|   
 | |  | | (_| | | \__ \ | |____   | |  | |____  
 |_|  |_|\__,_|_|_|___/ |______|  |_|  |______|


 - This Malware Detection Tool uses AI Before Static Analysis -

 - Rangga Wahyu Nugroho -
 - Beta 0.1 -
 - 2025 -

 - Type 'help' for information
    '''
)

# Minta input path file atau command
dire = input("Enter the directory of the file: ").strip()

# Jika user mengetik "help", tampilkan informasi
if dire.lower() in ["help", "-help", "/help"]:
    print("""
Usage:
  - Enter the full path of the file to analyze (e.g., C:\\Users\\User\\malware.exe)
  - The AI model will classify the file as:
      - 0: Potensi Malware
      - 1: Aman
      - 2: Malware
  - Ensure that the file is a valid PE file (EXE, DLL)

Example:
  Enter the directory of the file: C:\\Users\\User\\malware.exe
  Output: Hasil Analisis: Malware
    """)
    exit()

# Cek apakah file ada
if not os.path.exists(dire):
    print("Error: File tidak ditemukan. Pastikan path sudah benar.")
    exit()

print(f"Memproses file: {dire}")

# Fungsi ekstraksi fitur dari PE file
def extract_features_from_pe(file_path):
    binary = lief.parse(file_path)
    if binary is None:
        print(f"Error: Tidak bisa parse {file_path}")
        return None
    features = ember.extract_raw_features(binary)
    return features

# Ekstrak fitur
features = extract_features_from_pe(dire)

if features is None:
    print("Gagal mengekstrak fitur dari file.")
    exit()

# Konversi fitur ke DataFrame agar lebih mudah diolah
feature_names = [f"F{i}" for i in range(len(features))]
feature_df = pd.DataFrame([features], columns=feature_names)

# Pilih fitur yang diinginkan
selected_features = ['F627', 'F2360', 'F692', 'F2356', 'F2361', 'F2355', 
                     'F787', 'F2365', 'F614', 'F638', 'F621']
extracted_data = feature_df[selected_features]

print("Fitur yang diekstrak:")
print(extracted_data)

# Load StandardScaler jika sudah ada (gunakan scaler yang sama saat training)
try:
    scaler = joblib.load("scaler_model.joblib")
except FileNotFoundError:
    print("Error: StandardScaler belum dibuat! Silakan fit scaler dengan data training terlebih dahulu.")
    exit()

# Transform data menggunakan scaler
scaled_features = scaler.transform(extracted_data)

# Load model AI
try:
    model = tf.keras.models.load_model("model.h5")
except OSError:
    print("Error: Model .h5 tidak ditemukan! Pastikan model tersedia di direktori yang benar.")
    exit()

# Lakukan prediksi
prediction = model.predict(scaled_features)

# Konversi hasil prediksi ke label kelas (0, 1, 2)
predicted_class = np.argmax(prediction, axis=1)

# Interpretasi hasil prediksi
labels = {0: "Potensi Malware", 1: "Aman", 2: "Malware"}
result = labels[predicted_class[0]]

print(f"\nHasil Analisis: {result}")
