# Real-Time Malware and URL Scanner using Machine Learning

This project is a real-time malware and URL scanner powered by Machine Learning (ML) and Deep Learning (DL). It analyzes PE files and URLs to detect potential threats based on extracted features and trained models.

> ⚠️ **Disclaimer**: This project is for educational and research purposes only.

---

## 🧠 Inspiration

This project was inspired by several open-source efforts and academic research on malware detection using static analysis and ML/DL methods. In particular, we were influenced by existing approaches that use feature engineering on Portable Executable (PE) files and NLP-based URL classification.

---

## 📁 Project Structure

- `main.py`: Main script that activates the scanning pipeline.
- `PE_extract.py`: Extracts features from PE files.
- `URL_extract.py`: Cleans and preprocesses URLs.
- `PE.ipynb`: Jupyter notebook for analyzing PE headers and testing the model.
- `url.ipynb`: Jupyter notebook for analyzing URL data.
- `classier.pkl`: Machine Learning model for PE file classification.
- `dl_pe.keras`: Deep Learning model for PE file classification.
- `features.pkl`: Pickled features used in the models.
- `pickle_model.pkl`: ML model for URL classification.
- `pickle_vector.pkl`: Pickled vectorizer used for URL classification.

---

## ⚙️ How It Works

### 🔬 PE File Scanning

1. The PE file is analyzed to extract static features.
2. Features are passed to both ML and DL models.
3. The model returns a classification: **malicious** or **benign**.

### 🌐 URL Scanning

1. The URL is cleaned and vectorized.
2. The vector is passed through the ML model.
3. The model predicts if the URL is **malicious** or **safe**.

---

## 🛠️ How to Run

Make sure you have the required dependencies installed:

```bash
pip install -r requirements.txt
