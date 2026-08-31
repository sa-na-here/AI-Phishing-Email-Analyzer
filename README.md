# 🛡️ AI Phishing Email Analyzer

An explainable cybersecurity application that analyzes suspicious emails using rule-based security indicators and a machine-learning classification model.

## 📌 Project Overview

The AI Phishing Email Analyzer helps identify potentially malicious or suspicious emails by examining common phishing characteristics such as:

- Urgent or threatening language
- Credential requests
- Suspicious URLs
- Brand impersonation
- Requests to click or verify accounts
- Financial information requests
- Suspicious attachments
- Sender/domain characteristics

The application combines explainable security rules with a machine-learning model to provide both a human-readable risk assessment and an independent ML classification.

## ✨ Features

### 🔍 Explainable Risk Analysis
The analyzer calculates a risk score from 0–100 based on detected security indicators.

### 👤 Sender Analysis
Examines the sender email address and domain for suspicious characteristics and possible brand impersonation.

### 🔗 URL Analysis
Detects links and evaluates URLs for characteristics commonly associated with phishing.

### 🤖 Machine Learning Classification
A trained machine-learning model independently classifies an email as:

- Phishing
- Legitimate

The application also displays the model confidence.

### 📊 Security Assessment
The application provides:

- Risk score
- Risk level
- Detected indicators
- Detailed explanations
- ML classification
- ML confidence
- Recommended action

## 🧠 Machine Learning

The project uses a trained machine-learning model stored in:

`phishing_model.joblib`

The model is loaded by the Streamlit application and used to classify submitted email text.

The ML classification is presented separately from the explainable Risk Score so that users can distinguish between the rule-based security assessment and the machine-learning prediction.

## 🛠️ Technologies Used

- Python
- Streamlit
- Scikit-learn
- Joblib
- Regular Expressions
- URL Parsing
- Machine Learning
- Explainable Cybersecurity Analysis

## 📂 Project Structure

```text
AI-Phishing-Email-Analyzer/
│
├── app.py
├── ml_model.py
├── phishing_model.joblib
├── requirements.txt
└── README.md
