import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.metrics import classification_report, accuracy_score


# ============================================================
# AI PHISHING EMAIL ANALYZER — MACHINE LEARNING MODEL
# ============================================================

# Small labeled dataset for the MVP.
# 1 = phishing
# 0 = legitimate

data = [
    # -------------------------
    # PHISHING EMAILS
    # -------------------------
    ("URGENT: Your account will be suspended. Verify your password immediately by clicking this link.", 1),
    ("Your Microsoft account requires immediate verification. Confirm your credentials now.", 1),
    ("Security Alert! We detected suspicious activity. Login immediately to prevent account closure.", 1),
    ("Your bank account has been locked. Click here to verify your banking information.", 1),
    ("Congratulations! You won a $1,000 reward. Click the link and provide your account details.", 1),
    ("Your payment failed. Update your credit card information immediately to avoid service interruption.", 1),
    ("FINAL WARNING: Your account will be permanently deleted unless you verify your login today.", 1),
    ("We noticed unusual activity on your account. Confirm your username and password immediately.", 1),
    ("Your email storage is full. Click here and sign in to increase your storage limit.", 1),
    ("Your payroll information needs verification. Submit your Social Security number and banking details.", 1),
    ("You have an important secure message. Click the link and enter your login credentials.", 1),
    ("Your password has expired. Verify your account now or access will be restricted.", 1),
    ("Immediate action required. Your account has been compromised. Login to secure it.", 1),
    ("Your package could not be delivered. Confirm your address and payment information.", 1),
    ("You have been selected for a refund. Click here to confirm your bank account details.", 1),
    ("Microsoft Security Alert: Verify your account password immediately to prevent suspension.", 1),
    ("Your account will be disabled today. Click this link to confirm your identity.", 1),
    ("We detected a login from an unknown device. Verify your account using the link below.", 1),
    ("Important: Your authentication code is required. Enter your verification information now.", 1),
    ("Failure to verify your account within 24 hours will result in permanent suspension.", 1),

    # -------------------------
    # LEGITIMATE EMAILS
    # -------------------------
    ("Hi team, the meeting has been moved to 2 PM tomorrow. Please update your calendar.", 0),
    ("Thank you for your purchase. Your order has been received and is being processed.", 0),
    ("Your monthly statement is now available in your online account.", 0),
    ("Reminder: Your appointment is scheduled for Tuesday at 10 AM.", 0),
    ("Your password was successfully changed. If you made this change, no further action is required.", 0),
    ("Here is the agenda for tomorrow's project meeting. Please review it before the meeting.", 0),
    ("Your package has shipped and is expected to arrive on Friday.", 0),
    ("Thank you for contacting customer support. We have received your request.", 0),
    ("Your monthly newsletter is ready to view.", 0),
    ("The requested report has been attached to this email.", 0),
    ("Your application has been successfully submitted. We will contact you with the next steps.", 0),
    ("Your reservation has been confirmed for Saturday evening.", 0),
    ("The team meeting notes are available in the shared folder.", 0),
    ("Your invoice for this month is now available for review.", 0),
    ("Thank you for registering for our upcoming webinar.", 0),
    ("Your account settings were updated successfully.", 0),
    ("The project deadline has been extended until Friday.", 0),
    ("Please find the requested document attached for your review.", 0),
    ("Your subscription will renew automatically next month.", 0),
    ("We appreciate your feedback. Thank you for completing the survey.", 0),
]


# Convert the dataset into a DataFrame
df = pd.DataFrame(data, columns=["email", "label"])


# Split into training and testing data
X_train, X_test, y_train, y_test = train_test_split(
    df["email"],
    df["label"],
    test_size=0.25,
    random_state=42,
    stratify=df["label"]
)


# Build the ML pipeline
model = Pipeline([
    ("tfidf", TfidfVectorizer(
        lowercase=True,
        stop_words="english",
        ngram_range=(1, 2)
    )),
    ("classifier", LogisticRegression(
        max_iter=1000,
        random_state=42
    ))
])


# Train the classifier
model.fit(X_train, y_train)


# Evaluate the classifier
predictions = model.predict(X_test)

accuracy = accuracy_score(y_test, predictions)

print("\n============================================")
print("AI PHISHING EMAIL ANALYZER — ML MODEL")
print("============================================")
print(f"\nTest Accuracy: {accuracy * 100:.2f}%\n")

print("Classification Report:")
print(classification_report(
    y_test,
    predictions,
    target_names=["Legitimate", "Phishing"],
    zero_division=0
))


# Save the trained model
joblib.dump(model, "phishing_model.joblib")

print("============================================")
print("Model saved as: phishing_model.joblib")
print("============================================")
