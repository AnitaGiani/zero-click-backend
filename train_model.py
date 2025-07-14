import pandas as pd
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.model_selection import train_test_split
from sklearn.naive_bayes import MultinomialNB
import joblib

# Load the dataset
data = pd.read_csv("phishing_data.csv")

# Convert labels to 1 (malicious) and 0 (benign)
data['label'] = data['label'].map({'phishing': 1, 'benign': 0})

# Extract features using CountVectorizer (bag of words from URL text)
vectorizer = CountVectorizer()
X = vectorizer.fit_transform(data['url'])
y = data['label']

# Split into training/testing
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Train model
model = MultinomialNB()
model.fit(X_train, y_train)

# Save model and vectorizer
joblib.dump(model, "url_model.pkl")
joblib.dump(vectorizer, "vectorizer.pkl")

print("✅ Model trained and saved.")
