import pandas as pd
import re

# Load the data
df = pd.read_csv("phishing_data.csv")

# Feature functions
def count_dots(url):
    return url.count('.')

def count_hyphens(url):
    return url.count('-')

def has_ip(url):
    return 1 if re.match(r"https?://\d+\.\d+\.\d+\.\d+", url) else 0

def url_length(url):
    return len(url)

def count_at_symbols(url):
    return url.count('@')

def is_https(url):
    return 1 if url.startswith("https") else 0

# Apply feature extraction
df["num_dots"] = df["url"].apply(count_dots)
df["num_hyphens"] = df["url"].apply(count_hyphens)
df["has_ip"] = df["url"].apply(has_ip)
df["url_length"] = df["url"].apply(url_length)
df["num_at"] = df["url"].apply(count_at_symbols)
df["uses_https"] = df["url"].apply(is_https)

# Save extracted features
df.to_csv("features.csv", index=False)

print("✅ Features extracted and saved to features.csv")
