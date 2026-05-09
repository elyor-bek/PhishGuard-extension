print("Скрипт запустился")

import pandas as pd
import re
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
import pickle

tranco = pd.read_csv('top-1m.csv', header=None, names=['rank', 'domain'])
print("Импорты ок")

def extract_features(url):
    try:
        domain_part = url.split('/')[2]
    except:
        domain_part = url

    domain_length = len(domain_part)


    return {
        'length': len(url),
        'num_dots': url.count('.'),
        'num_hyphens': url.count('-'),
        'num_slashes': url.count('/'),
        'num_at': url.count('@'),
        'num_digits': sum(c.isdigit() for c in url),
        'has_https': int(url.startswith('https')),
        'has_ip': int(bool(re.search(r'\d+\.\d+\.\d+\.\d+', url))),
        'has_suspicious_words': int(bool(re.search(
            r'login|verify|secure|account|update|bank|paypal|free|lucky|win',
            url.lower()
        ))),
        'subdomain_count': max(0, len(domain_part.split('.')) - 2),
        'domain_length': domain_length,
        'path_length': len(url) - len(domain_part),
        'has_query_params': int('?' in url),
        'suspicious_tld': int(bool(re.search(
    r'\.(tk|ml|ga|cf|gq|xyz|win|top|click|loan|work|party|racing)$',
    url.lower().split('/')[2] if '/' in url else url.lower()
))),
    }

print("Читаю CSV...")
phish_df = pd.read_csv('PhiUSIIL_Phishing_URL_Dataset.csv', usecols=['URL', 'label'])
phish_df = phish_df[phish_df['label'] == 0][['URL']].rename(columns={'URL': 'url'})
phish_df['label'] = 1
phish_df = phish_df.head(50000)  


tranco = pd.read_csv('top-1m.csv', header=None, names=['rank', 'domain'])
tranco['url'] = 'https://www.' + tranco['domain']
tranco['label'] = 0
tranco = tranco[['url', 'label']].head(50000) 

df = pd.concat([phish_df, tranco], ignore_index=True).sample(frac=1, random_state=42)
print(f"Фишинг: {len(phish_df)}, легитимных: {len(tranco)}, итого: {len(df)}")

df['label'] = 1 - df['label']
print("Извлекаю фичи...")


features = df['url'].apply(extract_features).apply(pd.Series)
X = features
y = df['label']
print("Фичи готовы, обучаю модель...")

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
model = RandomForestClassifier(n_estimators=100, random_state=42, class_weight='balanced')
model.fit(X_train, y_train)
print("Модель обучена!")

y_pred = model.predict(X_test)
print(f"Accuracy: {accuracy_score(y_test, y_pred):.2%}")
print(classification_report(y_test, y_pred))

with open('model.pkl', 'wb') as f:
    pickle.dump(model, f)

print("Модель сохранена!")