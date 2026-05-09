from flask import Flask, request, jsonify
from flask_cors import CORS
import pickle
import re

app = Flask(__name__)
CORS(app)

with open('model.pkl', 'rb') as f:
    model = pickle.load(f)

SAFE_DOMAINS = {
    'google.com', 'youtube.com', 'amazon.com', 'wikipedia.org',
    'reddit.com', 'twitter.com', 'github.com', 'instagram.com',
    'netflix.com', 'microsoft.com', 'apple.com', 'linkedin.com',
    'click.uz', 'payme.uz', 'uzum.uz', 'nbu.uz', 'gov.uz', 'collegeboard.org',
}

def get_domain(url):
    try:
        parts = url.split('/')[2].split('.')
        return '.'.join(parts[-2:])
    except:
        return ''
def extract_features(url):
    try:
        domain_part = url.split('/')[2]
    except:
        domain_part = url

    domain_length = len(domain_part)

    return [[
        len(url),
        url.count('.'),
        url.count('-'),
        url.count('/'),
        url.count('@'),
        sum(c.isdigit() for c in url),
        int(url.startswith('https')),
        int(bool(re.search(r'\d+\.\d+\.\d+\.\d+', url))),
        int(bool(re.search(r'login|verify|secure|account|update|bank|paypal|free|lucky|win', url.lower()))),
        max(0, len(domain_part.split('.')) - 2),
        domain_length,
        len(url) - len(domain_part),
        int('?' in url),
        int(bool(re.search(r'\.(tk|ml|ga|cf|gq|xyz|win|top|click|loan|work|party|racing)$', domain_part.lower()))),
    ]]
@app.route('/predict', methods=['POST'])
def predict():
    data = request.get_json()
    url = data.get('url', '')

    if not url:
        return jsonify({'error': 'URL не указан'}), 400

    # Whitelist — сразу безопасно
    domain = get_domain(url)
    if domain in SAFE_DOMAINS:
        return jsonify({'url': url, 'score': 0.0, 'verdict': 'safe'})

    features = extract_features(url)
    score = model.predict_proba(features)[0][1]

    if score > 0.7:
        verdict = 'phishing'
    elif score > 0.4:
        verdict = 'suspicious'
    else:
        verdict = 'safe'

    if url.startswith('chrome://') or url.startswith('chrome-extension://') or url.startswith('about:'):
        return jsonify({'url': url, 'score': 0.0, 'verdict': 'safe'})


    return jsonify({'url': url, 'score': round(score, 3), 'verdict': verdict})

if __name__ == '__main__':
    app.run(port=5000, debug=True)