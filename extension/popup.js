document.getElementById('check-btn').addEventListener('click', async () => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const url = tab?.url;

    if (!url) {
    document.getElementById('result').textContent = 'Failed to get URL';
    return;
  }


  if (url.startsWith('chrome://') || url.startsWith('chrome-extension://') || url.startsWith('about:')) {
    document.getElementById('url-text').textContent = url;
    document.getElementById('result').textContent = '— System page';
    document.getElementById('result').className = '';
    document.getElementById('score-text').textContent = '';
    return;
  }

  document.getElementById('url-text').textContent = url;
  document.getElementById('result').textContent = 'Checking...';
  document.getElementById('result').className = '';

  try {
    const response = await fetch('http://localhost:5000/predict', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url })
    });

    const data = await response.json();

    const labels = {
      safe:       '✓ Safe',
      suspicious: '⚠ Suspicious',
      phishing:   '✗ Phishing!'
    };

    document.getElementById('result').textContent = labels[data.verdict];
    document.getElementById('result').className = data.verdict;
    document.getElementById('score-text').textContent = `Score: ${(data.score * 100).toFixed(0)}%`;

  } catch (e) {
    document.getElementById('result').textContent = 'Error - API not running';
    document.getElementById('result').className = 'suspicious';
  }
});