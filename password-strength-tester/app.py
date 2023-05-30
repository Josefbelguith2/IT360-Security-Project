import requests
from flask import Flask, render_template, request, jsonify
from zxcvbn import zxcvbn
from datetime import timedelta
import hashlib

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/check_password_strength', methods=['POST'])
def check_password_strength():
    password = request.form['password']
    
    # Check if the password has been pwned
    pwned_count = check_password_pwned(password)
    
    result = zxcvbn(password)
    score = result['score']
    feedback = result['feedback']['suggestions']
    crack_time = result['crack_times_display']['offline_slow_hashing_1e4_per_second']
    
    return jsonify(score=score, feedback=feedback, crack_time=crack_time, pwned_count=pwned_count)

def check_password_pwned(password):
    sha1_hash = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix = sha1_hash[:5]
    suffix = sha1_hash[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    
    response = requests.get(url)
    if response.status_code == 200:
        hashes = response.text.split('\n')
        for h in hashes:
            if h.split(':')[0] == suffix:
                return int(h.split(':')[1])
    
    return 0

if __name__ == '__main__':
    app.run(debug=True,host='0.0.0.0')
