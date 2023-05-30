# Import required libraries
import requests
from flask import Flask, render_template, request, jsonify
from zxcvbn import zxcvbn
import hashlib

# Create Flask application instance
app = Flask(__name__)

# Route for the homepage
@app.route('/')
def index():
    return render_template('index.html')

# Route for checking password strength
@app.route('/check_password_strength', methods=['POST'])
def check_password_strength():
    password = request.form['password']
    
    # Check if the password has been pwned
    pwned_count = check_password_pwned(password)
    
    # Use zxcvbn library to calculate password strength
    result = zxcvbn(password)
    score = result['score']
    feedback = result['feedback']['suggestions']
    crack_time = result['crack_times_display']['offline_slow_hashing_1e4_per_second']
    
    # Return the password strength information as JSON response
    return jsonify(score=score, feedback=feedback, crack_time=crack_time, pwned_count=pwned_count)

# Function to check if the password has been pwned
def check_password_pwned(password):
    # Generate SHA-1 hash of the password
    sha1_hash = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix = sha1_hash[:5]
    suffix = sha1_hash[5:]
    
    # Make request to the Pwned Passwords API to check for pwned passwords
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    response = requests.get(url)
    
    # If the API request is successful, check if the password hash exists in the response
    if response.status_code == 200:
        hashes = response.text.split('\n')
        for h in hashes:
            if h.split(':')[0] == suffix:
                return int(h.split(':')[1])
    
    # If the password hash is not found, return 0 indicating it has not been pwned
    return 0

# Run the Flask application if this script is executed directly
if __name__ == '__main__':
    app.run()
