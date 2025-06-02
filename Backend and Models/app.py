from flask import Flask, request, jsonify, render_template
import sqlite3
import requests
import os
import hashlib
import base64
import json
import numpy as np 
import time 
app = Flask(__name__)


URLSCAN_API_KEY = "a5e5fa8da8f76934df9fd1040be9b557a5164047a2a6e3791de1cb506558ed0e"
URLSCAN_SUBMIT_URL = "https://urlscan.io/api/v1/scan/"
URLSCAN_RESULT_URL = "https://urlscan.io/api/v1/result/"


@app.route('/')
def home():
    return render_template('index.html')

@app.route('/dataleak')
def dataleak_page():
    return render_template('dataleaks.html')

@app.route('/chatbotUi')
def chatbot_page():
    return render_template('chatbot.html')

@app.route('/urlscannerWeb')
def urlscanner_page():
    return render_template('urlscanner.html')

@app.route('/passwordchecker')
def passwordchecker_page():
    return render_template('passwordchecker.html')

@app.route('/phonenumberChecker')
def phonenumberchecker_page():
    return render_template('phonenumberChecker.html')

# --- URL Scanner (URLScan.io Integration) ---

# Commented out the ML model loading and preprocessing as requested
# try:
#     # Load the trained model and char2idx
#     model = load_model('models/phishing_url_model.h5')
#     with open('models/char2idx.json') as f:
#         char2idx = json.load(f)
#     max_len = 200  # Make sure this matches your training setting
# except Exception as e:
#     print(f"Error loading ML model or char2idx: {e}. URL prediction will rely on URLScan.io only.")
#     model = None
#     char2idx = None

# def preprocess_url(url):
#     if char2idx is None:
#         return np.array([[]]) # Return empty if char2idx is not loaded
#     seq = [char2idx.get(c, 0) for c in url]
#     if len(seq) < max_len:
#         seq += [0] * (max_len - len(seq))
#     else:
#         seq = seq[:max_len]
#     return np.array([seq])  # Return 2D array for model


@app.route('/predict_url', methods=['POST'])
def predict_url():
    """
    Receives a URL from the frontend, submits it to URLScan.io for analysis,
    and returns a prediction (malicious/safe) based on the scan results.
    """
    data = request.get_json()
    url_to_scan = data.get('url', '')

    
    if not url_to_scan:
        return jsonify({'prediction': 0, 'message': 'No URL provided.'}), 400

    
    if URLSCAN_API_KEY == 'YOUR_URLSCAN_API_KEY_HERE' or not URLSCAN_API_KEY:
        return jsonify({'prediction': 0, 'message': 'URLScan.io API key is not configured.'}), 500

    headers = {'API-Key': URLSCAN_API_KEY, 'Content-Type': 'application/json'}
    print(f"Attempting to submit URL: {url_to_scan}")

    
    try:
        payload = {'url': url_to_scan, 'visibility': 'public'} 
        submit_response = requests.post(URLSCAN_SUBMIT_URL, headers=headers, json=payload)
        submit_response.raise_for_status() 
        submit_data = submit_response.json()
        print(f"Submit response status: {submit_response.status_code}") 
        print(f"Submit response JSON: {submit_data}") 

        if submit_data.get('uuid'):
            scan_uuid = submit_data['uuid']
            print(f"URL submitted. Scan UUID: {scan_uuid}") 

           
            print("Waiting 10 seconds for scan to complete...")
            time.sleep(10) 
            print("Done waiting. Fetching results...") # Debug print

            result_response = requests.get(f"{URLSCAN_RESULT_URL}{scan_uuid}/", headers=headers)
            result_response.raise_for_status() # Raise an exception for HTTP errors
            result_data = result_response.json()
            print(f"Result response status: {result_response.status_code}") # Debug print
            print(f"Result response JSON: {result_data}") # Debug print

            # Step 3: Analyze the results for malicious indicators
            is_malicious = False
            message = "No immediate threats detected by URLScan.io."
            
            overall_verdict = result_data.get('verdicts', {}).get('overall', {})
            
            # Check for explicit malicious flag
            if overall_verdict.get('malicious'):
                is_malicious = True
                message = overall_verdict.get('description', 'Malicious URL detected by URLScan.io.')
            # Check for a suspicious score (adjusted threshold)
            elif overall_verdict.get('score', 0) >= 30: # Lowered threshold from 50 to 30
                is_malicious = True # Treat as malicious if score is 30 or higher
                message = f"Suspicious activity detected (Score: {overall_verdict.get('score')}). Consider with caution."
            
            # Check for malicious stats (e.g., detected by other engines)
            elif result_data.get('stats', {}).get('malicious'):
                is_malicious = True
                message = "Malicious activity reported by URLScan.io stats."

            # Construct the response for the frontend
            if is_malicious:
                return jsonify({
                    'prediction': 1, # 1 for malicious
                    'message': message,
                    'urlscan_report_link': result_data.get('task', {}).get('reportURL')
                })
            else:
                return jsonify({
                    'prediction': 0, # 0 for safe
                    'message': message,
                    'urlscan_report_link': result_data.get('task', {}).get('reportURL')
                })

        else:
            print("Error: No UUID received from URLScan.io submission.") # Debug print
            return jsonify({'prediction': 0, 'message': 'Failed to submit URL for scanning (No UUID).'}), 500

    except requests.exceptions.HTTPError as e:
        # Log detailed HTTP error for debugging
        print(f"HTTP Error from URLScan.io: {e.response.status_code} - {e.response.text}")
        return jsonify({'prediction': 0, 'message': f'URLScan.io HTTP Error: {e.response.status_code}. Please check your API key or URLScan.io status.'}), 500
    except requests.exceptions.ConnectionError as e:
        print(f"Connection Error: {e}")
        return jsonify({'prediction': 0, 'message': 'Failed to connect to URLScan.io. Check internet connection or firewall.'}), 500
    except requests.exceptions.Timeout as e:
        print(f"Timeout Error: {e}")
        return jsonify({'prediction': 0, 'message': 'URLScan.io request timed out. Please try again.'}), 500
    except requests.exceptions.RequestException as e:
        print(f"General Request Error: {e}")
        return jsonify({'prediction': 0, 'message': f'API request error: {e}.'}), 500
    except Exception as e:
        print(f"An unexpected error occurred in predict_url: {e}")
        return jsonify({'prediction': 0, 'message': f'An unexpected error occurred: {e}'}), 500

# --- Other API Routes ---

# --- Configuration ---
# Your single IPQS API Key
# IMPORTANT: For production, store this in an environment variable!
# IPQS_API_KEY = os.getenv('IPQS_API_KEY')
# For development, you can keep it hardcoded for now, but be mindful of security.
IPQS_API_KEY = "uGHW5Ye69CyTpqzmZbAQQ32WLiVS5lS2"

# --- IPQualityScore API Base URLs for different services ---
IPQS_EMAIL_API_BASE_URL = "https://www.ipqualityscore.com/api/json/email"
IPQS_PHONE_API_BASE_URL = "https://www.ipqualityscore.com/api/json/phone" # Assuming this is your phone endpoint

# --- Frontend Route: Serves your HTML page ---
@app.route('/')
def index():
    return render_template('index.html') # This tells Flask to serve the index.html file

# --- API Route: Email Data Leak Checker ---
@app.route('/api/check-email-leak', methods=['POST'])
def check_email_leak():
    data = request.get_json()
    email = data.get('email')

    if not email:
        return jsonify({'error': 'No email provided'}), 400

    if not IPQS_API_KEY:
        return jsonify({'error': 'IPQS_API_KEY is not configured. Please set it.'}), 500

    if "@" not in email or "." not in email.split('@')[-1]:
        return jsonify({'error': 'Invalid email format provided.'}), 400

    try:
        ipqs_url = f"{IPQS_EMAIL_API_BASE_URL}/{IPQS_API_KEY}/{email}"
        print(f"Attempting to call IPQS Email API: {ipqs_url}") # Debugging
        response = requests.get(ipqs_url, timeout=10)

        # Attempt to parse JSON. If it fails, print the raw response.
        try:
            ipqs_email_data = response.json()
        except requests.exceptions.JSONDecodeError:
            print(f"Error: Expected JSON from IPQS Email API, but received: {response.text[:500]}...")
            return jsonify({'error': 'Failed to decode JSON from IPQS Email API. Received unexpected response.', 'raw_response_start': response.text[:100]}), 500

        response.raise_for_status() # Raise an exception for HTTP errors (4xx or 5xx)

        is_breached = False
        if 'leaked' in ipqs_email_data and ipqs_email_data['leaked'] is True:
            is_breached = True
        elif 'breached' in ipqs_email_data and ipqs_email_data['breached'] is True:
            is_breached = True

        return jsonify({
            'breached': is_breached,
            'ipqs_email_details': ipqs_email_data
        })

    except requests.exceptions.Timeout:
        return jsonify({'error': 'Request to IPQualityScore Email API timed out.'}), 504
    except requests.exceptions.ConnectionError:
        return jsonify({'error': 'Failed to connect to IPQualityScore Email API. Check internet or IPQS service status.'}), 503
    except requests.exceptions.HTTPError as http_err:
        print(f"IPQS Email API HTTP Error: {http_err.response.status_code} - {http_err.response.text}")
        if http_err.response.status_code == 401:
            return jsonify({'error': 'IPQualityScore API Key is unauthorized or invalid for Email Validation. Check your key and plan.'}), 401
        elif http_err.response.status_code == 429:
            return jsonify({'error': 'IPQualityScore Email API rate limit exceeded. Please try again later.'}), 429
        else:
            return jsonify({'error': f'IPQualityScore Email API HTTP error: {http_err.response.status_code} - {http_err.response.text}'}), 500
    except Exception as e:
        return jsonify({'error': f'An unexpected server error occurred during email check: {str(e)}'}), 500


IPQS_API_KEY = "uGHW5Ye69CyTpqzmZbAQQ32WLiVS5lS2" # This key is for phone checker

@app.route('/api/phone-check', methods=['POST'])
def phone_check():
    data = request.get_json()
    phonenumber = data.get('phonenumber')
    if not phonenumber:
        return jsonify({'error': 'No phone number provided'}), 400

    try:
        # IPQualityScore API endpoint
        url = f"https://ipqualityscore.com/api/json/phone/{IPQS_API_KEY}/{phonenumber}"
        resp = requests.get(url)
        resp.raise_for_status() # Raise an exception for bad status codes
        result = resp.json()
        # Optionally, filter/format the result before returning
        return jsonify({
            'valid': result.get('valid'),
            'country_name': result.get('country_name'),
            'city': result.get('city'),
            'carrier': result.get('carrier'),
            'line_type': result.get('line_type'),
            'risk_score': result.get('risk_score'),
            'spammer': result.get('spammer')
        })
    except requests.exceptions.RequestException as e:
        return jsonify({'error': f'API connection error: {e}'}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/password-strength', methods=['POST'])
def password_strength():
    data = request.get_json()
    password = data.get('password')
    if not password:
        return jsonify({'error': 'No password provided'}), 400

    try:
        api_url = f"https://api.apiverve.com/v1/passwordstrength?password={password}"
        headers = {
            'x-api-key': '8e518f8e-ba0f-4509-9b9f-f15a2ac392c1', # This key is for password strength
            'Accept': 'application/json'
        }
        resp = requests.get(api_url, headers=headers)
        resp.raise_for_status()
        api_result = resp.json()
        if api_result.get('status') != 'ok' or not api_result.get('data'):
            return jsonify({'error': api_result.get('error', 'API Error')}), 500

        # Flatten the result for the frontend
        return jsonify({
            'strength': api_result['data']['strength'],
            'passwordInfo': api_result['data']['passwordInfo']
        })
    except requests.exceptions.RequestException as e:
        return jsonify({'error': f'API connection error: {e}'}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# --- Chatbot API ---
import google.generativeai as genai
GEMINI_API_KEY = "AIzaSyBGFtfGdfSz-ROyo2hdh4-m0jy14m241LQ" # This key is for chatbot
genai.configure(api_key=GEMINI_API_KEY)

@app.route('/api/chatbot', methods=['POST'])
def chatbot():
    data = request.get_json()
    user_message = data.get('message')
    if not user_message:
        return jsonify({'reply': "Please provide a message."}), 400

    try:
        model = genai.GenerativeModel('gemini-1.5-flash')
        response = model.generate_content(
    f"You are a helpful assistant for cybersecurity and cyberattack questions. {user_message}"
)
        reply = response.text.strip()
        return jsonify({'reply': reply})
    except Exception as e:
        return jsonify({'reply': f"Error: {str(e)}"}), 500

# --- User Management (Database) ---
def get_db():
    conn = sqlite3.connect('users.db')
    conn.row_factory = sqlite3.Row
    return conn

with get_db() as db:
    db.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    ''')
    db.commit()

@app.route('/register', methods=['POST'])       
def register():
    data = request.get_json(force=True)
    print("Received registration:", data)
    email = data['email']
    password = data['password']
    try:
        with get_db() as db:
            db.execute("INSERT INTO users (email, password) VALUES (?, ?)", (email, password))
            db.commit()   
        return jsonify({'success': True})
    except sqlite3.IntegrityError:
        return jsonify({'success': False, 'error': 'Email already registered'}), 400
    
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute("SELECT password FROM users WHERE email = ?", (email,))
    row = cursor.fetchone()
    conn.close()
    if row and row[0] == password:
        return jsonify({'success': True})
    else:
        return jsonify({'success': False})

if __name__ == '__main__':
    app.run(debug=True)