import uuid
import os
import re
import mysql.connector
from flask import Flask, request, jsonify, render_template, redirect, url_for
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity

load_dotenv()

app = Flask(__name__)
CORS(app)

app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY", "FALLBACK_SECRET_FOR_DEV") 
jwt = JWTManager(app)

def clean_phone_number(phone):
    if not phone:
        return None
    return re.sub(r'[^\d+]', '', phone)

def get_db_connection():
    return mysql.connector.connect(
        host=os.getenv("DB_HOST"),
        user=os.getenv("DB_USERNAME"),
        password=os.getenv("DB_PASSWORD"),
        database=os.getenv("DB_DATABASE"),
        port=os.getenv("DB_PORT")
    )

#-- PAGE ROUTES (SERVE HTML) --# 

app.route('/')
def index():
    # This makes the login page the "Home Page"
    return render_template('sign_in_page.html')

@app.route('/signup-page')
def signup_page():
    return render_template('signup_page.html')

@app.route('/admin')
@jwt_required()
def admin_page():
    return render_template('admin_page.html')

@app.route('/booking')
def booking_page():
    return render_template('customers_time.html')

#-- API ROUTES (HANDLE DATA) --# 

@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    user_id = str(uuid.uuid4())
    raw_phone = data.get('phoneNumber')
    phone_number = clean_phone_number(raw_phone)
    first_name = data.get('firstName')
    last_name = data.get('lastName')
    email = data.get('email')
    password = data.get('password')
    hashed_password = generate_password_hash(password)
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO users (user_id, first_name, last_name, email, phone_number, password) VALUES (%s, %s, %s, %s, %s, %s)",
            (user_id, first_name, last_name, email, phone_number, hashed_password)
        )
        conn.commit()
        return jsonify({'message': 'User registered successfully'}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
    user = cursor.fetchone()
    cursor.close()
    conn.close()
    if user and check_password_hash(user['password'], password):
        access_token = create_access_token(identity=user['user_id'], additional_claims={"role": user['role']})
        return jsonify({
            'message': 'Login successful',
            'token': access_token,
            'role': user['role'],
            'firstName': user['first_name']
        }), 200
    
    return jsonify({'message': 'Invalid email or password'}), 401

if __name__ == '__main__':
    app.run(debug=True, port=5001)