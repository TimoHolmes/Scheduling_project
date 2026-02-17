import uuid
from flask import Flask, request, jsonify
import mysql.connector
from werkzeug.security import generate_password_hash, check_password_hash
import os
from dotenv import load_dotenv
import re

def clean_phone_number(phone):
    if not phone:
        return None
    return re.sub(r'[^\d+]', '', phone)

app = Flask(__name__)

def get_db_connection():
    conn = mysql.connector.connect(
        host=os.getenv("DB_HOST"),
        user=os.getenv("DB_USERNAME"),
        password=os.getenv("DB_PASSWORD"),
        database=os.getenv("DB_DATABASE")
    )
    return conn

@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    user_id = str(uuid.uuid4())
    
    # Clean the phone number before doing anything else
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

@app.route('/login', methods= ['POST'])
def login(): 
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    conn = get_db_connection()
    # Using dictionary=True makes 'user' a dict instead of a tuple
    cursor = conn.cursor(dictionary=True) 
    
    cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
    user = cursor.fetchone()
    
    cursor.close()
    conn.close()

    # Now you can use user['password'] instead of user[4]
    if user and check_password_hash(user['password'], password):
        return jsonify({
            'message': 'Login successful',
            'user': {
                'id': user['user_id'],
                'firstName': user['first_name'],
                'email': user['email']
            }
        }), 200
        
    return jsonify({'message': 'Invalid email or password'}), 401

if __name__ == '__main__':
    app.run(debug=True)
