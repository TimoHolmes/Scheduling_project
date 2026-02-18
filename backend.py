import uuid
import os
import re
import mysql.connector
from flask import Flask, request, jsonify, render_template, make_response
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, 
    get_jwt_identity, set_access_cookies, unset_jwt_cookies
)


load_dotenv()

app = Flask(__name__)
CORS(app, supports_credentials=True)

# JWT Configuration for secure HttpOnly Cookies
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY", "dev-secret-key")
app.config["JWT_TOKEN_LOCATION"] = ["cookies"]
app.config["JWT_COOKIE_SECURE"] = False  # Set to True if using HTTPS
app.config["JWT_COOKIE_HTTPONLY"] = True # Mitigates XSS by hiding cookie from JS
app.config["JWT_ACCESS_COOKIE_PATH"] = "/"
app.config["JWT_COOKIE_CSRF_PROTECT"] = False

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

@app.route('/')
def index():
    return render_template('sign_in_page.html')

@app.route('/signup-page')
def signup_page_route():
    return render_template('signup_page.html')

@app.route('/admin')
def admin_page():
    # Page logic in admin_page.html handles the initial role check via localStorage
    return render_template('admin_page.html')

@app.route('/booking')
def booking_page():
    return render_template('customers_time.html')
#-- API ROUTES (HANDLE DATA) --# 

@app.route('/signup', methods=['POST'])
def signup():
    """Registers a new user with a hashed password and unique UUID."""
    data = request.get_json()
    user_id = str(uuid.uuid4())
    hashed_pw = generate_password_hash(data.get('password'))
    phone = clean_phone_number(data.get('phoneNumber'))
    
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO users (user_id, first_name, last_name, email, phone_number, password) VALUES (%s, %s, %s, %s, %s, %s)",
            (user_id, data.get('firstName'), data.get('lastName'), data.get('email'), phone, hashed_pw)
        )
        conn.commit()
        return jsonify({'message': 'Registration successful'}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM users WHERE email = %s", (data.get('email'),))
    user = cursor.fetchone()
    cursor.close()
    conn.close()
    
    if user and check_password_hash(user['password'], data.get('password')):
        access_token = create_access_token(identity=user['user_id'], additional_claims={"role": user['role']})
        
        resp = jsonify({
            'login': True,
            'role': user['role'],
            'firstName': user['first_name']
        })
        set_access_cookies(resp, access_token)
        return resp, 200
    
    return jsonify({'message': 'Invalid email or password'}), 401

@app.route('/logout', methods=['POST'])
def logout():
    """Clears the JWT cookies to log the user out."""
    resp = jsonify({'logout': True})
    unset_jwt_cookies(resp)
    return resp, 200

@app.route('/save_availability', methods=['POST'])
@jwt_required()
def save_availability():
    data = request.get_json()
    selected_date = data.get('date')
    active_slots = data.get('slots')
    
    # NEW: Get the admin's ID from the JWT cookie
    current_admin_id = get_jwt_identity() 

    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        # Only clear slots for THIS admin on THIS date
        cursor.execute(
            "DELETE FROM availability WHERE available_date = %s AND user_id = %s", 
            (selected_date, current_admin_id)
        )
        
        for slot in active_slots:
            cursor.execute(
                "INSERT INTO availability (availability_id, user_id, available_date, time_slot) VALUES (%s, %s, %s, %s)",
                (str(uuid.uuid4()), current_admin_id, selected_date, slot)
            )
        conn.commit()
        return jsonify({'message': 'Schedule updated successfully'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()
        conn.close()
        
@app.route('/get_availability', methods=['GET'])
def get_availability():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("SELECT available_date, time_slot FROM availability WHERE available_date >= CURDATE() ORDER BY available_date, time_slot")
        rows = cursor.fetchall()
        
        for row in rows:
            row['available_date'] = row['available_date'].strftime('%Y-%m-%d')
            
        return jsonify(rows), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()
        conn.close()



if __name__ == '__main__':

    app.run(debug=True, port=5001)