from flask import Flask, request, jsonify
import mysql.connector
from werkzeug.security import generate_password_hash

app = Flask(__name__)

db_config = {
    'user': 'root',
    'password': 'rocket',
    'host': 'localhost',
    'database': 'scheduling'
}

def get_db_connection():
    conn = mysql.connector.connect(**db_config)
    return conn

@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    first_name = data.get('firstName')
    last_name = data.get('lastName')
    email = data.get('email')
    password = data.get('password')
    hashed_password = generate_password_hash(password)

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO users (first_name, last_name, email, password) VALUES (%s, %s, %s, %s)",
                   (first_name, last_name, email, hashed_password))
    conn.commit()
    cursor.close()
    conn.close()
    return jsonify({'message': 'User registered successfully'}), 201

if __name__ == '__main__':
    app.run(debug=True)
