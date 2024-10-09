from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import uuid
import jwt
from functools import wraps
import datetime
import hashlib  # For simulating credit score
import os

def init_db():
    conn = sqlite3.connect('loans.db')
    c = conn.cursor()
    # Update the users table to include ssn, dob, and address
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id TEXT PRIMARY KEY, username TEXT UNIQUE, password TEXT,
                  ssn TEXT, dob TEXT, address TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS loan_applications
                 (id TEXT PRIMARY KEY, user_id TEXT, name TEXT, amount REAL, purpose TEXT, 
                  credit_score INTEGER, income REAL, status TEXT, balance REAL)''')
    c.execute('''CREATE TABLE IF NOT EXISTS loan_payments
                 (id TEXT PRIMARY KEY, loan_id TEXT, amount REAL, date TEXT)''')
    conn.commit()
    conn.close()

app = Flask(__name__)
CORS(app)
app.config['SECRET_KEY'] = 'your_secret_key'  # Change this to a secure random key in production

init_db()

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = data['user_id']
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired!'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Token is invalid!'}), 401
        return f(current_user, *args, **kwargs)
    return decorated

@app.route('/')
def home():
    return send_from_directory('', 'index.html')

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    hashed_password = generate_password_hash(data['password'])
    user_id = str(uuid.uuid4())

    ssn = data['ssn']
    dob = data['dob']
    address = data['address']

    conn = sqlite3.connect('loans.db')
    c = conn.cursor()
    try:
        c.execute("INSERT INTO users (id, username, password, ssn, dob, address) VALUES (?, ?, ?, ?, ?, ?)",
                  (user_id, data['username'], hashed_password, ssn, dob, address))
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({"message": "Username already exists"}), 400
    conn.close()

    return jsonify({"message": "User registered successfully"}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    conn = sqlite3.connect('loans.db')
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username = ?", (data['username'],))
    user = c.fetchone()
    conn.close()

    if user and check_password_hash(user['password'], data['password']):
        token = jwt.encode({'user_id': user['id'], 'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)},
                           app.config['SECRET_KEY'], algorithm="HS256")
        # Include ssn, dob, and address in the response
        return jsonify({
            "token": token,
            "ssn": user['ssn'],
            "dob": user['dob'],
            "address": user['address']
        })

    return jsonify({"message": "Invalid credentials"}), 401

def get_credit_score(ssn):
    # Simulate a credit score using the SSN
    score = int(hashlib.sha256(ssn.encode()).hexdigest(), 16) % 601 + 300  # Generates a score between 300 and 900
    return score

@app.route('/apply', methods=['POST'])
@token_required
def apply_loan(current_user):
    data = request.json
    loan_id = str(uuid.uuid4())

    # Extract necessary information
    name = data['name']
    amount = float(data['amount'])
    purpose = data['purpose']
    income = float(data['income'])

    # Fetch the user's ssn, dob, and address from the database
    conn = sqlite3.connect('loans.db')
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT ssn, dob, address FROM users WHERE id = ?", (current_user,))
    user_info = c.fetchone()

    if not user_info['ssn']:
        # If ssn is not set, store it now
        ssn = data['ssn']
        dob = data['dob']
        address = data['address']

        # Update the user's ssn, dob, and address
        c.execute("UPDATE users SET ssn = ?, dob = ?, address = ? WHERE id = ?", (ssn, dob, address, current_user))
        conn.commit()
    else:
        # Use the stored ssn, dob, and address
        ssn = user_info['ssn']
        dob = user_info['dob']
        address = user_info['address']

    # Simulate fetching the credit score
    credit_score = get_credit_score(ssn)

    # Determine loan status based on approval criteria
    # Criteria: Credit score >= 650 and income >= 2 * loan amount
    if credit_score >= 650 and income >= 2 * amount:
        status = 'Approved'
    else:
        status = 'Rejected'

    # Set initial balance equal to the loan amount if approved
    balance = amount if status == 'Approved' else 0

    # Store the loan application with the determined status and balance
    c.execute("""INSERT INTO loan_applications 
                 (id, user_id, name, amount, purpose, credit_score, income, status, balance) 
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
              (loan_id, current_user, name, amount, purpose,
               credit_score, income, status, balance))
    conn.commit()
    conn.close()

    return jsonify({"message": f"Loan application {status.lower()}", "loan_id": loan_id}), 201

@app.route('/applications', methods=['GET'])
@token_required
def get_applications(current_user):
    conn = sqlite3.connect('loans.db')
    conn.row_factory = sqlite3.Row  # Allows us to access columns by name
    c = conn.cursor()
    c.execute("""SELECT id, name, amount, purpose, credit_score, income, status, balance 
                 FROM loan_applications WHERE user_id = ?""", (current_user,))
    applications = []
    for row in c.fetchall():
        app = {
            "id": row["id"],
            "name": row["name"],
            "amount": row["amount"],
            "purpose": row["purpose"],
            "credit_score": row["credit_score"],
            "income": row["income"],
            "status": row["status"],
            "balance": row["balance"]
        }
        applications.append(app)
    conn.close()

    return jsonify(applications)

@app.route('/loans', methods=['GET'])
@token_required
def get_loans(current_user):
    # Fetch approved loans with outstanding balances
    conn = sqlite3.connect('loans.db')
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("""SELECT id, amount, balance FROM loan_applications 
                 WHERE user_id = ? AND status = 'Approved' AND balance > 0""", (current_user,))
    loans = []
    for row in c.fetchall():
        loan = {
            "id": row["id"],
            "amount": row["amount"],
            "balance": row["balance"]
        }
        loans.append(loan)
    conn.close()

    return jsonify(loans)

@app.route('/pay', methods=['POST'])
@token_required
def make_payment(current_user):
    data = request.json
    loan_id = data['loan_id']
    payment_amount = float(data['amount'])

    conn = sqlite3.connect('loans.db')
    c = conn.cursor()

    # Verify the loan belongs to the user and is approved
    c.execute("""SELECT balance FROM loan_applications 
                 WHERE id = ? AND user_id = ? AND status = 'Approved'""", (loan_id, current_user))
    result = c.fetchone()
    if not result:
        conn.close()
        return jsonify({"message": "Loan not found or not eligible for payment"}), 400

    current_balance = result[0]
    if payment_amount <= 0:
        conn.close()
        return jsonify({"message": "Payment amount must be positive"}), 400

    if payment_amount > current_balance:
        conn.close()
        return jsonify({"message": "Payment amount exceeds outstanding balance"}), 400

    # Update the loan balance
    new_balance = current_balance - payment_amount
    c.execute("UPDATE loan_applications SET balance = ? WHERE id = ?", (new_balance, loan_id))

    # Record the payment
    payment_id = str(uuid.uuid4())
    payment_date = datetime.datetime.utcnow().isoformat()
    c.execute("INSERT INTO loan_payments (id, loan_id, amount, date) VALUES (?, ?, ?, ?)",
              (payment_id, loan_id, payment_amount, payment_date))

    conn.commit()
    conn.close()

    return jsonify({"message": "Payment successful", "new_balance": new_balance}), 200

@app.route('/payment_history/<loan_id>', methods=['GET'])
@token_required
def payment_history(current_user, loan_id):
    conn = sqlite3.connect('loans.db')
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    # Verify the loan belongs to the user
    c.execute("SELECT id FROM loan_applications WHERE id = ? AND user_id = ?", (loan_id, current_user))
    if not c.fetchone():
        conn.close()
        return jsonify({"message": "Loan not found"}), 400

    # Fetch payment history
    c.execute("SELECT amount, date FROM loan_payments WHERE loan_id = ? ORDER BY date DESC", (loan_id,))
    payments = []
    for row in c.fetchall():
        payment = {
            "amount": row["amount"],
            "date": row["date"]
        }
        payments.append(payment)
    conn.close()

    return jsonify(payments)

@app.route('/user_info', methods=['GET'])
@token_required
def get_user_info(current_user):
    # Fetch the user's ssn, dob, and address
    conn = sqlite3.connect('loans.db')
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT ssn, dob, address FROM users WHERE id = ?", (current_user,))
    user_info = c.fetchone()
    conn.close()

    return jsonify({
        "ssn": user_info['ssn'],
        "dob": user_info['dob'],
        "address": user_info['address']
    })

@app.route('/<path:path>')
def static_files(path):
    return send_from_directory('', path)

if __name__ == '__main__':
    app.run(debug=True)
