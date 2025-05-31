from flask import Flask, render_template, request, redirect, flash, url_for, send_from_directory
from werkzeug.utils import secure_filename
import hashlib
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from dotenv import load_dotenv
import os
import json
import time

# Load environment variables
load_dotenv()

# Flask setup
app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "testsecret")
bcrypt = Bcrypt(app)
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'pdf', 'jpg', 'jpeg', 'png'}
LEDGER_FILE = 'ledger.json'
USERS_FILE = 'users.json'

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Create upload and ledger files/folders if not exist
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

if not os.path.exists(LEDGER_FILE):
    with open(LEDGER_FILE, 'w') as f:
        json.dump([], f)

# Load users from USERS_FILE or initialize empty dict
if os.path.exists(USERS_FILE):
    with open(USERS_FILE, 'r') as f:
        users = json.load(f)
else:
    users = {}

# Allow only specific file types
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# User model
class User(UserMixin):
    def __init__(self, id, username, email):
        self.id = id
        self.username = username
        self.email = email

    def get_id(self):
        return self.email  # Email as unique ID

@login_manager.user_loader
def load_user(email):
    user = users.get(email)
    if user:
        return User(id=email, username=user['username'], email=email)
    return None

# Home route
@app.route('/')
def home():
    return render_template('home.html', user=current_user)

# Upload route with blockchain-style logging and file listing
@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    if request.method == 'POST':
        file = request.files['file']

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)

            # Compute hash of file
            with open(filepath, 'rb') as f:
                file_data = f.read()
                file_hash = hashlib.sha256(file_data).hexdigest()

            # Load existing ledger
            with open(LEDGER_FILE, 'r') as f:
                ledger = json.load(f)

            previous_hash = ledger[-1]['current_hash'] if ledger else "0"

            block = {
                'username': current_user.username,
                'filename': filename,
                'timestamp': time.strftime("%Y-%m-%d %H:%M:%S"),
                'file_hash': file_hash,
                'previous_hash': previous_hash,
                'current_hash': hashlib.sha256(f"{file_hash}{previous_hash}".encode()).hexdigest()
            }

            ledger.append(block)
            with open(LEDGER_FILE, 'w') as f:
                json.dump(ledger, f, indent=4)

            flash(f"✅ File uploaded and secured! Hash: {block['current_hash']}")
            return redirect(url_for('upload'))
        else:
            flash("❌ Invalid file type. Only PDF, JPG, PNG allowed.")

    # List all uploaded files
    files = os.listdir(app.config['UPLOAD_FOLDER'])
    return render_template('upload.html', files=files)

# Serve uploaded files
@app.route('/uploads/<filename>')
@login_required
def uploaded_file(filename):
    # Optional: You could verify if current_user owns the file here
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# Registration
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        if email in users:
            flash('⚠️ Email already registered!')
            return redirect(url_for('register'))

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        users[email] = {
            'username': username,
            'email': email,
            'password': hashed_password
        }

        # Save users dict to file
        with open(USERS_FILE, 'w') as f:
            json.dump(users, f, indent=4)

        flash('✅ Registration successful! You can now log in.')
        return redirect(url_for('login'))

    return render_template('register.html')

# Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = users.get(email)
        if user and bcrypt.check_password_hash(user['password'], password):
            login_user(User(id=email, username=user['username'], email=email))
            flash(f"👋 Welcome, {user['username']}!")
            return redirect(url_for('home'))
        else:
            flash('❌ Invalid email or password.')

    return render_template('login.html')

# Logout
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("🔒 You’ve been logged out.")
    return redirect(url_for('login'))

# Run the app
if __name__ == '__main__':
    app.run(debug=True)
