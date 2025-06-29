from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory, session
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import os, uuid, sqlite3, datetime

# --- Configuration ---
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'txt', 'docx'}
DB_FILE = 'file_share.db'

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.secret_key = 'supersecretkey'

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# --- Helpers ---
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_user_storage_usage(user_id):
    total = 0
    with sqlite3.connect(DB_FILE) as con:
        files = con.execute("SELECT filepath FROM files WHERE user_id = ?", (user_id,)).fetchall()
    for file in files:
        if os.path.exists(file[0]):
            total += os.path.getsize(file[0])
    return total / (1024 * 1024)  # MB

def ensure_all_users_have_storage_limits():
    with sqlite3.connect(DB_FILE) as con:
        con.execute("UPDATE users SET max_storage_mb = 100 WHERE max_storage_mb IS NULL")

def init_db():
    with sqlite3.connect(DB_FILE) as con:
        con.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE,
                email TEXT,
                password TEXT,
                is_admin INTEGER DEFAULT 0,
                max_storage_mb INTEGER DEFAULT 100
            )
        ''')
        con.execute('''
            CREATE TABLE IF NOT EXISTS files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                filename TEXT,
                filepath TEXT,
                upload_time TIMESTAMP,
                share_id TEXT,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        ''')
        # Ensure max_storage_mb exists for existing users
        ensure_all_users_have_storage_limits()

        # Create default admin
        admin = con.execute("SELECT * FROM users WHERE username = 'admin'").fetchone()
        if not admin:
            admin_pw = generate_password_hash("admin123")
            con.execute("INSERT INTO users (username, email, password, is_admin, max_storage_mb) VALUES (?, ?, ?, 1, 100)",
                        ("admin", "admin@example.com", admin_pw))
            print("✅ Admin created: username=admin, password=admin123")

# --- Routes ---
@app.route('/')
def index():
    if 'user_id' in session:
        user_id = session['user_id']
        with sqlite3.connect(DB_FILE) as con:
            files = con.execute("SELECT * FROM files WHERE user_id = ?", (user_id,)).fetchall()
            user = con.execute("SELECT max_storage_mb FROM users WHERE id = ?", (user_id,)).fetchone()

        if user is None:
            flash("User not found. Please log in again.", "danger")
            return redirect(url_for('logout'))

        usage_mb = get_user_storage_usage(user_id)
        return render_template('dashboard.html', files=files, is_admin=session.get('is_admin'),
                               usage_mb=usage_mb, max_mb=user[0])
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')

        if not username or not email or not password:
            flash("All fields are required", "danger")
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password)

        try:
            with sqlite3.connect(DB_FILE) as con:
                con.execute("INSERT INTO users (username, email, password, max_storage_mb) VALUES (?, ?, ?, ?)",
                            (username, email, hashed_password, 100))
            flash("Registration successful. Please log in.", "success")
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash("Username already exists. Please choose another.", "danger")

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        with sqlite3.connect(DB_FILE) as con:
            user = con.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
            if user and check_password_hash(user[3], password):
                session['user_id'] = user[0]
                session['is_admin'] = user[4] == 1
                flash("Login successful", "success")
                return redirect(url_for('index'))
            else:
                flash("Invalid username or password", "danger")

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for('login'))

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    file = request.files.get('file')
    if file and allowed_file(file.filename):
        user_id = session['user_id']
        with sqlite3.connect(DB_FILE) as con:
            user = con.execute("SELECT max_storage_mb FROM users WHERE id = ?", (user_id,)).fetchone()
        if user is None:
            flash("User not found.", "danger")
            return redirect(url_for('logout'))

        max_limit = user[0]
        used = get_user_storage_usage(user_id)

        if used >= max_limit:
            flash(f"Storage limit exceeded ({used:.2f}MB of {max_limit}MB used)", "danger")
            return redirect(url_for('index'))

        filename = secure_filename(file.filename)
        unique_id = str(uuid.uuid4())
        save_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_id + '_' + filename)
        file.save(save_path)

        with sqlite3.connect(DB_FILE) as con:
            con.execute("INSERT INTO files (user_id, filename, filepath, upload_time, share_id) VALUES (?, ?, ?, ?, ?)",
                        (user_id, filename, save_path, datetime.datetime.now(), str(uuid.uuid4())))

        flash("File uploaded successfully", "success")
    else:
        flash("Invalid file type", "danger")

    return redirect(url_for('index'))

@app.route('/download/<int:file_id>')
def download_file(file_id):
    with sqlite3.connect(DB_FILE) as con:
        file = con.execute("SELECT * FROM files WHERE id = ?", (file_id,)).fetchone()
        if file and (file[1] == session.get('user_id') or session.get('is_admin')):
            return send_from_directory(directory=os.path.dirname(file[3]), path=os.path.basename(file[3]), as_attachment=True)
    flash("Access denied or file not found", "danger")
    return redirect(url_for('index'))

@app.route('/share/<share_id>')
def shared_download(share_id):
    with sqlite3.connect(DB_FILE) as con:
        file = con.execute("SELECT * FROM files WHERE share_id = ?", (share_id,)).fetchone()
        if file:
            return send_from_directory(directory=os.path.dirname(file[3]), path=os.path.basename(file[3]), as_attachment=True)
    return 'Link expired or invalid.'

@app.route('/admin')
def admin_dashboard():
    if not session.get('is_admin'):
        return redirect(url_for('index'))

    with sqlite3.connect(DB_FILE) as con:
        users = con.execute("SELECT id, username, email, is_admin, max_storage_mb FROM users").fetchall()
        files = con.execute("SELECT f.id, u.username, f.filename, f.upload_time FROM files f JOIN users u ON f.user_id = u.id").fetchall()
    return render_template('admin.html', users=users, files=files)

# --- Run the App ---
if __name__ == '__main__':
    init_db()
    app.run(debug=True)
