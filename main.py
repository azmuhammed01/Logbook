from flask import Flask, render_template, request, url_for, session, flash, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
from datetime import timedelta, datetime
import csv
from io import StringIO
from flask import make_response
import os
from flask_migrate import Migrate


load_dotenv()


# Create a Flask application instance
app = Flask(__name__)
app.permanent_session_lifetime = timedelta(days=365)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.secret_key = '08069Xx100%'
app.config['SECRET_KEY'] = '08069Xx100%'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
migrate = Migrate(app, db)
def send_reset_email(to_email, reset_url):
    message = Mail(
        from_email=,
        to_emails=to_email,
        subject='Password Reset Request',
        plain_text_content=reset_url
    )
    try:
        sg = SendGridAPIClient(os.getenv("DY3SgUOAQWyfHvSt4W1"))
        response = sg.send(message)
        print("Email sent:", response.status_code)
    except Exception as e:
        print("SendGrid error:", {e})

def get_serializer():
    return URLSafeTimedSerializer(app.secret_key)

#Creating a Model for the Database
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(100), nullable=False, unique=True)
    password = db.Column(db.String(100), nullable=False)

class Log(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.DateTime, default=datetime.utcnow)
    title = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return f"<Log {self.title}>"
    
#Creating a representation
def __repr__(self):
    return f"<User {self.name}>"

#Creating a route for the home page
@app.route('/')
def home():
    return render_template('index.html')

#Creating a route for the signup page
@app.route('/signup', methods=['POST', 'GET'])
def signup():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm']
        existing = User.query.filter_by(email=email).first()
        if existing:
            flash('Email already exists Try to Login')
            return redirect(url_for('signup'))
        if password != confirm_password:
            flash('Password does not match')
            return redirect(url_for('signup'))
        hashed_pw = bcrypt.generate_password_hash(password)
        new_user = User(name=name, email=email, password=hashed_pw)
        db.session.add(new_user)
        db.session.commit()
        flash('Account created successfully Try to Login ')
        return redirect(url_for('signup'))
    return render_template('signup.html')

#Creating a route for the login page
@app.route('/login', methods=['POST', 'GET'])
def login():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['user_name'] = user.name
            session.permanent = True
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password')
            return redirect(url_for('login'))
    return render_template('login.html')

#Creating a route for the dashboard
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    user_name = session['user_name']
    logs = Log.query.filter_by(user_id=user_id).order_by(Log.date.desc()).all()
    return render_template('dashboard.html', user_name=user_name, logs=logs)

#Creating a route for the logout
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('user_name', None)
    flash('You have been logged out')
    return redirect(url_for('login'))

#Creating a route for the forgot password
@app.route('/forgot', methods=['POST', 'GET'])
def forgot():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        if user:
            serializer = get_serializer()
            token = serializer.dumps(user.email, salt='password-reset')
            reset_url = url_for('reset_with_token', token=token, _external=True)
            send_reset_email(user.email, reset_url)
            flash('Password reset link has been sent to your email.', 'info')
            return redirect(url_for('login'))
        else:
            flash('Email not found', 'danger')
            return redirect(url_for('forgot'))
    return render_template('forgot-password.html')

#Creating the reset password
@app.route('/reset/<token>', methods=['GET', 'POST'])
def reset_with_token(token):
    serializer = get_serializer()
    try:
        email = serializer.loads(token, salt='password-reset', max_age=300)
    except SignatureExpired:
        flash('The link has expired.', 'danger')
        return redirect(url_for('forgot'))
    except BadSignature:
        flash('Invalid reset token.', 'danger')
        return redirect(url_for('forgot'))

    user = User.query.filter_by(email=email).first()
    if request.method == 'POST':
        new_password = request.form['password']
        hashed_pw = bcrypt.generate_password_hash(new_password)
        user.password = hashed_pw
        db.session.commit()
        flash('Password has been reset. You can now log in.', 'success')
        return redirect(url_for('login'))

    return render_template('reset-password.html', token=token)


@app.route('/add-log', methods=['GET', 'POST'])
def add_log():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        new_log = Log(title=title, description=description, user_id=session['user_id'])
        db.session.add(new_log)
        db.session.commit()
        return redirect(url_for('dashboard'))

    return render_template('addlog.html')

@app.route('/edit-log/<int:log_id>', methods=['GET', 'POST'])
def edit_log(log_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    log = Log.query.get_or_404(log_id)

    if log.user_id != session['user_id']:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        log.title = request.form['title']
        log.description = request.form['description']
        db.session.commit()
        return redirect(url_for('dashboard'))

    return render_template('editlog.html', log=log)

@app.route('/delete-log/<int:log_id>', methods=['POST'])
def delete_log(log_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    log = Log.query.get_or_404(log_id)

    if log.user_id != session['user_id']:
        return redirect(url_for('dashboard'))

    db.session.delete(log)
    db.session.commit()
    return redirect(url_for('dashboard'))


@app.route('/export-csv')
def export_csv():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    logs = Log.query.filter_by(user_id=user_id).order_by(Log.date.desc()).all()

    si = StringIO()
    writer = csv.writer(si, quoting=csv.QUOTE_MINIMAL)

    # Custom headers
    writer.writerow(['Log Title', 'Content', 'Logged On'])

    for log in logs:
        title = log.title.upper()
        description = log.description
        date = log.date.strftime('%A, %d %B %Y %I:%M %p')

        writer.writerow([title, description, date])

    response = make_response(si.getvalue())
    response.headers["Content-Disposition"] = "attachment; filename=my_logbook_export.csv"
    response.headers["Content-type"] = "text/csv"
    return response

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)