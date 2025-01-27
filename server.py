from flask import Flask, render_template, request, redirect, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager, login_required, logout_user, login_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

app = Flask(__name__)

app.config['SECRET_KEY'] = 'super_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(150), nullable=False)
    last_name = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone = db.Column(db.String(10), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='visitor')

@app.route("/")
def home():
    return render_template('home.html')

@app.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            if current_user.role != 'admin':
                return redirect('/profile')
            else:
                return redirect('/dashboard')
        else:
            flash("Invalid username or password")
            return redirect('/login') 
    else:
        return render_template('login.html')
    
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route("/register", methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        first_name = request.form.get('first-name')
        last_name = request.form.get('last-name')
        email = request.form.get('email')
        phone = request.form.get('phone')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm-password')
        
        if password != confirm_password:
            flash("Passwords do not match")
            return redirect('/register')
        
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256', salt_length=16)     
        
        user = User(first_name=first_name, last_name=last_name, email=email, phone=phone, password=hashed_password)
        try:
            db.session.add(user)
            db.session.commit()
            return redirect('/login')
        except Exception as e:
            print(f"Error: {e}")
            return redirect('/register')
    return render_template('register.html')

@app.route("/exhibits")
def exhibits():
    return render_template('exhibits.html')

@app.route("/events")
def events():
    return render_template('events.html')

@app.route("/news")
def news():
    return render_template('news.html')

@app.route("/services")
def services():
    return render_template('services.html')

@app.route("/feedback")
def feedback():
    return render_template('feedback.html')

@app.route("/contact")
def contact():
    return render_template('contact.html')

@app.route("/profile")
@login_required
def profile():
    return render_template('profile.html')

@app.route("/dashboard")
@login_required
def dashboard():
    if current_user.role != 'admin':
        return "Unauthorized", 403
    return render_template('dashboard.html')

@app.route("/logout")
def logout():
    logout_user()
    return redirect('/')

@app.route("/dashboard/add/news")
@login_required
def add_news():
    if current_user.role != 'admin':
        return "Unauthorized", 403
    return render_template('add_news.html')

@app.route("/dashboard/add/event")
@login_required
def add_event():
    if current_user.role != 'admin':
        return "Unauthorized", 403
    return render_template('add_event.html')

@app.route("/dashboard/view/messages")
@login_required
def view_messages():
    if current_user.role != 'admin':
        return "Unauthorized", 403
    return render_template('view_messages.html')

@app.route("/dashboard/view/feedback")
@login_required
def view_feedback():
    if current_user.role != 'admin':
        return "Unauthorized", 403
    return render_template('view_feedback.html')

@login_manager.unauthorized_handler
def unauthorized_callback():
    return redirect('/login')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
    # from waitress import serve
    # serve(app, host="0.0.0.0", port=8080)