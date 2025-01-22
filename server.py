from flask import Flask, render_template, request, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager, login_required, logout_user, login_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

app.config['SECRET_KEY'] = 'super_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    fullname = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone = db.Column(db.String(10), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='user')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route("/")
def home():
    return render_template('home.html')

@app.route("/login")
def login():
    return render_template('login.html')

@app.route("/register")
def register():
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

@login_manager.unauthorized_handler
def unauthorized_callback():
    return redirect('/login')

if __name__ == '__main__':
    app.run(debug=True)