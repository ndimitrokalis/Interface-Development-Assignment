from flask import Flask, render_template, request, redirect, flash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import and_
from flask_login import UserMixin, LoginManager, login_required, logout_user, login_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timezone
from tzlocal import get_localzone
import pytz

app = Flask(__name__)

app.config['SECRET_KEY'] = 'super_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)

def get_local_today_date():
    local_timezone = get_localzone()
    utc_now = datetime.utcnow().replace(tzinfo=pytz.utc)
    local_now = utc_now.astimezone(local_timezone)
    return local_now.date()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(150), nullable=False)
    last_name = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone = db.Column(db.String(10), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='visitor')
    tickets = db.relationship('Ticket', back_populates='visitor')
    feedbacks = db.relationship('Feedback', back_populates='visitor')

class Ticket(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    visitor_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    event_id = db.Column(db.Integer, db.ForeignKey('event.id'), nullable=True)
    date = db.Column(db.Date, default=lambda: datetime.now(timezone.utc).date(), nullable=False)
    type = db.Column(db.String(10), nullable=False)
    amount = db.Column(db.Integer, default=1, nullable=True)
    visitor = db.relationship('User', back_populates='tickets')
    event = db.relationship('Event', back_populates='tickets')
    feedback = db.relationship('Feedback', back_populates='ticket', uselist=False)

class Event(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=False)
    date = db.Column(db.Date, nullable=False)
    price = db.Column(db.String(50), nullable=False, default="Free")
    image = db.Column(db.String(255), nullable=False)
    is_listed = db.Column(db.Boolean, default=True, nullable=False)
    tickets = db.relationship('Ticket', back_populates='event')
    
class News(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=False)
    image = db.Column(db.String(255), nullable=False)
    category = db.Column(db.String(50), nullable=True)
    date_posted = db.Column(db.Date, default=lambda: datetime.now(timezone.utc).date(), nullable=False)
    link = db.Column(db.String(255), nullable=True)
    features = db.Column(db.Text, nullable=True)
    is_listed = db.Column(db.Boolean, default=True, nullable=False)

class Exhibit(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=False)
    narrative = db.Column(db.Text, nullable=True)
    image = db.Column(db.String(255), nullable=False)
    is_listed = db.Column(db.Boolean, default=True, nullable=False)
    date_created = db.Column(db.Date, default=lambda: datetime.now(timezone.utc).date(), nullable=False)

class Feedback(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    visitor_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    ticket_id = db.Column(db.Integer, db.ForeignKey('ticket.id'), unique=True, nullable=False)
    date_posted = db.Column(db.Date, default=lambda: datetime.now(timezone.utc).date(), nullable=False)
    rating = db.Column(db.Integer, nullable=False)
    text = db.Column(db.Text, nullable=False)
    visitor = db.relationship('User', back_populates='feedbacks')
    ticket = db.relationship('Ticket', back_populates='feedback')

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    text = db.Column(db.Text, nullable=False)

@app.route("/")
def home():
    today_date = get_local_today_date()

    upcoming_events = Event.query.filter(
        and_(
            Event.date >= today_date,
            Event.is_listed == True
        )
    ).order_by(Event.date).limit(3).all()

    return render_template('home.html', events=upcoming_events)

@app.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            if current_user.role != 'admin':
                return redirect('/profile/overview')
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
    available_exhibits = Exhibit.query.filter(Exhibit.is_listed == True).all()
    print(available_exhibits)
    return render_template('exhibits.html', exhibits=available_exhibits)

@app.route("/events")
def events():
    today_date = get_local_today_date()

    upcoming_events = Event.query.filter(
        and_(
            Event.date >= today_date,
            Event.is_listed == True
        )
    ).order_by(Event.date).all()
    
    return render_template('events.html', events=upcoming_events)

@app.route("/news")
def news():
    available_news = News.query.filter(News.is_listed == True).all()
    return render_template('news.html', news=available_news)

@app.route("/services")
def services():
    return render_template('services.html')

@app.route("/feedback")
def feedback():
    return render_template('feedback.html')

@app.route("/contact", methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        text = request.form.get('text')
        new_message = Message(name=name, email=email, text=text)
        try:
            db.session.add(new_message)
            db.session.commit()
            return redirect('/')
        except Exception as e:
            print(f"Error: {e}")
            return redirect('/contact')
    return render_template('contact.html')

@app.route("/profile/overview")
@login_required
def profile():
    return render_template('profile_overview.html')

@app.route("/profile/book/visit", methods=['GET', 'POST'])
@login_required
def reservation():
    today_date = get_local_today_date()
    available_events = Event.query.filter(Event.is_listed == True, Event.date >= today_date).all()
    if request.method == 'POST':
        visitor_id = current_user.id
        event_id = request.form.get('event-id')
        print(event_id)
        check_date = request.form.get('date')
        date = None
        if check_date:
            date = datetime.strptime(check_date, '%Y-%m-%d').date()
            is_date_in_events = any(event.date == date for event in available_events)
            if is_date_in_events:
                for event in available_events:
                    if event.date == date:
                        event_id = event.id
                        break
        if not date:
            selected_event = Event.query.get(event_id)
            if selected_event:
                date = selected_event.date
            else:
                flash("Event not found.", "danger")
                return redirect('/profile/book/visit')
        type = request.form.get('type')
        amount = request.form.get('amount')
        new_ticket = Ticket(visitor_id=visitor_id, date=date, type=type, amount=amount, event_id=event_id)
        print(new_ticket)
        try:
            db.session.add(new_ticket)
            db.session.commit()
            return redirect('/profile/overview')
        except Exception as e:
            print(f"Error: {e}")
            return redirect('/profile/book/visit')
    return render_template('book_visit.html', events=available_events)

@app.route("/profile/add/feedback", methods=['GET', 'POST'])
@login_required
def add_feedback():
    today_date = get_local_today_date()
    all_past_visits = Ticket.query.filter(
        Ticket.date <= today_date,
        Ticket.visitor_id == current_user.id,
        ~Ticket.id.in_(db.session.query(Feedback.ticket_id).filter_by(visitor_id=current_user.id))
    ).all()
    if request.method == 'POST':
        visitor_id = current_user.id
        ticket_id = request.form.get('visit-id')
        existing_feedback = Feedback.query.filter_by(visitor_id=visitor_id, ticket_id=ticket_id).first()

        if existing_feedback:
            flash("You have already submitted feedback for this visit.")
            return redirect('/feedback')
        
        rating = request.form.get('rating')
        text = request.form.get('text')
        
        new_feedback = Feedback(visitor_id=visitor_id, ticket_id=ticket_id, rating=rating, text=text)

        try: 
            db.session.add(new_feedback)
            db.session.commit()
            return redirect('/profile/overview')
        except Exception as e:
            print(f"Error: {e}")
            return redirect('/profile/add/feedback')
    return render_template('add_feedback.html', visits=all_past_visits)

@app.route("/profile/tickets")
@login_required
def view_tickets():
    today_date = get_local_today_date()
    active_tickets = Ticket.query.filter(Ticket.date >= today_date, Ticket.visitor_id == current_user.id)
    return render_template('view_tickets.html', tickets=active_tickets)

@app.route("/profile/history")
@login_required
def visit_history():
    today_date = get_local_today_date()
    past_visits = Ticket.query.filter(Ticket.date <= today_date, Ticket.visitor_id == current_user.id)
    return render_template('visit_history.html', visits=past_visits)

@app.route("/profile/settings")
@login_required
def settings():
    return render_template('settings.html')

@app.route("/profile/edit", methods=['GET', 'POST'])
@login_required
def edit_profile():
    user = User.query.get(current_user.id)
    if request.method == 'POST':
        first_name = request.form.get('first-name')
        last_name = request.form.get('last-name')
        email = request.form.get('email')
        phone = request.form.get('phone')
        password = request.form.get('password')
        new_password = request.form.get('new-password')
        confirm_password = request.form.get('confirm-password')

        if not check_password_hash(user.password, password):
            flash("The current password is incorrect.")
            return redirect("/profile/edit")

        if new_password and new_password != confirm_password:
            flash("The new passwords do not match.")
            return redirect("/profile/edit")

        user.first_name = first_name
        user.last_name = last_name
        user.email = email
        user.phone = phone

        if new_password:
            user.password = generate_password_hash(new_password, method='pbkdf2:sha256', salt_length=16)

        try:
            db.session.commit()
            flash("Profile updated successfully.")
            return redirect("/profile/overview")
        except Exception as e:
            db.session.rollback()
            print(f"Error: {e}")
            flash("An error occurred while updating your profile.")
            return redirect("/profile/edit")
    return render_template('edit_profile.html', user=user)

@app.route("/dashboard")
@login_required
def dashboard():
    if current_user.role != 'admin':
        return "Unauthorized", 403
    return render_template('dashboard.html')

@app.route("/dashboard/add/news", methods=['GET', 'POST'])
@login_required
def add_news():
    if current_user.role != 'admin':
        return "Unauthorized", 403
    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        image = request.form.get('image')
        category = request.form.get('category')
        link = request.form.get('link')
        features = request.form.get('features')
        new_news = News(title=title, description=description, image=image, category=category, link=link, features=features)
        try:
            db.session.add(new_news)
            db.session.commit()
            return redirect('/dashboard')
        except Exception as e:
            print(f"Error: {e}")
            return redirect('/dashboard/add/news')
    return render_template('add_news.html')

@app.route("/dashboard/add/event", methods=['GET', 'POST'])
@login_required
def add_event():
    if current_user.role != 'admin':
        return "Unauthorized", 403
    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        date = datetime.strptime(request.form.get('date'), '%Y-%m-%d').date()
        image = request.form.get('image')
        price = request.form.get('price')
        new_event = Event(title=title, description=description, date=date, image=image, price=price)
        try:
            db.session.add(new_event)
            db.session.commit()
            return redirect('/dashboard')
        except Exception as e:
            print(f"Error: {e}")
            return redirect('/dashboard/add/event')
    return render_template('add_event.html')

@app.route("/dashboard/add/exhibit", methods=['GET', 'POST'])
@login_required
def add_exhibit():
    if current_user.role != 'admin':
        return "Unauthorized", 403
    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        image = request.form.get('image')
        narrative = request.form.get('narrative')
        new_exhibit = Exhibit(title=title, description=description, image=image, narrative=narrative)
        try:
            db.session.add(new_exhibit)
            db.session.commit()
            return redirect('/dashboard')
        except Exception as e:
            print(f"Error: {e}")
            return redirect('/dashboard/add/exhibit')
    return render_template('add_exhibit.html')

@app.route("/dashboard/view/messages")
@login_required
def view_messages():
    if current_user.role != 'admin':
        return "Unauthorized", 403
    all_messages = Message.query.all()
    return render_template('view_messages.html', messages=all_messages)

@app.route("/dashboard/view/feedback")
@login_required
def view_feedback():
    if current_user.role != 'admin':
        return "Unauthorized", 403
    all_feedbacks = Feedback.query.all()
    return render_template('view_feedback.html', feedbacks=all_feedbacks)

@app.route("/dashboard/delete/feedback/<int:feedback_id>", methods=['POST'])
@login_required
def delete_feedback(feedback_id):
    if current_user.role != 'admin':
        return "Unauthorized", 403
    feedback = Feedback.query.get(feedback_id)
    if not feedback:
        return "Feedback not found", 404
    try:
        db.session.delete(feedback)
        db.session.commit()
        return redirect('/dashboard/view/feedback')
    except Exception as e:
        print(f"Error: {e}")
        return "An error occurred while deleting the feedback", 500

@app.route("/logout")
def logout():
    logout_user()
    return redirect('/')

@login_manager.unauthorized_handler
def unauthorized_callback():
    return redirect('/login')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)