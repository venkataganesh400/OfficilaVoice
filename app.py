# app.py

import os
from datetime import datetime
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash, session, g, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

# --- 1. APP & DATABASE CONFIGURATION ---
# --- 1. APP & DATABASE CONFIGURATION ---
app = Flask(__name__)
# IMPORTANT: Use an environment variable for the secret key in production
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'a_very_secret_and_hard_to_guess_key_for_dev')

# Use environment variable for the database URL, with a fallback to local sqlite
# This is the key change for deployment!
DATABASE_URL = os.environ.get('DATABASE_URL', 'sqlite:///' + os.path.join(basedir, 'app.db'))
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


# --- 2. DATABASE MODELS ---
# (User, Poll, PollOption, Vote, PollLike, DeletionRequest)
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(100), nullable=False)
    last_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    voter_id = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(256))
    is_admin = db.Column(db.Boolean, default=False)
    polls = db.relationship('Poll', backref='author', lazy=True, cascade="all, delete-orphan")
    deletion_request = db.relationship('DeletionRequest', backref='user', uselist=False, cascade="all, delete-orphan")

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Poll(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    topic = db.Column(db.String(300), nullable=False)
    description = db.Column(db.Text, nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    date_created = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default='pending')
    is_featured = db.Column(db.Boolean, default=False)
    options = db.relationship('PollOption', backref='poll', lazy='dynamic', cascade="all, delete-orphan")
    likes = db.relationship('PollLike', backref='poll', lazy='dynamic', cascade="all, delete-orphan")
    votes = db.relationship('Vote', backref='poll', lazy='dynamic', cascade="all, delete-orphan")

class PollOption(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(200), nullable=False)
    poll_id = db.Column(db.Integer, db.ForeignKey('poll.id'), nullable=False)
    votes = db.relationship('Vote', backref='option', lazy='dynamic', cascade="all, delete-orphan")

class Vote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    poll_id = db.Column(db.Integer, db.ForeignKey('poll.id'), nullable=False)
    option_id = db.Column(db.Integer, db.ForeignKey('poll_option.id'), nullable=False)

class PollLike(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    poll_id = db.Column(db.Integer, db.ForeignKey('poll.id'), nullable=False)

class DeletionRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), unique=True, nullable=False)
    reason = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default='pending')
    requested_on = db.Column(db.DateTime, default=datetime.utcnow)


# --- 3. HELPER FUNCTIONS & DECORATORS ---
@app.before_request
def load_logged_in_user():
    user_id = session.get('user_id')
    g.user = User.query.get(user_id) if user_id else None

@app.context_processor
def inject_globals():
    return {'user': g.user, 'year': datetime.utcnow().year}

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if g.user is None:
            flash("You need to be logged in to access this page.", "warning")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if g.user is None or not g.user.is_admin:
            flash("You do not have permission to access this area.", "danger")
            return redirect(url_for('home'))
        return f(*args, **kwargs)
    return decorated_function

# --- 4. MAIN & AUTHENTICATION ROUTES ---
@app.route('/')
def home():
    featured_polls = Poll.query.filter_by(status='approved', is_featured=True).order_by(Poll.date_created.desc()).limit(3).all()
    return render_template("Home.html", featured_polls=featured_polls)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if g.user: return redirect(url_for('dashboard'))
    if request.method == 'POST':
        user_by_email = User.query.filter_by(email=request.form.get('email')).first()
        if user_by_email:
            flash('An account with this email already exists.', 'warning')
            return redirect(url_for('signup'))
        new_user = User(
            first_name=request.form.get('first_name'),
            last_name=request.form.get('last_name'),
            email=request.form.get('email'),
            voter_id=request.form.get('voter_id')
        )
        new_user.set_password(request.form.get('password'))
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful! You can now log in.', 'success')
        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if g.user: return redirect(url_for('dashboard'))
    if request.method == 'POST':
        user = User.query.filter_by(email=request.form.get('identifier')).first()
        if user and user.check_password(request.form.get('password')):
            session['user_id'] = user.id
            flash('Logged in successfully!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials. Please try again.', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    session.clear()
    return redirect(url_for('home'))

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')


# --- 5. POLL MANAGEMENT ROUTES ---
@app.route('/polls/all')
@login_required
def all_polls():
    polls = Poll.query.filter_by(status='approved').order_by(Poll.date_created.desc()).all()
    user_votes = {v.poll_id: v.option_id for v in Vote.query.filter_by(user_id=g.user.id).all()}
    user_likes = [l.poll_id for l in PollLike.query.filter_by(user_id=g.user.id).all()]
    return render_template('all_polls.html', polls=polls, user_votes=user_votes, user_likes=user_likes)

@app.route('/polls/create', methods=['GET', 'POST'])
@login_required
def create_poll():
    if request.method == 'POST':
        topic = request.form.get('topic')
        description = request.form.get('description')
        options = request.form.getlist('options') # Gets all options as a list

        new_poll = Poll(topic=topic, description=description, author=g.user)
        db.session.add(new_poll)

        for option_text in options:
            if option_text.strip():
                new_option = PollOption(text=option_text.strip(), poll=new_poll)
                db.session.add(new_option)

        db.session.commit()
        flash('Your poll has been submitted and is awaiting admin approval.', 'success')
        return redirect(url_for('all_polls'))
    return render_template('create_poll.html')

@app.route('/polls/vote/<int:poll_id>/<int:option_id>', methods=['POST'])
@login_required
def vote_poll(poll_id, option_id):
    # AJAX route for voting
    existing_vote = Vote.query.filter_by(user_id=g.user.id, poll_id=poll_id).first()
    if existing_vote:
        return jsonify({'success': False, 'message': 'You have already voted on this poll.'})
    
    new_vote = Vote(user_id=g.user.id, poll_id=poll_id, option_id=option_id)
    db.session.add(new_vote)
    db.session.commit()
    return jsonify({'success': True, 'message': 'Vote recorded!'})

@app.route('/polls/like/<int:poll_id>', methods=['POST'])
@login_required
def like_poll(poll_id):
    # AJAX route for liking
    existing_like = PollLike.query.filter_by(user_id=g.user.id, poll_id=poll_id).first()
    if existing_like:
        db.session.delete(existing_like)
        db.session.commit()
        return jsonify({'success': True, 'liked': False, 'count': PollLike.query.filter_by(poll_id=poll_id).count()})
    else:
        new_like = PollLike(user_id=g.user.id, poll_id=poll_id)
        db.session.add(new_like)
        db.session.commit()
        return jsonify({'success': True, 'liked': True, 'count': PollLike.query.filter_by(poll_id=poll_id).count()})

# --- 6. USER PROFILE & ACCOUNT MANAGEMENT ROUTES ---
@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html')

@app.route('/delete_account', methods=['GET', 'POST'])
@login_required
def delete_account():
    existing_request = DeletionRequest.query.filter_by(user_id=g.user.id).first()
    if existing_request:
        flash("You already have a pending deletion request.", "info")
        return redirect(url_for('profile'))
        
    if request.method == 'POST':
        reason = request.form.get('reason')
        new_request = DeletionRequest(user_id=g.user.id, reason=reason)
        db.session.add(new_request)
        db.session.commit()
        flash('Your account deletion request has been submitted for admin review.', 'success')
        return redirect(url_for('profile'))
    return render_template('delete_account.html')

# --- 7. ADMIN ROUTES ---
@app.route('/admin')
@admin_required
def admin_dashboard():
    stats = {
        'total_users': User.query.count(),
        'pending_polls': Poll.query.filter_by(status='pending').count(),
        'deletion_requests': DeletionRequest.query.filter_by(status='pending').count(),
    }
    return render_template('admin/admin_dashboard.html', stats=stats)

@app.route('/admin/polls')
@admin_required
def manage_polls():
    pending_polls = Poll.query.filter_by(status='pending').order_by(Poll.date_created.desc()).all()
    return render_template('admin/manage_polls.html', polls=pending_polls)

@app.route('/admin/poll/<int:poll_id>/<action>')
@admin_required
def action_poll(poll_id, action):
    poll = Poll.query.get_or_404(poll_id)
    if action == 'approve':
        poll.status = 'approved'
        flash(f"Poll '{poll.topic[:30]}...' has been approved.", 'success')
    elif action == 'reject':
        poll.status = 'rejected'
        flash(f"Poll '{poll.topic[:30]}...' has been rejected.", 'warning')
    elif action == 'feature':
        poll.is_featured = not poll.is_featured
        flash(f"Poll feature status updated.", 'info')
    db.session.commit()
    return redirect(request.referrer or url_for('manage_polls'))

@app.route('/admin/deletions')
@admin_required
def manage_deletions():
    requests = DeletionRequest.query.filter_by(status='pending').order_by(DeletionRequest.requested_on.desc()).all()
    return render_template('admin/manage_deletions.html', requests=requests)

@app.route('/admin/deletion/<int:req_id>/approve')
@admin_required
def approve_deletion(req_id):
    req = DeletionRequest.query.get_or_404(req_id)
    user_to_delete = req.user
    db.session.delete(user_to_delete) # This will cascade and delete related data
    db.session.commit()
    flash(f"User {user_to_delete.email} has been permanently deleted.", 'success')
    return redirect(url_for('manage_deletions'))


if __name__ == '__main__':
    with app.app_context():
        # db.drop_all() # Uncomment to reset the database completely
        db.create_all()

        # Check if admin user exists, if not, create one
        if not User.query.filter_by(is_admin=True).first():
            print("Creating default admin user...")
            admin_user = User(
                first_name="Admin", last_name="User",
                email="admin@officialvoice.com", voter_id="ADMIN001",
                is_admin=True
            )
            admin_user.set_password("AdminPass123") # Change this password!
            db.session.add(admin_user)
            db.session.commit()
            print("Admin user created: admin@officialvoice.com / AdminPass123")

    app.run(debug=True)