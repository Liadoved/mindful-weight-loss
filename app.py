from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timezone, timedelta
from functools import wraps
import os
from dotenv import load_dotenv
import json
import logging
from logging.handlers import RotatingFileHandler
from flask_oauthlib.client import OAuth
from email.mime.text import MIMEText
import ssl
from urllib.parse import urlparse
import csv
from io import StringIO
from flask_migrate import Migrate
from flask_mail import Mail

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'default-secret-key')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///users.db').replace('postgres://', 'postgresql://')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)

db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
mail = Mail(app)

# Email configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')

# Video configuration
VIDEOS = [
    {"title": "פרק 1: מבוא לירידה במשקל מודעת", "duration": "15:00"},
    {"title": "פרק 2: הבנת דפוסי אכילה", "duration": "20:00"},
    {"title": "פרק 3: מיינדפולנס באכילה", "duration": "25:00"},
    {"title": "פרק 4: התמודדות עם רגשות", "duration": "18:00"},
    {"title": "פרק 5: בניית הרגלים בריאים", "duration": "22:00"},
    {"title": "פרק 6: סיכום והמשך הדרך", "duration": "20:00"}
]

# Total number of items (chapters + quiz)
TOTAL_ITEMS = 7  # 7 chapters including quiz

# הגדרת לוגים
if not os.path.exists('logs'):
    os.mkdir('logs')
file_handler = RotatingFileHandler('logs/registration.log', maxBytes=10240, backupCount=10)
file_handler.setFormatter(logging.Formatter(
    '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
))
file_handler.setLevel(logging.INFO)
app.logger.addHandler(file_handler)
app.logger.setLevel(logging.INFO)

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    full_name = db.Column(db.String(120))
    phone = db.Column(db.String(20))
    gender = db.Column(db.String(10))
    registration_date = db.Column(db.DateTime(timezone=True))
    last_login = db.Column(db.DateTime(timezone=True))
    difficulty = db.Column(db.Integer, default=0)
    quiz_answers = db.Column(db.JSON, default=lambda: {})
    completed_videos = db.Column(db.Text, default='')
    progress = db.Column(db.Integer, default=0)
    is_admin = db.Column(db.Boolean, default=False)
    quiz_completed = db.Column(db.Boolean, default=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        if not self.password_hash:
            return False
        return check_password_hash(self.password_hash, password)

    def get_eating_type(self):
        types = {
            1: 'אכלנית מאוזנת',
            2: 'אכלנית רגשית',
            3: 'אכלנית כפייתית'
        }
        return types.get(self.difficulty, 'טרם סווג')

    def save_quiz_answers(self, answers):
        """שמירת תשובות השאלון"""
        self.quiz_answers = answers
        db.session.commit()

    def get_quiz_answers(self):
        """קבלת תשובות השאלון"""
        return self.quiz_answers if self.quiz_answers else {}

    def get_completed_videos_count(self):
        if not self.completed_videos:
            return 0
        videos = [v for v in self.completed_videos.split(',') if v]
        return len(videos)

    def mark_video_completed(self, video_id):
        completed = set(v for v in self.completed_videos.split(',') if v)
        completed.add(str(video_id))
        self.completed_videos = ','.join(sorted(completed))
        # עדכון התקדמות
        total_videos = 10  # מספר הסרטונים הכולל בקורס
        self.progress = min(100, int((len(completed) / total_videos) * 100))
        db.session.commit()

    def get_progress(self):
        return self.progress

    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'full_name': self.full_name,
            'phone': self.phone,
            'gender': self.gender,
            'registration_date': self.registration_date.isoformat() if self.registration_date else None,
            'last_login': self.last_login.isoformat() if self.last_login else None,
            'difficulty': self.difficulty,
            'quiz_answers': self.quiz_answers,
            'completed_videos': self.completed_videos,
            'progress': self.progress,
            'is_admin': self.is_admin
        }

class Settings(db.Model):
    __tablename__ = 'settings'
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(50), unique=True, nullable=False)
    value = db.Column(db.String(500), nullable=False)
    updated_at = db.Column(db.DateTime(timezone=True))

    @staticmethod
    def get_course_price():
        setting = Settings.query.filter_by(key='course_price').first()
        return setting.value if setting else '997'

    @staticmethod
    def set_course_price(price):
        setting = Settings.query.filter_by(key='course_price').first()
        if not setting:
            setting = Settings(key='course_price', value=str(price))
            db.session.add(setting)
        else:
            setting.value = str(price)
            setting.updated_at = datetime.now(timezone.utc)
        db.session.commit()

class Prices(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    original_price = db.Column(db.Integer, nullable=False)
    discount_price = db.Column(db.Integer, nullable=False)
    updated_at = db.Column(db.DateTime(timezone=True))

class Price(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    original_price = db.Column(db.Float, nullable=False, default=997.0)
    discounted_price = db.Column(db.Float, nullable=False, default=497.0)
    
    @staticmethod
    def get_prices():
        price = Price.query.first()
        if not price:
            price = Price()
            db.session.add(price)
            db.session.commit()
        return price

def requires_admin(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            flash('עליך להתחבר תחילה', 'error')
            return redirect(url_for('login'))
        if not current_user.is_admin:
            flash('אין לך הרשאות מתאימות', 'error')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def generate_password(length=10):
    """Generate a random password."""
    characters = string.ascii_letters + string.digits + "!@#$%^&*"
    return ''.join(random.choice(characters) for i in range(length))

def get_eating_type_text(difficulty):
    types = {
        1: "קל לי לרדת במשקל כשאני מחליטה",
        2: "קשה לי לרדת במשקל בגלל אכילה רגשית",
        3: "אני מרגישה תלות באוכל וקושי גדול לשלוט בכמויות",
        0: "לא צוין"
    }
    return types.get(difficulty, "לא צוין")

def send_registration_email(email, username, password, user_data, is_admin=False):
    try:
        sender_email = "razit.mindful@gmail.com"
        receiver_email = "razit.mindful@gmail.com" if is_admin else email
        
        message = MIMEMultipart('alternative')
        message["From"] = sender_email
        message["To"] = receiver_email
        
        if is_admin:
            message["Subject"] = f"משתמשת חדשה נרשמה לקורס: {user_data['full_name']}"
            html_content = f"""
            <div dir="rtl" style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; background-color: #f9f9f9;">
                <h2 style="color: #8a5dc7; text-align: center; margin-bottom: 20px; font-size: 24px;">משתמשת חדשה נרשמה לקורס!</h2>
                
                <div style="background-color: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 20px;">
                    <h3 style="color: #8a5dc7; margin-bottom: 20px; font-size: 20px;">פרטים אישיים</h3>
                    <div style="margin-bottom: 15px;">
                        <p style="margin-bottom: 10px; font-size: 16px;"><strong style="color: #666;">שם מלא:</strong> {user_data['full_name']}</p>
                        <p style="margin-bottom: 10px; font-size: 16px;"><strong style="color: #666;">אימייל:</strong> {user_data['email']}</p>
                        <p style="margin-bottom: 10px; font-size: 16px;"><strong style="color: #666;">טלפון:</strong> {user_data['phone']}</p>
                        <p style="margin-bottom: 10px; font-size: 16px;"><strong style="color: #666;">גיל:</strong> {user_data['age']}</p>
                        <p style="margin-bottom: 10px; font-size: 16px;"><strong style="color: #666;">מגדר:</strong> {user_data['gender']}</p>
                        <p style="margin-bottom: 10px; font-size: 16px;"><strong style="color: #666;">עיר:</strong> {user_data['city'] or 'לא צוין'}</p>
                        <p style="margin-bottom: 10px; font-size: 16px;"><strong style="color: #666;">כתובת:</strong> {user_data['address'] or 'לא צוין'}</p>
                    </div>
                </div>

                <div style="background-color: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 20px;">
                    <h3 style="color: #8a5dc7; margin-bottom: 20px; font-size: 20px;">מידע על הקורס</h3>
                    <div style="margin-bottom: 15px;">
                        <p style="margin-bottom: 10px; font-size: 16px;"><strong style="color: #666;">רמת קושי בירידה במשקל:</strong></p>
                        <div style="background-color: #f5f5f5; padding: 15px; border-radius: 6px; margin-bottom: 15px;">
                            {get_eating_type_text(user_data['difficulty'])}
                        </div>
                        
                        <p style="margin-bottom: 10px; font-size: 16px;"><strong style="color: #666;">שיתוף נוסף מהמשתמשת:</strong></p>
                        <div style="background-color: #f5f5f5; padding: 15px; border-radius: 6px;">
                            {user_data['comments'] or 'לא צוין'}
                        </div>
                    </div>
                </div>

                <div style="background-color: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
                    <h3 style="color: #8a5dc7; margin-bottom: 20px; font-size: 20px;">מידע טכני</h3>
                    <div style="margin-bottom: 15px;">
                        <p style="margin-bottom: 10px; font-size: 16px;"><strong style="color: #666;">תאריך הרשמה:</strong> {user_data['registration_date'].strftime('%d/%m/%Y %H:%M')}</p>
                        <p style="margin-bottom: 10px; font-size: 16px;"><strong style="color: #666;">שם משתמש:</strong> {username}</p>
                        <p style="margin-bottom: 10px; font-size: 16px;"><strong style="color: #666;">סיסמה:</strong> {password}</p>
                    </div>
                </div>
            </div>
            """
        else:
            message["Subject"] = "ברוכים הבאים לקורס המבוא של רזית"
            html_content = f"""
            <div dir="rtl" style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; background-color: #f9f9f9;">
                <div style="text-align: center; margin-bottom: 30px;">
                    <h1 style="color: #8a5dc7; margin-bottom: 10px;">ברוכים הבאים לקורס המבוא של רזית!</h1>
                    <p style="color: #666; font-size: 18px;">אנחנו שמחים שהצטרפת אלינו למסע</p>
                </div>
                
                <div style="background-color: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
                    <p style="font-size: 16px; line-height: 1.6; margin-bottom: 20px;">
                        שלום {user_data['full_name']},
                    </p>
                    
                    <p style="font-size: 16px; line-height: 1.6; margin-bottom: 20px;">
                        תודה שנרשמת לקורס המבוא שלנו! אנחנו מאמינים שתמצאי ערך רב בתכנים שהכנו עבורך.
                    </p>
                    
                    <div style="background-color: #f5f5f5; padding: 20px; border-radius: 6px; margin: 20px 0;">
                        <h3 style="color: #8a5dc7; margin-bottom: 15px;">פרטי ההתחברות שלך:</h3>
                        <p style="margin-bottom: 10px;"><strong>שם משתמש:</strong> {username}</p>
                        <p style="margin-bottom: 10px;"><strong>סיסמה:</strong> {password}</p>
                    </div>
                    
                    <p style="font-size: 16px; line-height: 1.6; margin: 20px 0;">
                        מומלץ לשמור את פרטי ההתחברות במקום בטוח.
                    </p>
                    
                    <div style="text-align: center; margin-top: 30px;">
                        <a href="https://mindful-weight-loss.onrender.com/login" 
                           style="background-color: #8a5dc7; color: white; padding: 12px 30px; text-decoration: none; border-radius: 25px; font-weight: bold;">
                            התחברות לקורס
                        </a>
                    </div>
                </div>
                
                <div style="text-align: center; margin-top: 30px; color: #666;">
                    <p>אם יש לך שאלות, אנחנו כאן בשבילך!</p>
                    <p>צוות רזית</p>
                </div>
            </div>
            """
        
        message.attach(MIMEText(html_content, 'html'))
        
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context) as server:
            server.login(sender_email, os.getenv('EMAIL_PASSWORD'))
            server.send_message(message)
            
        return True
    except Exception as e:
        app.logger.error(f"Error sending email: {str(e)}")
        return False

oauth = OAuth(app)
google = None

if os.environ.get('GOOGLE_CLIENT_ID') and os.environ.get('GOOGLE_CLIENT_SECRET'):
    google = oauth.remote_app(
        'google',
        consumer_key=os.environ.get('GOOGLE_CLIENT_ID'),
        consumer_secret=os.environ.get('GOOGLE_CLIENT_SECRET'),
        request_token_params={
            'scope': 'email'
        },
        base_url='https://www.googleapis.com/oauth2/v1/',
        request_token_url=None,
        access_token_method='POST',
        access_token_url='https://accounts.google.com/o/oauth2/token',
        authorize_url='https://accounts.google.com/o/oauth2/auth',
    )

    @google.tokengetter
    def get_google_oauth_token():
        return session.get('google_token')

@app.route('/login/google')
def google_login():
    if not google:
        flash('Google login is not configured.', 'error')
        return redirect(url_for('login'))
    return google.authorize(callback=url_for('google_authorized', _external=True))

@app.route('/login/google/authorized')
def google_authorized():
    if not google:
        flash('Google login is not configured.', 'error')
        return redirect(url_for('login'))
    try:
        resp = google.authorized_response()
        if resp is None or resp.get('access_token') is None:
            error_reason = request.args.get('error_reason', 'unknown')
            error_desc = request.args.get('error_description', 'No error description')
            app.logger.error('Access denied: reason=%s error=%s', error_reason, error_desc)
            flash('לא הצלחנו להתחבר עם גוגל. נא לנסות שוב.', 'error')
            return redirect(url_for('login'))

        app.logger.info('Google response received: %s', resp)
        session['google_token'] = (resp['access_token'], '')
        app.logger.info('Access token saved to session')
        
        try:
            me = google.get('userinfo')
            if me.data is None:
                app.logger.error('Failed to get user info from Google')
                flash('לא הצלחנו לקבל את פרטי המשתמש מגוגל. נא לנסות שוב.', 'error')
                return redirect(url_for('login'))
            
            app.logger.info('User info received: %s', me.data)
            
            try:
                user = User.query.filter_by(email=me.data['email']).first()
                if user is None:
                    # יצירת משתמש חדש
                    username = me.data['email'].split('@')[0]
                    user = User(
                        username=username,
                        email=me.data['email'],
                        registration_date=datetime.now(timezone.utc)
                    )
                    db.session.add(user)
                    db.session.commit()
                    app.logger.info('Created new user: %s', user.email)

                # עדכון זמן התחברות אחרון
                user.last_login = datetime.now(timezone.utc)
                db.session.commit()
                
                login_user(user)
                app.logger.info(f'התחברות מוצלחת: {me.data["email"]}')

                # הפניה לדף המבוקש או לדף הבית
                next_page = request.args.get('next')
                if not next_page or urlparse(next_page).netloc != '':
                    next_page = url_for('admin') if user.is_admin else url_for('index')
                return redirect(next_page)

            except Exception as e:
                app.logger.error('Database error: %s', str(e))
                db.session.rollback()
                flash('אירעה שגיאה בשמירת פרטי המשתמש. נא לנסות שוב.', 'error')
                return redirect(url_for('login'))

        except Exception as e:
            app.logger.error('Error getting user info: %s', str(e))
            flash('אירעה שגיאה בקבלת פרטי המשתמש. נא לנסות שוב.', 'error')
            return redirect(url_for('login'))

    except Exception as e:
        app.logger.error('Error in google_authorized: %s', str(e))
        flash('אירעה שגיאה בתהליך ההתחברות. נא לנסות שוב.', 'error')
        return redirect(url_for('login'))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        try:
            email = request.form.get('email', '').strip()
            username = request.form.get('username', '').strip()
            password = request.form.get('password', '').strip()
            full_name = request.form.get('full_name', '').strip()
            phone = request.form.get('phone', '').strip()
            gender = request.form.get('gender', '').strip()

            # וולידציה בסיסית
            if not all([email, username, password, full_name]):
                flash('כל השדות המסומנים בכוכבית הם חובה', 'error')
                return redirect(url_for('register'))

            # בדיקת אורך סיסמה
            if len(password) < 6:
                flash('הסיסמה חייבת להכיל לפחות 6 תווים', 'error')
                return redirect(url_for('register'))

            # בדיקת תקינות אימייל
            if '@' not in email or '.' not in email:
                flash('כתובת האימייל אינה תקינה', 'error')
                return redirect(url_for('register'))

            # בדיקה אם המשתמש כבר קיים
            if User.query.filter_by(email=email).first():
                flash('כתובת האימייל כבר רשומה במערכת', 'error')
                return redirect(url_for('register'))

            if User.query.filter_by(username=username).first():
                flash('שם המשתמש כבר תפוס', 'error')
                return redirect(url_for('register'))

            # יצירת משתמש חדש
            user = User(
                username=username,
                email=email,
                full_name=full_name,
                phone=phone,
                gender=gender
            )
            user.set_password(password)

            try:
                db.session.add(user)
                db.session.commit()

                # שליחת אימייל
                user_data = {
                    'full_name': full_name,
                    'email': email,
                    'phone': phone,
                    'gender': gender
                }
                
                try:
                    send_registration_email(email, username, password, user_data)
                    send_registration_email(email, username, password, user_data, is_admin=True)
                except Exception as e:
                    app.logger.error(f'שגיאה בשליחת אימייל: {str(e)}')
                    # לא נחזיר שגיאה למשתמש כי ההרשמה עצמה הצליחה

                login_user(user)
                return redirect(url_for('registration_success'))

            except Exception as e:
                db.session.rollback()
                app.logger.error(f'שגיאה בהרשמת משתמש: {str(e)}')
                flash('אירעה שגיאה בתהליך ההרשמה. נא לנסות שוב.', 'error')
                return redirect(url_for('register'))

        except Exception as e:
            app.logger.error(f'שגיאה כללית בתהליך ההרשמה: {str(e)}')
            flash('אירעה שגיאה. נא לנסות שוב מאוחר יותר.', 'error')
            return redirect(url_for('register'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
        
    if request.method == 'POST':
        try:
            email = request.form.get('email', '').strip()
            password = request.form.get('password', '').strip()
            remember = request.form.get('remember', False)

            if not email or not password:
                flash('נא למלא את כל השדות', 'error')
                return redirect(url_for('login'))

            user = User.query.filter_by(email=email).first()
            
            if not user:
                app.logger.warning(f'ניסיון התחברות כושל - משתמש לא קיים: {email}')
                flash('שם משתמש או סיסמה שגויים', 'error')
                return redirect(url_for('login'))

            if not user.check_password(password):
                app.logger.warning(f'ניסיון התחברות כושל - סיסמה שגויה: {email}')
                flash('שם משתמש או סיסמה שגויים', 'error')
                return redirect(url_for('login'))

            # עדכון זמן התחברות אחרון
            user.last_login = datetime.now(timezone.utc)
            try:
                db.session.commit()
            except Exception as e:
                app.logger.error(f'שגיאה בעדכון זמן התחברות אחרון: {str(e)}')
                # לא נחזיר שגיאה למשתמש כי ההתחברות עצמה הצליחה

            login_user(user, remember=remember)
            app.logger.info(f'התחברות מוצלחת: {email}')

            # הפניה לדף המבוקש או לדף הבית
            next_page = request.args.get('next')
            if not next_page or urlparse(next_page).netloc != '':
                next_page = url_for('admin') if user.is_admin else url_for('index')
            return redirect(next_page)

        except Exception as e:
            app.logger.error(f'שגיאה בתהליך ההתחברות: {str(e)}')
            flash('אירעה שגיאה. נא לנסות שוב מאוחר יותר.', 'error')
            return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    try:
        logout_user()
        return redirect(url_for('index'))
    except Exception as e:
        app.logger.error(f'שגיאה בתהליך ההתנתקות: {str(e)}')
        flash('אירעה שגיאה בהתנתקות', 'error')
        return redirect(url_for('index'))

@app.route('/course')
@login_required
def course():
    # בדיקה אם המשתמש השלים את כל הפרקים
    total_videos = len(VIDEOS)
    completed_count = current_user.get_completed_videos_count()
    current_user.progress = int((completed_count / total_videos) * 100)
    
    # אם המשתמש סיים את כל הפרקים, נסמן זאת
    if current_user.progress == 100:
        current_user.course_completed = True
        db.session.commit()
    
    return render_template('course.html', 
                         videos=VIDEOS,
                         completed_videos=current_user.completed_videos.split(',') if current_user.completed_videos else [],
                         progress=current_user.progress,
                         course_completed=getattr(current_user, 'course_completed', False))

@app.route('/mark_complete/<video_id>', methods=['POST'])
@login_required
def mark_complete(video_id):
    try:
        if not current_user.completed_videos:
            completed_videos = []
        else:
            completed_videos = current_user.completed_videos.split(',')
        
        app.logger.info(f"Current completed videos: {completed_videos}")
        app.logger.info(f"Trying to mark as complete: {video_id}")
        
        # Handle regular chapters
        video_id = str(video_id)
        prev_chapter = str(int(video_id) - 1) if video_id.isdigit() else None
        
        # בדיקה אם ניתן לפתוח את הפרק
        can_unlock = (
            video_id == '1' or  # פרק ראשון תמיד פתוח
            video_id in completed_videos or  # פרק שכבר הושלם
            prev_chapter in completed_videos  # הפרק הקודם הושלם
        )
        
        app.logger.info(f"Can unlock chapter {video_id}? {can_unlock}")
        app.logger.info(f"Previous chapter: {prev_chapter}")
        
        if can_unlock and video_id not in completed_videos:
            completed_videos.append(video_id)
            current_user.completed_videos = ','.join(completed_videos)
            
            # Calculate progress
            progress = int((len(completed_videos) / TOTAL_ITEMS) * 100)
            current_user.progress = progress
            
            app.logger.info(f"Chapter {video_id} marked as complete. New progress: {progress}%")
            app.logger.info(f"New completed videos: {completed_videos}")
            
            db.session.commit()
            
            return jsonify({
                'success': True,
                'progress': progress
            })
        
        return jsonify({'success': False, 'message': 'לא ניתן לסמן כהושלם'})
        
    except Exception as e:
        app.logger.error(f"Error marking video as complete: {str(e)}")
        return jsonify({'success': False, 'message': str(e)})

@app.route('/update_progress', methods=['POST'])
@login_required
def update_progress():
    data = request.get_json()
    current_user.completed_videos = ','.join(map(str, data['completed_videos']))
    current_user.progress = len(data['completed_videos']) / TOTAL_ITEMS * 100
    db.session.commit()
    return jsonify({'status': 'success'})

@app.route('/get_progress')
@login_required
def get_progress():
    try:
        completed_videos = []
        if current_user.completed_videos and current_user.completed_videos.strip():
            completed_videos = current_user.completed_videos.split(',')
            
        progress = int((len(completed_videos) / TOTAL_ITEMS) * 100)
        
        return jsonify({
            'completed_videos': completed_videos,
            'progress': progress
        })
    except Exception as e:
        app.logger.error(f"Error getting progress: {str(e)}")
        return jsonify({
            'completed_videos': [],
            'progress': 0
        })

@app.route('/about-course')
def about_course():
    return render_template('about_course.html')

@app.route('/contact')
def contact():
    return render_template('contact.html')

@app.route('/reset_progress', methods=['POST'])
@login_required
def reset_progress():
    try:
        user = User.query.filter_by(email=current_user.email).first()
        user.completed_videos = []
        user.quiz_completed = False
        user.quiz_results = None
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        app.logger.error(f"Error resetting progress: {str(e)}")
        db.session.rollback()
        return jsonify({'success': False, 'message': 'An error occurred'})

@app.route('/quiz')
@login_required
def quiz():
    user = User.query.filter_by(email=current_user.email).first()
    try:
        if not user.quiz_completed:
            return render_template('quiz.html')
    except:
        return render_template('quiz.html')
    return redirect(url_for('quiz_results'))

@app.route('/submit_quiz', methods=['POST'])
@login_required
def submit_quiz():
    if not current_user.is_authenticated:
        return jsonify({'error': 'User not authenticated'}), 401

    try:
        data = request.get_json()
        answers = data.get('answers', {})
        
        # שמירת התשובות בדאטהבייס
        current_user.quiz_answers = answers
        try:
            current_user.quiz_completed = True
        except:
            pass
        db.session.commit()
        
        return jsonify({'status': 'success', 'redirect': url_for('quiz_results')})

    except Exception as e:
        app.logger.error(f'שגיאה בתהליך השאלון: {str(e)}')
        return jsonify({'error': 'שגיאה בתהליך השאלון'}), 500

@app.route('/quiz_results')
@login_required
def quiz_results():
    if not current_user.quiz_answers:
        return redirect(url_for('quiz'))
    
    # מקבל את התשובות מהדאטהבייס
    answers = current_user.quiz_answers
    
    # חישוב התוצאות
    eating_types = {
        'a': {'name': 'אכלנית רגשית', 'score': 0},
        'b': {'name': 'אכלנית בגדול', 'score': 0},
        'c': {'name': 'אכלנית המרצה', 'score': 0},
        'd': {'name': 'אכלנית מכורה', 'score': 0},
        'e': {'name': 'אכלנית עצלנית', 'score': 0},
        'f': {'name': 'אכלנית חולת שליטה', 'score': 0}
    }
    
    # חישוב הציון לכל סוג
    for q_num, answer in answers.items():
        q_type = get_question_type(int(q_num))
        if q_type in eating_types:
            eating_types[q_type]['score'] += int(answer)
    
    # מיון התוצאות לפי ציון
    sorted_types = sorted(
        [{'type': k, **v} for k, v in eating_types.items()],
        key=lambda x: x['score'],
        reverse=True
    )

    # מסמן שהמשתמש סיים את השאלון
    try:
        current_user.quiz_completed = True
        db.session.commit()
    except:
        pass
    
    return render_template('quiz_results.html', results=sorted_types)

def get_question_type(q_num):
    """מחזיר את סוג השאלה לפי מספר השאלה"""
    question_types = {
        1: 'a', 2: 'b', 3: 'c', 4: 'd', 5: 'e', 6: 'f',
        7: 'a', 8: 'b', 9: 'c', 10: 'd', 11: 'e', 12: 'f',
        13: 'a', 14: 'b', 15: 'c', 16: 'd', 17: 'e', 18: 'f',
        19: 'a', 20: 'b', 21: 'c', 22: 'd', 23: 'e', 24: 'f',
        25: 'a', 26: 'b', 27: 'c', 28: 'd', 29: 'e', 30: 'f',
        31: 'a', 32: 'b', 33: 'c', 34: 'd', 35: 'e', 36: 'f'
    }
    return question_types.get(q_num)

@app.route('/test-email')
def test_email():
    try:
        msg = Message('Test Email',
                    sender=app.config['MAIL_USERNAME'],
                    recipients=[app.config['MAIL_USERNAME']])
        msg.body = 'This is a test email from your Flask application.'
        mail.send(msg)
        return 'Test email sent successfully!'
    except Exception as e:
        app.logger.error(f'Test email failed: {str(e)}')
        return f'Failed to send test email: {str(e)}'

@app.route('/setup_database')
def setup_database():
    try:
        # יצירת הטבלאות
        db.drop_all()
        db.create_all()
        
        # יצירת משתמש אדמין
        admin_user = User(
            username='admin',
            email='admin@razit.co.il',
            password_hash=generate_password_hash('Aa123456!'),
            full_name='מנהל המערכת',
            age=30,
            gender='other',
            address='',
            city='',
            phone='',
            difficulty=0,
            comments='משתמש אדמין',
            is_admin=True
        )
        
        # הוספת המשתמש לבסיס הנתונים
        db.session.add(admin_user)
        db.session.commit()
        
        return 'Database setup completed successfully!'
    except Exception as e:
        return f'Error setting up database: {str(e)}'

@app.route('/admin')
@login_required
@requires_admin
def admin():
    prices = Prices.query.order_by(Prices.updated_at.desc()).first()
    users = User.query.filter_by(is_admin=False).all()
    
    # חישוב סטטיסטיקות
    total_users = len(users)
    female_users = len([u for u in users if u.gender == 'נקבה'])
    male_users = len([u for u in users if u.gender == 'זכר'])
    
    female_percentage = round((female_users / total_users * 100) if total_users > 0 else 0)
    male_percentage = round((male_users / total_users * 100) if total_users > 0 else 0)
    
    # סטטיסטיקות אכלניות
    users_with_type = [u for u in users if u.difficulty != 0]
    total_typed = len(users_with_type) if len(users_with_type) > 0 else 1
    
    balanced_eaters = len([u for u in users if u.difficulty == 1])
    emotional_eaters = len([u for u in users if u.difficulty == 2])
    compulsive_eaters = len([u for u in users if u.difficulty == 3])
    
    balanced_percentage = round((balanced_eaters / total_typed * 100))
    emotional_percentage = round((emotional_eaters / total_typed * 100))
    compulsive_percentage = round((compulsive_eaters / total_typed * 100))
    
    # ממוצע התקדמות
    average_progress = round(sum(u.progress for u in users) / total_users if total_users > 0 else 0)
    
    # מחיר נוכחי
    current_price = Settings.get_course_price()
    
    return render_template('admin.html',
                         prices=prices,
                         users=users,
                         total_users=total_users,
                         female_users=female_users,
                         male_users=male_users,
                         female_percentage=female_percentage,
                         male_percentage=male_percentage,
                         balanced_eaters=balanced_eaters,
                         emotional_eaters=emotional_eaters,
                         compulsive_eaters=compulsive_eaters,
                         balanced_percentage=balanced_percentage,
                         emotional_percentage=emotional_percentage,
                         compulsive_percentage=compulsive_percentage,
                         average_progress=average_progress,
                         current_price=current_price)

@app.route('/api/prices', methods=['GET'])
def get_prices():
    try:
        price = Price.get_prices()
        return jsonify({
            'original_price': price.original_price,
            'discounted_price': price.discounted_price
        }), 200
    except Exception as e:
        app.logger.error(f'שגיאה בקבלת מחירים: {str(e)}')
        return jsonify({'error': 'שגיאה בקבלת המחירים'}), 500

@app.route('/api/prices', methods=['POST'])
@requires_admin
def update_prices():
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'לא התקבלו נתונים'}), 400
            
        original_price = data.get('original_price')
        discounted_price = data.get('discounted_price')
        
        # וולידציה
        if original_price is None or discounted_price is None:
            return jsonify({'error': 'חסרים שדות חובה'}), 400
            
        try:
            original_price = float(original_price)
            discounted_price = float(discounted_price)
        except ValueError:
            return jsonify({'error': 'המחירים חייבים להיות מספרים'}), 400

        # בדיקה שהמחירים חיוביים
        if original_price <= 0 or discounted_price <= 0:
            return jsonify({'error': 'המחירים חייבים להיות חיוביים'}), 400

        # בדיקה שמחיר המבצע נמוך מהמחיר המקורי
        if discounted_price >= original_price:
            return jsonify({'error': 'מחיר המבצע חייב להיות נמוך מהמחיר המקורי'}), 400

        # עדכון המחירים
        price = Price.query.first()
        if not price:
            price = Price()
            db.session.add(price)
        
        price.original_price = original_price
        price.discounted_price = discounted_price
        db.session.commit()
        
        return jsonify({
            'message': 'המחירים עודכנו בהצלחה',
            'original_price': price.original_price,
            'discounted_price': price.discounted_price
        }), 200
        
    except Exception as e:
        app.logger.error(f'שגיאה בעדכון מחירים: {str(e)}')
        db.session.rollback()
        return jsonify({'error': 'שגיאה בעדכון המחירים'}), 500

@app.route('/api/statistics')
@requires_admin
def get_statistics():
    try:
        total_users = User.query.count()
        completed_users = User.query.filter_by(course_completed=True).count()
        completion_rate = (completed_users / total_users * 100) if total_users > 0 else 0
        
        # פילוח סוגי אכילה
        eating_types = db.session.query(
            User.difficulty,
            db.func.count(User.id)
        ).group_by(User.difficulty).all()
        
        eating_types_data = {
            eating_type: count 
            for eating_type, count in eating_types 
            if eating_type is not None
        }
        
        # אחוזי הקלקה על וואצאפ
        whatsapp_clicks = User.query.filter_by(clicked_whatsapp=True, course_completed=True).count()
        whatsapp_rate = (whatsapp_clicks / completed_users * 100) if completed_users > 0 else 0
        
        return jsonify({
            'total_users': total_users,
            'completion_rate': round(completion_rate, 1),
            'eating_types': eating_types_data,
            'whatsapp_click_rate': round(whatsapp_rate, 1)
        })
        
    except Exception as e:
        app.logger.error(f'שגיאה בקבלת נתונים סטטיסטיים: {str(e)}')
        return jsonify({'error': 'שגיאה בקבלת הנתונים'}), 500

@app.route('/api/track_whatsapp_click', methods=['POST'])
@login_required
def track_whatsapp_click():
    try:
        current_user.clicked_whatsapp = True
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        app.logger.error(f'שגיאה בתיעוד לחיצה על וואצאפ: {str(e)}')
        return jsonify({'error': 'שגיאה בתיעוד הלחיצה'}), 500

@app.route('/admin/settings', methods=['POST'])
@login_required
@requires_admin
def update_settings():
    price = request.form.get('course_price')
    if price:
        Settings.set_course_price(price)
        flash('המחיר עודכן בהצלחה', 'success')
    return redirect(url_for('admin'))

@app.route('/make_admin/<int:user_id>')
@login_required
@requires_admin
def make_admin(user_id):
    user = User.query.get_or_404(user_id)
    if not user.is_admin:
        user.is_admin = True
        db.session.commit()
        flash(f'המשתמש {user.username} הפך למנהל בהצלחה', 'success')
    return redirect(url_for('admin'))

@app.route('/export_users', methods=['GET'])
@requires_admin
def export_users():
    try:
        # יצירת קובץ CSV
        si = StringIO()
        cw = csv.writer(si)
        
        # כותרות העמודות
        cw.writerow(['שם מלא', 'אימייל', 'תאריך הרשמה', 'התקדמות', 'סוג אכילה', 'מספר שיעורים שהושלמו'])
        
        # נתוני המשתמשים
        users = User.query.all()
        for user in users:
            cw.writerow([
                user.full_name,
                user.email,
                user.registration_date.strftime('%Y-%m-%d'),
                f"{user.get_progress()}%",
                user.get_eating_type(),
                user.get_completed_videos_count()
            ])
        
        # הגדרת התגובה
        output = si.getvalue()
        si.close()
        
        response = app.make_response(output)
        response.headers["Content-Disposition"] = f"attachment; filename=users_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        response.headers["Content-type"] = "text/csv; charset=utf-8"
        return response
        
    except Exception as e:
        app.logger.error(f'שגיאה בייצוא משתמשים: {str(e)}')
        return jsonify({'error': 'שגיאה בייצוא המשתמשים'}), 500

_is_db_initialized = False

@app.before_request
def initialize_database():
    global _is_db_initialized
    if not _is_db_initialized:
        with app.app_context():
            # יצירת הטבלאות אם הן לא קיימות
            db.create_all()
            
            # בדיקה אם העמודה quiz_answers קיימת
            inspector = db.inspect(db.engine)
            columns = [col['name'] for col in inspector.get_columns('users')]
            
            if 'quiz_answers' not in columns:
                # הוספת העמודה quiz_answers
                with db.engine.connect() as conn:
                    conn.execute(db.text(
                        "ALTER TABLE users ADD COLUMN IF NOT EXISTS quiz_answers JSONB DEFAULT '{}'::jsonb"
                    ))
                    conn.commit()
            
            # הוספת מחיר ברירת מחדל אם לא קיים
            if not Settings.query.filter_by(key='course_price').first():
                Settings.set_course_price('997')
            
            # יצירת משתמש אדמין אם לא קיים
            admin_user = User.query.filter_by(username='admin').first()
            if not admin_user:
                admin_user = User(
                    username='admin',
                    email='admin@mindful-weight-loss.com',
                    is_admin=True,
                    registration_date=datetime.now(timezone.utc)
                )
                admin_user.set_password('Aa123456!')
                db.session.add(admin_user)
                db.session.commit()
                app.logger.info('Admin user created successfully')
            
            _is_db_initialized = True

if __name__ == '__main__':
    app.run(debug=True)