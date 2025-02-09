from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timezone
from functools import wraps
import os
import json
from flask_oauthlib.client import OAuth
from dotenv import load_dotenv
from flask_mail import Mail, Message
import logging
from logging.handlers import RotatingFileHandler
import string
import random
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import ssl

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///users.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
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
    password_hash = db.Column(db.String(120))
    full_name = db.Column(db.String(120))
    phone = db.Column(db.String(20))
    gender = db.Column(db.String(10))  # זכר/נקבה
    registration_date = db.Column(db.DateTime, default=datetime.now(timezone.utc))
    last_login = db.Column(db.DateTime)
    difficulty = db.Column(db.Integer, default=0)  # 0=לא ענה, 1=מאוזנת, 2=רגשית, 3=כפייתית
    quiz_answers = db.Column(db.JSON, default={})  # שמירת תשובות השאלון
    completed_videos = db.Column(db.Text, default='')
    progress = db.Column(db.Integer, default=0)
    is_admin = db.Column(db.Boolean, default=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
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
        return len(self.completed_videos.split(','))

    def mark_video_completed(self, video_id):
        completed = set(self.completed_videos.split(',')) if self.completed_videos else set()
        completed.add(str(video_id))
        self.completed_videos = ','.join(sorted(completed))
        # עדכון התקדמות
        total_videos = 10  # מספר הסרטונים הכולל בקורס
        self.progress = min(100, int((len(completed) / total_videos) * 100))
        db.session.commit()

class Settings(db.Model):
    __tablename__ = 'settings'
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(50), unique=True, nullable=False)
    value = db.Column(db.String(500), nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.now(timezone.utc))

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

def requires_admin(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash('אין לך הרשאות לצפות בדף זה', 'error')
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

google = oauth.remote_app(
    'google',
    consumer_key=os.getenv('GOOGLE_CLIENT_ID'),
    consumer_secret=os.getenv('GOOGLE_CLIENT_SECRET'),
    request_token_params={
        'scope': 'email profile openid',
        'access_type': 'offline',
        'include_granted_scopes': 'true'
    },
    base_url='https://www.googleapis.com/oauth2/v2/',
    request_token_url=None,
    access_token_method='POST',
    access_token_url='https://oauth2.googleapis.com/token',
    authorize_url='https://accounts.google.com/o/oauth2/v2/auth'
)

@google.tokengetter
def get_google_oauth_token():
    return session.get('google_token')

@app.route('/login/google')
def google_login():
    return google.authorize(callback=url_for('google_authorized', _external=True))

@app.route('/login/google/authorized')
def google_authorized():
    try:
        app.logger.info("Starting Google authorization process")
        app.logger.info(f"Request args: {request.args}")
        
        resp = google.authorized_response()
        app.logger.info(f"Google response received: {resp}")
        
        if resp is None:
            error_reason = request.args.get('error_reason', 'unknown')
            error_description = request.args.get('error_description', 'No data received.')
            app.logger.error(f"Authorization failed: {error_reason} - {error_description}")
            return f'Access denied: reason={error_reason} error={error_description}'
            
        if 'access_token' not in resp:
            app.logger.error(f"No access token in response: {resp}")
            return 'Access token not found in response'
        
        session['google_token'] = (resp['access_token'], '')
        app.logger.info("Access token saved to session")
        
        try:
            me = google.get('userinfo')
            app.logger.info(f"User info received: {me.data if me else 'None'}")
            
            if not me or not me.data or 'email' not in me.data:
                app.logger.error("Failed to get valid user info")
                return 'Failed to get user info'
            
            # בדיקה אם המשתמש כבר קיים במערכת
            user = User.query.filter_by(email=me.data['email']).first()
            
            if not user:
                app.logger.info(f"Creating new user for email: {me.data['email']}")
                # יצירת משתמש חדש
                username = me.data['email'].split('@')[0]
                base_username = username
                counter = 1
                
                # בדיקה אם שם המשתמש כבר קיים ויצירת שם חדש אם צריך
                while User.query.filter_by(username=username).first():
                    username = f"{base_username}{counter}"
                    counter += 1
                
                user = User(
                    username=username,
                    email=me.data['email'],
                    registration_date=datetime.now(timezone.utc)
                )
                db.session.add(user)
                db.session.commit()
                app.logger.info(f"New user created: {username}")
            else:
                app.logger.info(f"Existing user found: {user.username}")
            
            # התחברות המשתמש
            login_user(user)
            user.last_login = datetime.now(timezone.utc)
            db.session.commit()
            
            flash('התחברת בהצלחה!', 'success')
            app.logger.info(f"User {user.username} logged in successfully")
            return redirect(url_for('course'))
            
        except Exception as e:
            app.logger.error(f"Error getting user info: {str(e)}")
            app.logger.exception(e)
            return 'Failed to get user info'
            
    except Exception as e:
        app.logger.error(f"Error in google_authorized: {str(e)}")
        app.logger.exception(e)
        return 'Error during authorization'

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email')
        full_name = request.form.get('full_name')
        age = request.form.get('age')
        gender = request.form.get('gender')
        phone = request.form.get('phone')
        city = request.form.get('city')
        address = request.form.get('address')
        difficulty = request.form.get('difficulty')
        comments = request.form.get('comments')

        # בדיקת שדות חובה
        required_fields = {'email': email, 'full_name': full_name, 'age': age, 
                         'gender': gender, 'phone': phone, 'difficulty': difficulty}
        
        missing_fields = [field for field, value in required_fields.items() if not value]
        
        if missing_fields:
            app.logger.warning(f"Registration failed: Missing required fields: {', '.join(missing_fields)}")
            flash("אנא מלא/י את כל שדות החובה")
            return render_template('register.html')

        # בדיקה אם המשתמש כבר קיים
        if User.query.filter_by(email=email).first():
            flash("כתובת האימייל כבר רשומה במערכת")
            return render_template('register.html')

        try:
            # משתמשים במספר הטלפון כסיסמה
            password = phone
            
            # יצירת משתמש חדש
            new_user = User(
                username=email,  # משתמשים באימייל בתור שם משתמש
                email=email,
                password_hash=generate_password_hash(password),
                full_name=full_name,
                age=int(age),
                gender=gender,
                phone=phone,
                city=city or None,
                address=address or None,
                difficulty=int(difficulty),
                comments=comments or None,
                registration_date=datetime.now(timezone.utc)  # שימוש ב-datetime במקום current_timestamp
            )
            
            db.session.add(new_user)
            db.session.commit()
            
            # הכנת נתוני המשתמש לשליחה במייל
            user_data = {
                'full_name': full_name,
                'email': email,
                'phone': phone,
                'age': age,
                'gender': gender,
                'city': city,
                'address': address,
                'difficulty': difficulty,
                'comments': comments,
                'registration_date': new_user.registration_date  # שימוש באובייקט שכבר נשמר
            }
            
            # שליחת מייל למשתמש
            user_email_sent = send_registration_email(email, email, password, user_data, is_admin=False)
            
            # שליחת מייל למנהל
            admin_email_sent = send_registration_email(email, email, password, user_data, is_admin=True)
            
            if user_email_sent and admin_email_sent:
                flash("ההרשמה הושלמה בהצלחה! שלחנו לך מייל עם פרטי ההתחברות")
            else:
                flash("ההרשמה הושלמה אך הייתה בעיה בשליחת המייל. אנא צור/י קשר עם התמיכה")
            
            return redirect(url_for('login'))
                
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Registration error: {str(e)}")
            flash("אירעה שגיאה בתהליך ההרשמה. אנא נסה/י שוב מאוחר יותר")
            return render_template('register.html')

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            flash('אנא מלא את כל השדות')
            return render_template('login.html')
        
        # מנסה למצוא משתמש לפי אימייל או שם משתמש
        user = User.query.filter(
            db.or_(User.email == username, User.username == username)
        ).first()
        
        if user and user.check_password(password):
            login_user(user)
            
            # עדכון זמן התחברות אחרון
            user.last_login = datetime.now(timezone.utc)
            db.session.commit()
            
            # בדיקה אם יש הפניה לדף אחר
            next_page = request.args.get('next')
            if next_page:
                return redirect(next_page)
            
            # אם אין הפניה, מעביר לדף הקורס
            return redirect(url_for('course'))
        else:
            flash('שם משתמש או סיסמה שגויים')
            return render_template('login.html')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/course')
@login_required
def course():
    try:
        completed_videos = []
        if current_user.completed_videos:
            completed_videos = current_user.completed_videos.split(',')
            
        app.logger.info(f"Completed videos: {completed_videos}")
        
        # חישוב ההתקדמות
        progress = 0
        if completed_videos:
            progress = int((len(completed_videos) / TOTAL_ITEMS) * 100)
            
        app.logger.info(f"Progress: {progress}%")
        
        # קביעת הפרק הבא
        next_chapter = 1
        for i in range(1, 8):  # 7 chapters total
            if str(i) not in completed_videos:
                next_chapter = i
                break
        
        app.logger.info(f"Next chapter: {next_chapter}")
        
        return render_template('course.html',
                             completed_videos=completed_videos,
                             progress=progress,
                             next_chapter=next_chapter)
    except Exception as e:
        app.logger.error(f"Error in course route: {str(e)}")
        return render_template('course.html', completed_videos=[], progress=0, next_chapter=1)

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
        current_user.completed_videos = ''
        current_user.progress = 0
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        app.logger.error(f"Error resetting progress: {str(e)}")
        db.session.rollback()
        return jsonify({'success': False, 'message': 'An error occurred'})

@app.route('/quiz', methods=['GET', 'POST'])
@login_required
def quiz():
    if request.method == 'POST':
        answers = request.form.to_dict()
        current_user.save_quiz_answers(answers)  # שמירת התשובות
        
        # חישוב התוצאה
        emotional_score = int(answers.get('q2', 0)) + int(answers.get('q4', 0)) + int(answers.get('q6', 0))
        compulsive_score = int(answers.get('q1', 0)) + int(answers.get('q3', 0)) + int(answers.get('q5', 0))
        
        if emotional_score > compulsive_score:
            current_user.difficulty = 2  # רגשית
        elif compulsive_score > emotional_score:
            current_user.difficulty = 3  # כפייתית
        else:
            current_user.difficulty = 1  # מאוזנת
            
        db.session.commit()
        return redirect(url_for('quiz_results'))
        
    # אם יש תשובות קודמות, נציג אותן
    saved_answers = current_user.get_quiz_answers()
    return render_template('quiz.html', saved_answers=saved_answers)

@app.route('/quiz_results')
@login_required
def quiz_results():
    if current_user.difficulty == 0:
        return redirect(url_for('quiz'))
    return render_template('quiz_results.html', 
                         eating_type=current_user.get_eating_type(),
                         answers=current_user.get_quiz_answers())

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
            
            _is_db_initialized = True

if __name__ == '__main__':
    app.run(debug=True)