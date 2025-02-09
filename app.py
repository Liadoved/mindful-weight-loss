from flask import Flask, render_template, redirect, url_for, flash, request, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
import os
from dotenv import load_dotenv
import logging
from logging.handlers import RotatingFileHandler
from functools import wraps
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import string
import random

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'default-dev-key')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'postgresql://mindful_weight_loss_db_user:zD74Z46KHMson7xDWV6FGhqYqGpyrhtS@dpg-cuhi2g23esus73cjn9vg-a/mindful_weight_loss_db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Email configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
mail = Mail(app)

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
    __tablename__ = 'users'  # Explicitly set table name
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    progress = db.Column(db.Integer, default=0)
    completed_videos = db.Column(db.String(200), default='')
    full_name = db.Column(db.String(100))
    age = db.Column(db.Integer)
    gender = db.Column(db.String(20))
    address = db.Column(db.String(200))
    city = db.Column(db.String(100))
    phone = db.Column(db.String(20))
    difficulty = db.Column(db.Integer)
    comments = db.Column(db.Text)
    is_admin = db.Column(db.Boolean, default=False)
    registration_date = db.Column(db.DateTime, default=db.func.current_timestamp())
    last_login = db.Column(db.DateTime)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

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

def send_registration_email(email, username, password):
    """Send registration confirmation email with login credentials."""
    sender_email = "razit.mindful@gmail.com"  # כתובת המייל של המערכת
    sender_password = os.environ.get("EMAIL_PASSWORD")
    
    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = email
    msg['Subject'] = "ברוכים הבאים לקורס רזית!"
    
    body = f"""
    שלום רב,
    
    תודה שנרשמת לקורס רזית! אנחנו שמחים לראות אותך איתנו.
    
    פרטי ההתחברות שלך:
    שם משתמש: {username}
    סיסמה: {password}
    
    אנא שמור/י פרטים אלו במקום בטוח.
    
    ניתן להתחבר לאתר בכתובת:
    https://mindful-weight-loss.onrender.com/login
    
    בברכה,
    צוות רזית
    """
    
    msg.attach(MIMEText(body, 'plain', 'utf-8'))
    
    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(sender_email, sender_password)
        server.send_message(msg)
        server.quit()
        return True
    except Exception as e:
        app.logger.error(f"Failed to send email: {str(e)}")
        return False

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
            # יצירת סיסמה רנדומלית
            password = generate_password()
            
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
                registration_date=db.func.current_timestamp()
            )
            
            db.session.add(new_user)
            db.session.commit()
            
            # שליחת מייל עם פרטי ההתחברות
            if send_registration_email(email, email, password):
                flash("ההרשמה הושלמה בהצלחה! שלחנו לך מייל עם פרטי ההתחברות")
                return redirect(url_for('login'))
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
        # בדיקה אם המשתמש התחבר עם שם משתמש או אימייל
        login_id = request.form.get('email')  # נשאיר את השם 'email' בטופס כדי לא לשבור את הממשק
        user = User.query.filter(
            (User.username == login_id) | (User.email == login_id)
        ).first()
        
        if user is None or not user.check_password(request.form.get('password')):
            flash('שם משתמש או סיסמה לא נכונים', 'error')
            return render_template('login.html')
        
        # עדכון זמן הכניסה האחרון
        user.last_login = db.func.current_timestamp()
        db.session.commit()
        
        login_user(user)
        
        # אם יש הפניה לדף מסוים אחרי הלוגין
        next_page = request.args.get('next')
        if next_page:
            return redirect(next_page)
        return redirect(url_for('index'))
        
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

@app.route('/quiz')
@login_required
def quiz():
    return render_template('quiz.html')

@app.route('/submit_quiz', methods=['POST'])
def submit_quiz():
    try:
        results = request.get_json()
        
        # Save results in session
        session['quiz_results'] = results
        
        return jsonify({
            'status': 'success',
            'message': 'התוצאות נשמרו בהצלחה'
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/quiz_results')
def quiz_results():
    return render_template('quiz_results.html')

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
    users = User.query.all()
    return render_template('admin.html', users=users)

if __name__ == '__main__':
    with app.app_context():
        # Create tables if they don't exist
        db.create_all()
    app.run(debug=True, host='0.0.0.0', port=5002)