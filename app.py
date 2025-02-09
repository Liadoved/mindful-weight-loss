from flask import Flask, render_template, redirect, url_for, flash, request, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import os
import logging
from datetime import datetime
from logging.handlers import RotatingFileHandler
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'default-secret-key')

# Database configuration
if os.environ.get('DATABASE_URL'):
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL').replace('postgres://', 'postgresql://')
else:
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'

db = SQLAlchemy(app)

# Login manager configuration
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Email configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
mail = Mail(app)

# User model
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

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Configure logging
if not os.path.exists('logs'):
    os.mkdir('logs')

file_handler = RotatingFileHandler('logs/registration.log', maxBytes=10240, backupCount=10)
file_handler.setFormatter(logging.Formatter(
    '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
))
file_handler.setLevel(logging.INFO)
app.logger.addHandler(file_handler)
app.logger.setLevel(logging.INFO)
app.logger.info('Mindful Weight Loss startup')

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

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # Extract form data with default values
        username = request.form.get('email', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()
        full_name = request.form.get('full_name', '').strip()
        age = request.form.get('age', '')
        gender = request.form.get('gender', '').strip()
        address = request.form.get('address', '').strip()
        city = request.form.get('city', '').strip()
        phone = request.form.get('phone', '').strip()
        difficulty = request.form.get('difficulty', '')
        comments = request.form.get('comments', '').strip()

        # לוג פרטי הרשמה
        app.logger.info(f'Registration attempt: {username}, {email}')

        # Validate required fields
        if not all([username, email, password, full_name]):
            app.logger.warning('Registration failed: Missing required fields')
            flash('אנא מלא את כל השדות החובה', 'error')
            return render_template('register.html')

        # Check if user already exists
        user = User.query.filter_by(username=username).first()
        if user:
            app.logger.warning(f'Registration failed: User {username} already exists')
            flash('משתמש קיים במערכת', 'error')
            return render_template('register.html')

        # Convert age and difficulty to integers safely
        try:
            age = int(age) if age else None
            difficulty = int(difficulty) if difficulty else None
        except ValueError:
            app.logger.warning('Registration failed: Invalid age or difficulty')
            flash('גיל ורמת קושי צריכים להיות מספרים', 'error')
            return render_template('register.html')

        # Create new user
        new_user = User(
            username=username,
            email=email,
            full_name=full_name,
            age=age,
            gender=gender,
            address=address,
            city=city,
            phone=phone,
            difficulty=difficulty,
            comments=comments
        )
        new_user.set_password(password)

        try:
            db.session.add(new_user)
            db.session.commit()
            app.logger.info(f'User {username} registered successfully')

            # Send confirmation email
            try:
                msg = Message('ברוכים הבאים לקורס הרזיה מודעת!',
                            sender=app.config['MAIL_USERNAME'],
                            recipients=[email])
                msg.body = f'''שלום {full_name},

תודה שנרשמת לקורס הרזיה מודעת! אנחנו שמחים לקבל אותך לקהילה שלנו.

פרטי ההתחברות שלך לאתר:
------------------------
שם משתמש: {email}
סיסמה: {password}

כדי להתחיל את הקורס:
1. היכנס/י לאתר בכתובת: http://localhost:5002/login
2. הזן/י את פרטי ההתחברות שלך
3. התחל/י את המסע שלך להרזיה מודעת!

אם יש לך שאלות או בעיות בהתחברות, אל תהסס/י ליצור איתנו קשר.

בברכה,
צוות הרזיה מודעת'''
                
                # שלח את המייל
                mail.send(msg)
                app.logger.info(f'Confirmation email sent to {email}')
                
                # הודעת הבזק להצגה למשתמש
                flash('ההרשמה בוצעה בהצלחה! פרטי ההתחברות נשלחו למייל שלך.', 'success')
            
            except Exception as email_error:
                app.logger.error(f'Failed to send email: {str(email_error)}')
                flash(f'ההרשמה בוצעה בהצלחה! שמור את פרטי ההתחברות: משתמש - {email}, סיסמה - {password}', 'warning')

            # Log in the user automatically after registration
            login_user(new_user)
            
            # Redirect to course page with a success message
            return redirect(url_for('course'))
        
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error during registration: {str(e)}")
            flash('אירעה שגיאה בהרשמה. אנא נסה שוב.', 'error')
            return render_template('register.html')

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Demo mode - auto login
        demo_user = User.query.filter_by(username='demo').first()
        if not demo_user:
            demo_user = User(username='demo', email='demo@example.com')
            demo_user.set_password('demo123')
            db.session.add(demo_user)
            db.session.commit()
        
        login_user(demo_user)
        return redirect(url_for('course'))
    
    return render_template('login.html')

@app.route('/logout')
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
                             next_chapter=next_chapter,
                             videos=VIDEOS)
    except Exception as e:
        app.logger.error(f"Error in course route: {str(e)}")
        return render_template('course.html', completed_videos=[], progress=0, next_chapter=1, videos=VIDEOS)

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

@app.route('/about_course')
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

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    port = int(os.environ.get('PORT', 5002))
    app.run(host='0.0.0.0', port=port, debug=True)