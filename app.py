from flask import Flask, render_template, redirect, url_for, flash, request, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
import os
from dotenv import load_dotenv
import logging
from logging.handlers import RotatingFileHandler

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'default-dev-key')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
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

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

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
        username = request.form.get('username')
        password = request.form.get('password')
        
        try:
            user = User.query.filter_by(username=username).first()
            if user and user.check_password(password):
                login_user(user)
                return redirect(url_for('course'))
            else:
                flash('שם משתמש או סיסמה שגויים')
        except Exception as e:
            print(f"Error during login: {str(e)}")
            flash('אירעה שגיאה בהתחברות. אנא נסה שוב.')
            
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/course')
def course():
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
    
    # Get completed videos from session
    completed_videos = session.get('completed_videos', [])
    
    # Define chapters
    chapters = {
        '1': 'פרק ראשון - מבוא',
        '2': 'פרק שני - הכרת דפוסי האכילה',
        '3': 'פרק שלישי - זיהוי רעב ושובע',
        '4': 'פרק רביעי - אכילה מודעת',
        '5': 'פרק חמישי - שאלון אבחון',
        '6': 'פרק שישי - סיכום'
    }
    
    return render_template('course.html', 
                         chapters=chapters,
                         completed_videos=completed_videos)

@app.route('/mark_complete/<int:chapter_id>', methods=['POST'])
def mark_complete(chapter_id):
    if not current_user.is_authenticated:
        return jsonify({'success': False, 'message': 'נדרשת התחברות'})
    
    # Get completed videos from session
    completed_videos = session.get('completed_videos', [])
    
    # Add the chapter to completed videos if not already there
    if str(chapter_id) not in completed_videos:
        completed_videos.append(str(chapter_id))
        session['completed_videos'] = completed_videos
    
    # Calculate progress
    total_chapters = 6
    progress = (len(completed_videos) / total_chapters) * 100
    
    return jsonify({
        'success': True,
        'progress': progress,
        'message': 'הפרק סומן כהושלם בהצלחה'
    })

@app.route('/reset_progress', methods=['POST'])
def reset_progress():
    if not current_user.is_authenticated:
        return jsonify({'success': False, 'message': 'נדרשת התחברות'})
    
    # Clear completed videos from session
    session['completed_videos'] = []
    
    return jsonify({
        'success': True,
        'message': 'ההתקדמות אופסה בהצלחה'
    })

@app.route('/about_course')
def about_course():
    return render_template('about_course.html')

@app.route('/contact')
def contact():
    return render_template('contact.html')

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
        # Create tables if they don't exist
        db.create_all()
    app.run(debug=True, host='0.0.0.0', port=5002)