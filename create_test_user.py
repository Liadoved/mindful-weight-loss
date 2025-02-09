from app import app, db, User
from werkzeug.security import generate_password_hash

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

with app.app_context():
    # יצירת הטבלאות
    print("Creating database tables...")
    db.drop_all()  # מוחק את כל הטבלאות הקיימות
    db.create_all()  # יוצר את כל הטבלאות מחדש
    print("Database tables created successfully!")

    # בדיקה אם המשתמש כבר קיים
    existing_admin = User.query.filter_by(username='admin').first()
    if existing_admin is None:
        # הוספת המשתמש לבסיס הנתונים
        db.session.add(admin_user)
        db.session.commit()
        print("Admin user created successfully!")
    else:
        print("Admin user already exists!")
