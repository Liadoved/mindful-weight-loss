from app import app, db, User
from werkzeug.security import generate_password_hash
from datetime import datetime, timezone

# יצירת משתמשי אדמין
admin_users = [
    User(
        username='admin',
        email='admin@razit.co.il',
        password_hash=generate_password_hash('Razit123321'),
        full_name='מנהל המערכת',
        phone='',
        gender='other',
        registration_date=datetime.now(timezone.utc),
        difficulty=0,
        is_admin=True
    ),
    User(
        username='razit.mindful',
        email='razit.mindful@gmail.com',
        password_hash=generate_password_hash('Razit123321'),
        full_name='מנהל המערכת',
        phone='',
        gender='other',
        registration_date=datetime.now(timezone.utc),
        difficulty=0,
        is_admin=True
    )
]

with app.app_context():
    # יצירת הטבלאות
    print("Creating database tables...")
    db.drop_all()  # מוחק את כל הטבלאות הקיימות
    db.create_all()  # יוצר את כל הטבלאות מחדש
    print("Database tables created successfully!")

    # הוספת המשתמשים
    for admin_user in admin_users:
        existing_admin = User.query.filter(
            (User.username == admin_user.username) | 
            (User.email == admin_user.email)
        ).first()
        
        if existing_admin is None:
            db.session.add(admin_user)
            db.session.commit()
            print(f"Admin user {admin_user.username} created successfully!")
        else:
            print(f"Admin user {admin_user.username} already exists!")
