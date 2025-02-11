from app import app, db, User
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timezone

ADMIN_PASSWORD = 'Razit123321'

# יצירת משתמשי אדמין
admin_users = [
    User(
        username='admin',
        email='admin@razit.co.il',
        password_hash=generate_password_hash(ADMIN_PASSWORD),
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
        password_hash=generate_password_hash(ADMIN_PASSWORD),
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
            
            # בדיקה שהמשתמש נוצר כראוי
            created_user = User.query.filter_by(username=admin_user.username).first()
            if created_user and created_user.check_password(ADMIN_PASSWORD):
                print(f"Admin user {admin_user.username} created and verified successfully!")
            else:
                print(f"Warning: Admin user {admin_user.username} created but password verification failed!")
        else:
            print(f"Admin user {admin_user.username} already exists!")

    # הצגת כל המשתמשים
    print("\nCurrent users in database:")
    for user in User.query.all():
        print(f"Username: {user.username}, Email: {user.email}, Is Admin: {user.is_admin}, Has Password: {bool(user.password_hash)}")
