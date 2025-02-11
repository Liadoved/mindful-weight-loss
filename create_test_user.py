from app import app, db, User
from werkzeug.security import generate_password_hash

def create_admin_user(username, email, password):
    with app.app_context():
        # בדיקה אם המשתמש כבר קיים
        existing_user = User.query.filter(
            (User.username == username) | (User.email == email)
        ).first()
        
        if existing_user:
            # עדכון המשתמש הקיים
            existing_user.username = username
            existing_user.email = email
            existing_user.password_hash = generate_password_hash(password)
            existing_user.is_admin = True
            db.session.commit()
            print(f"Admin user {username} updated successfully!")
        else:
            # יצירת משתמש חדש
            user = User(
                username=username,
                email=email,
                password_hash=generate_password_hash(password),
                is_admin=True
            )
            db.session.add(user)
            db.session.commit()
            print(f"Admin user {username} created successfully!")
        
        # בדיקת המשתמש שנוצר
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            print(f"Password verification successful for {username}")
        else:
            print(f"Password verification failed for {username}")

if __name__ == '__main__':
    print("Creating database tables...")
    with app.app_context():
        db.create_all()
    print("Database tables created successfully!")
    
    # יצירת משתמשי אדמין
    create_admin_user('admin', 'admin@razit.co.il', 'Razit123321')
    create_admin_user('razit.mindful', 'razit.mindful@gmail.com', 'Razit123321')
    
    # הצגת כל המשתמשים בבסיס הנתונים
    print("\nCurrent users in database:")
    with app.app_context():
        users = User.query.all()
        for user in users:
            print(f"Username: {user.username}, Email: {user.email}, Is Admin: {user.is_admin}, Has Password: {bool(user.password_hash)}")
