from app import app, db, User

# Create the database tables
with app.app_context():
    db.create_all()
    
    # Create a test user
    test_user = User(
        username="test@example.com",
        email="test@example.com",
        full_name="משתמש לדוגמה",
        age=30,
        gender="male",
        address="רחוב הרצל 1",
        city="תל אביב",
        phone="0501234567",
        difficulty=3,
        comments="משתמש לבדיקת המערכת",
        progress=0,
        completed_videos=""
    )
    
    # Set password
    test_user.set_password("test123")  # שינינו את הסיסמה למשהו פשוט יותר
    
    # Add user to database
    db.session.add(test_user)
    db.session.commit()
    
    print("Test user created successfully!")
    print("Username: test@example.com")
    print("Password: test123")
