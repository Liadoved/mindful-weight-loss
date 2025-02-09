from app import app, db, User
from werkzeug.security import generate_password_hash

# Create the database tables
with app.app_context():
    db.create_all()
    
    # Create a test user
    test_user = User(
        username="test@example.com",
        email="test@example.com",
        password_hash=generate_password_hash("password123"),
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
    
    # Add the user to the database
    db.session.add(test_user)
    db.session.commit()
    
    print("Test user created successfully!")
