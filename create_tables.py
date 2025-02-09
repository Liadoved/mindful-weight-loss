from app import app, db

with app.app_context():
    # Create tables if they don't exist
    db.create_all()
    print("Tables created successfully")
