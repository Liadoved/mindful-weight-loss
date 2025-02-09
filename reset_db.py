from app import app, db

with app.app_context():
    # Drop all tables
    db.drop_all()
    # Create tables
    db.create_all()
    print("Database reset successfully")
