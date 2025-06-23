# init_db.py

import os
from app import app, db, User # Import from your app

print("Starting database initialization...")

# The database URI is configured in app.py using environment variables
with app.app_context():
    print("Creating all database tables...")
    db.create_all()
    print("Tables created.")

    # Check if admin user exists, if not, create one
    if not User.query.filter_by(is_admin=True).first():
        print("Creating default admin user...")
        try:
            admin_user = User(
                first_name="Admin", last_name="User",
                email="admin@officialvoice.com", voter_id="ADMIN001",
                is_admin=True
            )
            # Use environment variable for password if available, otherwise use a default
            # You should set ADMIN_PASSWORD in your production environment!
            admin_password = os.environ.get('ADMIN_PASSWORD', 'AdminPass123')
            admin_user.set_password(admin_password)
            db.session.add(admin_user)
            db.session.commit()
            print("Admin user created successfully.")
        except Exception as e:
            print(f"Error creating admin user: {e}")
            db.session.rollback() # Rollback in case of error
    else:
        print("Admin user already exists.")

print("Database initialization finished.")