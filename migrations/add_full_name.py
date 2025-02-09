"""Add full_name column to user table

Revision ID: add_full_name
"""
from alembic import op
import sqlalchemy as sa

def upgrade():
    # Add full_name column
    op.add_column('user', sa.Column('full_name', sa.String(120)))
    
    # Copy data from name to full_name if it exists
    try:
        op.execute('UPDATE "user" SET full_name = name')
        # Drop the old name column
        op.drop_column('user', 'name')
    except:
        pass  # name column might not exist

def downgrade():
    # Remove full_name column
    op.drop_column('user', 'full_name')
