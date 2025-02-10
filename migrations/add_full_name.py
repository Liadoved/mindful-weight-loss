"""Add name column to user table

Revision ID: add_name_column
"""
from alembic import op
import sqlalchemy as sa

def upgrade():
    # Add name column
    op.add_column('user', sa.Column('name', sa.String(120)))

def downgrade():
    # Remove name column
    op.drop_column('user', 'name')
