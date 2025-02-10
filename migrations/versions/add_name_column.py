"""Add name column

Revision ID: add_name_column
Create Date: 2025-02-10 13:12:00.000000

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'add_name_column'
down_revision = None
branch_labels = None
depends_on = None

def upgrade() -> None:
    # Add name column if it doesn't exist
    op.add_column('user', sa.Column('name', sa.String(120)))
    
    # Copy data from full_name to name if full_name exists
    try:
        op.execute('UPDATE "user" SET name = full_name')
    except:
        pass
    
    # Drop full_name column if it exists
    try:
        op.drop_column('user', 'full_name')
    except:
        pass

def downgrade() -> None:
    # Add full_name column
    op.add_column('user', sa.Column('full_name', sa.String(120)))
    
    # Copy data from name to full_name
    op.execute('UPDATE "user" SET full_name = name')
    
    # Drop name column
    op.drop_column('user', 'name')
