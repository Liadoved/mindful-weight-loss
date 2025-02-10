"""Add name column

Revision ID: add_name_column
Create Date: 2025-02-10 12:59:00.000000

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

def downgrade() -> None:
    # Remove name column
    op.drop_column('user', 'name')
