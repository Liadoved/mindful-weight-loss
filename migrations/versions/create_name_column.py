"""Create name column

Revision ID: create_name_column
Create Date: 2025-02-10 13:22:00.000000

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'create_name_column'
down_revision = None
branch_labels = None
depends_on = None

def upgrade() -> None:
    # Create name column
    op.add_column('user', sa.Column('name', sa.String(120)))

def downgrade() -> None:
    # Remove name column
    op.drop_column('user', 'name')
