"""empty message

Revision ID: 0e1d299b570b
Revises: c1368071c083
Create Date: 2017-01-23 16:33:21.514982

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '0e1d299b570b'
down_revision = 'c1368071c083'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('records', sa.Column('user_sso', sa.Integer(), nullable=True))
    # op.drop_constraint(None, 'records', type_='foreignkey')
    # op.create_foreign_key(None, 'records', 'users', ['user_sso'], ['sso'])
    op.drop_column('records', 'sso')
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('records', sa.Column('sso', sa.Integer(), nullable=True))
    # op.drop_constraint(None, 'records', type_='foreignkey')
    # op.create_foreign_key(None, 'records', 'users', ['sso'], ['sso'])
    op.drop_column('records', 'user_sso')
    # ### end Alembic commands ###