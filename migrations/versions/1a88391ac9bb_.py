"""empty message

Revision ID: 1a88391ac9bb
Revises: 
Create Date: 2021-04-10 08:48:40.271474

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '1a88391ac9bb'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('onetimepassword',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('otp_secret', sa.String(length=16), nullable=True),
    sa.Column('token', sa.String(length=8), nullable=True),
    sa.Column('is_used', sa.Boolean(), nullable=False),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('token')
    )
    op.create_table('user_locked_out',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('username', sa.String(length=64), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_user_locked_out_username'), 'user_locked_out', ['username'], unique=True)
    op.create_table('admin',
    sa.Column('name', sa.String(length=64), nullable=False),
    sa.Column('username', sa.String(length=64), nullable=False),
    sa.Column('email', sa.String(length=120), nullable=False),
    sa.Column('login_attempt_number', sa.Integer(), nullable=False),
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('admin_password_hash', sa.String(length=128), nullable=False),
    sa.Column('admin_mode', sa.Boolean(), nullable=False),
    sa.Column('otp_id', sa.Integer(), nullable=True),
    sa.ForeignKeyConstraint(['otp_id'], ['onetimepassword.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_admin_email'), 'admin', ['email'], unique=True)
    op.create_index(op.f('ix_admin_username'), 'admin', ['username'], unique=True)
    op.create_table('user',
    sa.Column('name', sa.String(length=64), nullable=False),
    sa.Column('username', sa.String(length=64), nullable=False),
    sa.Column('email', sa.String(length=120), nullable=False),
    sa.Column('login_attempt_number', sa.Integer(), nullable=False),
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('is_admin', sa.Boolean(), nullable=False),
    sa.Column('sent_email', sa.Integer(), nullable=False),
    sa.Column('password_hash', sa.String(length=128), nullable=False),
    sa.Column('otp_id', sa.Integer(), nullable=True),
    sa.ForeignKeyConstraint(['otp_id'], ['onetimepassword.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_user_email'), 'user', ['email'], unique=True)
    op.create_index(op.f('ix_user_username'), 'user', ['username'], unique=True)
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_index(op.f('ix_user_username'), table_name='user')
    op.drop_index(op.f('ix_user_email'), table_name='user')
    op.drop_table('user')
    op.drop_index(op.f('ix_admin_username'), table_name='admin')
    op.drop_index(op.f('ix_admin_email'), table_name='admin')
    op.drop_table('admin')
    op.drop_index(op.f('ix_user_locked_out_username'), table_name='user_locked_out')
    op.drop_table('user_locked_out')
    op.drop_table('onetimepassword')
    # ### end Alembic commands ###