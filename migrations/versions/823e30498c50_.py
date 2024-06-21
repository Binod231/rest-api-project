"""empty message

Revision ID: 823e30498c50
Revises: 
Create Date: 2024-06-20 10:36:33.533815

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '823e30498c50'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('blocklist')
    with op.batch_alter_table('token_blocklist', schema=None) as batch_op:
        batch_op.drop_index('ix_token_blocklist_jti')

    op.drop_table('token_blocklist')
    op.drop_table('blacklist')
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('blacklist',
    sa.Column('jti', sa.VARCHAR(), nullable=False),
    sa.Column('user_id', sa.INTEGER(), nullable=True),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
    sa.PrimaryKeyConstraint('jti')
    )
    op.create_table('token_blocklist',
    sa.Column('id', sa.INTEGER(), nullable=False),
    sa.Column('jti', sa.VARCHAR(length=36), nullable=False),
    sa.Column('created_at', sa.DATETIME(), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('token_blocklist', schema=None) as batch_op:
        batch_op.create_index('ix_token_blocklist_jti', ['jti'], unique=False)

    op.create_table('blocklist',
    sa.Column('id', sa.INTEGER(), nullable=False),
    sa.Column('token', sa.VARCHAR(length=256), nullable=False),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('token')
    )
    # ### end Alembic commands ###