"""empty message

Revision ID: 9adb2951f765
Revises: 823e30498c50
Create Date: 2024-06-20 10:43:05.375142

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '9adb2951f765'
down_revision = '823e30498c50'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('items', schema=None) as batch_op:
        batch_op.add_column(sa.Column('description', sa.String(), nullable=True))

    # ### end Alembic commands ###



def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('items', schema=None) as batch_op:
        batch_op.drop_column('description')

    # ### end Alembic commands ###
