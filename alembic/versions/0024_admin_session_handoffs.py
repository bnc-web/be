"""Persist short-lived, single-use Android admin browser handoffs."""

from sqlalchemy import inspect, text

from alembic import op
from app.models.admin_session_handoff import AdminSessionHandoff

revision = "0024_admin_session_handoffs"
down_revision = "0023_backend_tables_rls"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    AdminSessionHandoff.__table__.create(bind, checkfirst=True)
    if bind.dialect.name == "postgresql":
        tables = set(inspect(bind).get_table_names(schema="public"))
        if AdminSessionHandoff.__tablename__ in tables:
            bind.execute(
                text(
                    'ALTER TABLE public."admin_session_handoffs" '
                    "ENABLE ROW LEVEL SECURITY"
                )
            )


def downgrade():
    AdminSessionHandoff.__table__.drop(op.get_bind(), checkfirst=True)
