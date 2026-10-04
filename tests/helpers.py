import tempfile
from pathlib import Path

from app.core.config import load_settings
from app.main import create_app


def make_app(extra_env=None):
    tmp = Path(tempfile.mkdtemp(prefix="csx_test_"))
    env = {"CYBERSHIELD_DB_PATH": str(tmp / "test.db")}
    env.update(extra_env or {})
    settings = load_settings(env, read_dotenv=False)
    return create_app(settings), settings
