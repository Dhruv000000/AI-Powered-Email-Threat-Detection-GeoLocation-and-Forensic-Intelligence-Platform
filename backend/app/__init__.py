import sys
from pathlib import Path

# Ensure both backend/ and project root are dynamically in sys.path
_current_file = Path(__file__).resolve()
_app_dir = _current_file.parent
_backend_dir = _app_dir.parent
_root_dir = _backend_dir.parent

for _p in [str(_app_dir), str(_backend_dir), str(_root_dir)]:
    if _p not in sys.path:
        sys.path.insert(0, _p)
