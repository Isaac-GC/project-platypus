# conftest.py
# Place this file at the root of your project (alongside the `dex/` package).
# pytest will automatically pick it up and add the project root to sys.path.

import sys
import os

# Ensure project root is on the path so `dex.*` imports resolve
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))