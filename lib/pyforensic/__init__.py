"""Safety-critical case engine backing the ``bin/*`` CLI wrappers.

This package intentionally uses only the Python standard library. It is
imported both as a library (by ``cli.py`` and the test suite) and executed
directly for the flag-scanner worker subprocess.
"""
