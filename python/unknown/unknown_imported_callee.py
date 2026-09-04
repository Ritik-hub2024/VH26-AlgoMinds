"""Unknown Case: Resource passed to external library function."""

import shutil


def delegate_to_system():
    f = open("temp_archive.tar", "rb")
    # Ownership transferred to external module function whose AST is not available
    shutil.copyfileobj(f, None)
    return "delegated"
