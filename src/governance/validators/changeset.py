from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import PurePosixPath

from governance.validators.base import FileSet, Finding, Validator

SOURCE = (".py", ".ts", ".tsx", ".js", ".jsx", ".rs")
TEST = re.compile(r"(^|/)(tests?|__tests__|spec)/|(^|/)test_[^/]+\.py$|_test\.(py|rs)$|\.(test|spec)\.[jt]sx?$")
NON_BEHAVIOURAL = re.compile(r"(^|/)(docs?|migrations?|scripts)/|(^|/)(conftest|setup|__init__)\.py$")


def tests_accompany_changes(fs: FileSet) -> Iterator[Finding]:
    if fs.changed is None:
        return
    changed = list(fs.changed)
    sources = [p for p in changed if p.endswith(SOURCE) and not TEST.search(p) and not NON_BEHAVIOURAL.search(p)]
    if sources and not any(TEST.search(p) for p in changed):
        names = ", ".join(PurePosixPath(p).name for p in sources[:5])
        yield Finding(sources[0], 1, f"Production code changed ({names}) without test changes.")


VALIDATORS = [
    Validator(
        "tests-accompany-changes",
        "Production changes include test changes",
        changeset_check=tests_accompany_changes,
    ),
]
