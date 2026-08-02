"""Fixture used by CI to confirm the security gate blocks Medium+ findings.

Excluded from CodeQL analysis via .github/codeql/codeql-config.yml. This
file is imported by no production code and no test.
"""

import subprocess  # noqa: S404


def run_untrusted(cmd: str) -> str:
    # Intentional finding: shell=True with untrusted input.
    # Scanners must NOT flag this file — it is path-excluded.
    return subprocess.check_output(cmd, shell=True).decode()  # noqa: S602
