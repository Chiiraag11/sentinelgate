"""Common interface every scanner wrapper implements."""

from __future__ import annotations

import subprocess
from abc import ABC, abstractmethod

from sentinelgate.models import Finding


class ScannerError(RuntimeError):
    """Raised when a scanner binary is missing or exits with an unexpected error."""


class BaseScanner(ABC):
    name: str = "base"

    def __init__(self, target_dir: str):
        self.target_dir = target_dir

    @abstractmethod
    def run(self) -> list[Finding]:
        """Execute the scanner and return normalized Findings."""
        raise NotImplementedError

    def _run_subprocess(self, cmd: list[str], allow_nonzero: bool = True) -> str:
        """Run a scanner CLI and return stdout.

        allow_nonzero=True because most security scanners exit non-zero when
        they find something (that's the whole point) — a nonzero exit is not
        the same as a crash, so we only raise on a genuine execution failure.
        """
        try:
            proc = subprocess.run(
                cmd,
                cwd=self.target_dir,
                capture_output=True,
                text=True,
                timeout=300,
            )
        except FileNotFoundError as e:
            raise ScannerError(
                f"{self.name}: executable not found ({cmd[0]}). Is it installed?"
            ) from e
        except subprocess.TimeoutExpired as e:
            raise ScannerError(f"{self.name}: timed out after 300s") from e

        if not allow_nonzero and proc.returncode != 0:
            raise ScannerError(
                f"{self.name}: exited {proc.returncode}\nstderr: {proc.stderr[:2000]}"
            )
        return proc.stdout
