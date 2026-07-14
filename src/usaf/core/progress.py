from __future__ import annotations

from typing import TYPE_CHECKING

from rich.console import Console
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)

if TYPE_CHECKING:
    from rich.progress import TaskID

console = Console(stderr=True)


class ScanProgress:
    """Rich-based progress indicator for scan phases.

    Shows a progress bar for collector and check execution phases,
    and a spinner for post-processing phases.
    All output is on stderr so it doesn't interfere with report output.
    """

    def __init__(self) -> None:
        self.progress = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            TextColumn("•"),
            TimeElapsedColumn(),
            TimeRemainingColumn(),
            transient=True,
            console=console,
        )
        self.progress.start()
        self._collector_task: TaskID | None = None
        self._check_task: TaskID | None = None
        self._spinner_task: TaskID | None = None

    def _clear_spinner(self) -> None:
        if self._spinner_task is not None:
            self.progress.remove_task(self._spinner_task)
            self._spinner_task = None

    def start_collecting(self, total: int) -> None:
        self._clear_spinner()
        self._collector_task = self.progress.add_task(
            "Collecting data", total=total
        )

    def advance_collectors(self) -> None:
        if self._collector_task is not None:
            self.progress.advance(self._collector_task)

    def finish_collecting(self) -> None:
        if self._collector_task is not None:
            self.progress.update(self._collector_task, completed=True)
            self.progress.remove_task(self._collector_task)
            self._collector_task = None

    def start_checks(self, total: int) -> None:
        self._clear_spinner()
        self._check_task = self.progress.add_task(
            "Running checks", total=total
        )

    def advance_checks(self) -> None:
        if self._check_task is not None:
            self.progress.advance(self._check_task)

    def finish_checks(self) -> None:
        if self._check_task is not None:
            self.progress.update(self._check_task, completed=True)
            self.progress.remove_task(self._check_task)
            self._check_task = None

    def set_spinner(self, description: str) -> None:
        self._clear_spinner()
        self._spinner_task = self.progress.add_task(
            description, total=None
        )

    def stop(self) -> None:
        self._clear_spinner()
        self.finish_collecting()
        self.finish_checks()
        self.progress.stop()
