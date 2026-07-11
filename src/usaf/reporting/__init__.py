from usaf.reporting.terminal import TerminalReporter
from usaf.reporting.json import JSONReporter
from usaf.reporting.markdown import MarkdownReporter

REPORTERS: dict[str, type[TerminalReporter | JSONReporter | MarkdownReporter]] = {
    "terminal": TerminalReporter,
    "json": JSONReporter,
    "markdown": MarkdownReporter,
}

__all__ = ["REPORTERS", "TerminalReporter", "JSONReporter", "MarkdownReporter"]
