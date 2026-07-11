from usaf.reporting.json import JSONReporter
from usaf.reporting.markdown import MarkdownReporter
from usaf.reporting.terminal import TerminalReporter

REPORTERS: dict[str, type[TerminalReporter | JSONReporter | MarkdownReporter]] = {
    "terminal": TerminalReporter,
    "json": JSONReporter,
    "markdown": MarkdownReporter,
}

__all__ = ["REPORTERS", "JSONReporter", "MarkdownReporter", "TerminalReporter"]
