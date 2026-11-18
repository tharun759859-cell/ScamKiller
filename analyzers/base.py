"""
SCAM KILLER — Base Analyzer Interface
All security layer analyzers inherit from BaseAnalyzer.
"""

from abc import ABC, abstractmethod
from typing import Dict, Any


class BaseAnalyzer(ABC):
    """Abstract contract for security analysis layers."""

    @abstractmethod
    def analyze(self, target: Any, **kwargs) -> Dict[str, Any]:
        """
        Executes analysis on target.
        Must return dict containing:
            - status: 'flagged' | 'caution' | 'passed' | 'skipped' | 'unavailable'
            - score: int (heuristic severity weight)
            - summary: str
            - indicators: list of strings
        """
        pass
