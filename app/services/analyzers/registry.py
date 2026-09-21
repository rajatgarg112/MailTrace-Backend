from typing import Dict, List, Optional
from app.services.analyzers.base import BaseAnalyzer


class AnalyzerRegistry:
    """Registry container for dynamically managing backend analyzer implementations."""

    def __init__(self):
        self._analyzers: Dict[str, BaseAnalyzer] = {}

    def register(self, analyzer: BaseAnalyzer) -> None:
        """Register an analyzer instance. Overwrites existing analyzer with same name."""
        if not isinstance(analyzer, BaseAnalyzer):
            raise TypeError("Analyzer must be an instance of BaseAnalyzer")
        self._analyzers[analyzer.name] = analyzer

    def unregister(self, name: str) -> Optional[BaseAnalyzer]:
        """Unregister and return an analyzer by name."""
        return self._analyzers.pop(name, None)

    def get(self, name: str) -> Optional[BaseAnalyzer]:
        """Retrieve a registered analyzer by name."""
        return self._analyzers.get(name)

    def list_analyzers(self) -> List[BaseAnalyzer]:
        """List all currently registered analyzers."""
        return list(self._analyzers.values())

    def get_by_category(self, category: str) -> List[BaseAnalyzer]:
        """Filter registered analyzers by category name."""
        category_lower = category.strip().lower()
        return [
            analyzer for analyzer in self._analyzers.values()
            if analyzer.category.lower() == category_lower
        ]

    def clear(self) -> None:
        """Clear all registered analyzers."""
        self._analyzers.clear()


# Default singleton instance for application orchestrator
default_registry = AnalyzerRegistry()
