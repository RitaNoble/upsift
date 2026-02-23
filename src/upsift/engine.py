import importlib
import pkgutil
from typing import List, Optional, Type
from .checks.base import BaseCheck, Finding

def _discover_plugins() -> List[Type[BaseCheck]]:
    import upsift.plugins  # noqa
    plugins = []
    for _, name, _ in pkgutil.iter_modules(upsift.plugins.__path__, upsift.plugins.__name__ + "."):
        mod = importlib.import_module(name)
        # Find subclasses of BaseCheck
        for obj_name in dir(mod):
            obj = getattr(mod, obj_name)
            try:
                if issubclass(obj, BaseCheck) and obj is not BaseCheck:
                    plugins.append(obj)
            except TypeError:
                continue
    return plugins

def list_checks() -> List[BaseCheck]:
    return [cls() for cls in _discover_plugins()]

def run_checks(only: Optional[str] = None, skip: Optional[str] = None) -> List[Finding]:
    ids_only = set(only.split(",")) if only else None
    ids_skip = set(skip.split(",")) if skip else set()
    results: List[Finding] = []
    for cls in _discover_plugins():
        chk = cls()
        if ids_only and chk.id not in ids_only:
            continue
        if chk.id in ids_skip:
            continue
        try:
            findings = chk.run()
            if findings:
                results.extend(findings)
        except Exception as e:
            results.append(
                Finding(
                    id=chk.id,
                    title=f"Check error: {chk.name}",
                    severity="info",
                    description=str(e),
                    evidence=None,
                    remediation="Run with higher privileges or file a bug with stacktrace.",
                    references=[],
                )
            )
    return results
