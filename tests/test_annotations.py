"""Verify every function in bsu_tool has complete type annotations and docstrings."""

import importlib
import inspect
import pkgutil
import types
import typing

import bsu_tool

"""Return every function defined in bsu_tool and its submodules."""
def _bsu_tool_functions() -> list[tuple[str, types.FunctionType]]:
    results: list[tuple[str, types.FunctionType]] = []
    for info in pkgutil.walk_packages(bsu_tool.__path__, prefix="bsu_tool."):
        module = importlib.import_module(info.name)
        for _, obj in inspect.getmembers(module, inspect.isfunction):
            if obj.__module__ == info.name:
                results.append((f"{obj.__module__}.{obj.__qualname__}", obj))
    return results

"""Every function in bsu_tool must annotate all parameters and return type."""
def test_all_functions_fully_annotated() -> None:
    missing: list[str] = []
    for qualname, func in _bsu_tool_functions():
        hints = typing.get_type_hints(func)
        file = inspect.getfile(func)
        line = inspect.getsourcelines(func)[1]
        location = f"{file}:{line}"
        if "return" not in hints:
            missing.append(
                f"  {location}\n    error: missing return annotation on '{qualname}'"
            )
        for param in inspect.signature(func).parameters:
            if param in ("self", "cls"):
                continue
            if param not in hints:
                missing.append(
                    f"  {location}\n    error: parameter '{param}' in '{qualname}' has no annotation"
                )
    assert not missing, "Annotation errors:\n" + "\n".join(missing)


"""Every public function in bsu_tool must have a docstring."""
def test_all_functions_have_docstrings() -> None:
    missing: list[str] = []
    for qualname, func in _bsu_tool_functions():
        if func.__name__.startswith("_"):
            continue  # private functions are exempt
        if not inspect.getdoc(func):
            file = inspect.getfile(func)
            line = inspect.getsourcelines(func)[1]
            missing.append(f"  {file}:{line}\n    error: '{qualname}' has no docstring")
    assert not missing, "Docstring errors:\n" + "\n".join(missing)
