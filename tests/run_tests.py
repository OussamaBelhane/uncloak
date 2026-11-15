"""
Standalone Zero-Dependency Test Runner for Uncloak.
Discovers and executes test functions and unittest.TestCase suites across tests/ and reports results.
"""

from __future__ import annotations

import importlib
import inspect
import os
import pathlib
import sys
import tempfile
import time
import traceback
import unittest
from typing import Any, Callable


def run_all_tests() -> int:
    """Discovers and runs test_* functions and TestCase classes in tests/."""
    tests_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.abspath(os.path.join(tests_dir, ".."))
    src_dir = os.path.join(project_root, "src")
    if project_root not in sys.path:
        sys.path.insert(0, project_root)
    if src_dir not in sys.path:
        sys.path.insert(0, src_dir)

    filter_keyword = sys.argv[1].strip().lower() if len(sys.argv) > 1 and not sys.argv[1].startswith("-") else None

    # Discover registered fixtures in tests/conftest.py if present
    fixture_registry: dict[str, Callable[[], Any]] = {}
    try:
        conftest = importlib.import_module("tests.conftest")
        for name, obj in inspect.getmembers(conftest, inspect.isfunction):
            raw = getattr(obj, "__wrapped__", obj)
            fixture_registry[name] = raw
    except Exception:
        pass

    # Discover all test_*.py files recursively under tests/
    test_files: list[tuple[str, str]] = []
    for root, dirs, files in os.walk(tests_dir):
        dirs[:] = [d for d in dirs if not d.startswith(".") and d != "__pycache__"]
        for f in sorted(files):
            if f.startswith("test_") and f.endswith(".py"):
                rel_path = os.path.relpath(os.path.join(root, f), project_root)
                mod_path = os.path.splitext(rel_path)[0].replace(os.sep, ".")
                test_files.append((mod_path, rel_path))

    test_files.sort(key=lambda x: x[1])

    total_tests = 0
    passed_tests = 0
    failed_tests = 0
    errors: list[tuple[str, str]] = []

    print("=" * 70)
    scope_desc = f"matching '{filter_keyword}'" if filter_keyword else f"across {len(test_files)} test modules"
    print(f"[*] Running Uncloak Test Suite {scope_desc}...")
    print("=" * 70)

    start_time = time.time()

    for mod_name, rel_path in test_files:
        try:
            mod = importlib.import_module(mod_name)
        except Exception as exc:
            print(f"[FAIL] Error importing {mod_name}: {exc}")
            failed_tests += 1
            errors.append((mod_name, traceback.format_exc()))
            continue

        file_tests_count = 0

        # 1. Discover top-level test_* functions defined in this module
        test_funcs = [
            (name, func) for name, func in inspect.getmembers(mod, inspect.isfunction)
            if name.startswith("test_") and getattr(func, "__module__", "") == mod.__name__
        ]

        for func_name, func in test_funcs:
            test_desc = f"{os.path.basename(rel_path)}::{func_name}"
            if filter_keyword and filter_keyword not in test_desc.lower():
                continue

            file_tests_count += 1
            total_tests += 1

            sig = inspect.signature(func)
            kwargs: dict[str, Any] = {}
            missing_params: list[str] = []

            with tempfile.TemporaryDirectory() as td:
                tmp_p = pathlib.Path(td)
                for p in sig.parameters.values():
                    if p.name in ("tmp_path", "tmpdir"):
                        kwargs[p.name] = tmp_p
                    elif p.name in fixture_registry:
                        kwargs[p.name] = fixture_registry[p.name]()
                    elif p.default != inspect.Parameter.empty:
                        kwargs[p.name] = p.default
                    else:
                        missing_params.append(p.name)

                if missing_params:
                    failed_tests += 1
                    err_msg = f"Requires unsatisfied fixture parameter(s): {', '.join(missing_params)}"
                    print(f"[FAIL] {test_desc}: {err_msg}")
                    errors.append((test_desc, err_msg))
                    continue

                try:
                    func(**kwargs)
                    passed_tests += 1
                    print(f"[PASS] {test_desc}")
                except AssertionError as exc:
                    failed_tests += 1
                    print(f"[FAIL] {test_desc}: AssertionError ({exc})")
                    errors.append((test_desc, traceback.format_exc()))
                except Exception as exc:
                    failed_tests += 1
                    print(f"[ERROR] {test_desc}: {exc}")
                    errors.append((test_desc, traceback.format_exc()))

        # 2. Discover unittest.TestCase subclasses defined in this module
        test_classes = [
            (name, cls) for name, cls in inspect.getmembers(mod, inspect.isclass)
            if issubclass(cls, unittest.TestCase) and getattr(cls, "__module__", "") == mod.__name__
        ]

        for cls_name, cls in test_classes:
            case_method_names = [
                m for m in dir(cls)
                if m.startswith("test_") and callable(getattr(cls, m))
            ]
            for m in case_method_names:
                test_desc = f"{os.path.basename(rel_path)}::{cls_name}::{m}"
                if filter_keyword and filter_keyword not in test_desc.lower():
                    continue

                file_tests_count += 1
                total_tests += 1
                try:
                    case = cls(m)
                    result = unittest.TestResult()
                    case.run(result)
                    if result.wasSuccessful():
                        passed_tests += 1
                        print(f"[PASS] {test_desc}")
                    elif result.failures:
                        failed_tests += 1
                        fail_trace = result.failures[0][1]
                        print(f"[FAIL] {test_desc}: Failure in test case")
                        errors.append((test_desc, fail_trace))
                    elif result.errors:
                        failed_tests += 1
                        err_trace = result.errors[0][1]
                        print(f"[ERROR] {test_desc}: Error in test case")
                        errors.append((test_desc, err_trace))
                except Exception as exc:
                    failed_tests += 1
                    print(f"[ERROR] {test_desc}: {exc}")
                    errors.append((test_desc, traceback.format_exc()))

        if not filter_keyword and file_tests_count == 0:
            print(f"[WARN] {os.path.basename(rel_path)}: 0 tests discovered in module.")

    elapsed = time.time() - start_time
    print("=" * 70)
    print(f"[*] Test Summary: {passed_tests} PASSED, {failed_tests} FAILED in {elapsed:.3f}s (Total: {total_tests})")
    print("=" * 70)

    if errors:
        print("\n=== Detailed Error Traces ===")
        for desc, trace in errors:
            print(f"\n[FAILING TEST]: {desc}")
            print(trace)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(run_all_tests())
