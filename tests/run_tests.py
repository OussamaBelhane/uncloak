"""
Standalone Zero-Dependency Test Runner for Uncloak.
Discovers and executes all test functions in tests/unit/ and reports results.
"""

from __future__ import annotations

import importlib
import inspect
import os
import sys
import time
import traceback


def run_all_tests() -> int:
    """Discovers and runs test_* functions in tests/unit/."""
    tests_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.abspath(os.path.join(tests_dir, ".."))
    src_dir = os.path.join(project_root, "src")
    if project_root not in sys.path:
        sys.path.insert(0, project_root)
    if src_dir not in sys.path:
        sys.path.insert(0, src_dir)

    unit_dir = os.path.join(tests_dir, "unit")

    test_files = sorted([
        f for f in os.listdir(unit_dir)
        if f.startswith("test_") and f.endswith(".py")
    ])

    total_tests = 0
    passed_tests = 0
    failed_tests = 0
    errors: list[tuple[str, str]] = []

    print("=" * 70)
    print(f"[*] Running Uncloak Test Suite across {len(test_files)} test modules...")
    print("=" * 70)

    start_time = time.time()

    for test_file in test_files:
        mod_name = f"tests.unit.{test_file[:-3]}"
        try:
            mod = importlib.import_module(mod_name)
        except Exception as exc:
            print(f"[FAIL] Error importing {mod_name}: {exc}")
            failed_tests += 1
            errors.append((mod_name, traceback.format_exc()))
            continue

        test_funcs = [
            (name, func) for name, func in inspect.getmembers(mod, inspect.isfunction)
            if name.startswith("test_")
        ]

        for func_name, func in test_funcs:
            # Check if function requires pytest fixtures (parameters without defaults)
            sig = inspect.signature(func)
            req_params = [
                p for p in sig.parameters.values()
                if p.default == inspect.Parameter.empty
            ]
            if req_params:
                # Skip legacy pytest fixture functions if running standalone runner
                continue

            total_tests += 1
            test_desc = f"{test_file}::{func_name}"
            try:
                func()
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

    elapsed = time.time() - start_time
    print("=" * 70)
    print(f"[*] Test Summary: {passed_tests} PASSED, {failed_tests} FAILED in {elapsed:.3f}s (Total: {total_tests})")
    print("=" * 70)

    if errors:
        print("\n--- Detailed Error Traces ---")
        for desc, trace in errors:
            print(f"\n[FAILING TEST]: {desc}")
            print(trace)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(run_all_tests())
