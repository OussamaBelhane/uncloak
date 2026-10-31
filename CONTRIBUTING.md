# Contributing to Uncloak

Thank you for your interest in contributing to **Uncloak**.

Uncloak is engineered as a high-performance, production-grade cybersecurity tool. We maintain uncompromising code quality, zero amateur hacks, and strict architectural discipline.

---

### Core Engineering Guidelines

1. **The `src/` Layout:** All production code lives exclusively under `src/uncloak/`.
2. **Strict Typing:** All new functions and methods must have complete Python type annotations validated by `mypy --strict`.
3. **Decoupled Architecture:** Subsystems (Capture, Attribution, Analysis, Storage, UI) must communicate only through typed dataclass models in `core/models.py`.
4. **Performance Constraints:**
   - Memory footprint: `< 10 MB` RAM under normal operation.
   - CPU utilization: `< 2%` on average host workloads.
   - Zero blocking synchronous operations inside live packet capture loops.
5. **Testing Requirements:**
   - Every bug fix or feature must include corresponding unit tests in `tests/unit/`.
   - Windows-specific API calls (`iphlpapi.dll`) must be accompanied by mock fallbacks in `platform_compat.py` to allow the test suite to pass on Linux CI runners.

---

### Development Setup

```bash
# 1. Clone repository
git clone https://github.com/uncloak-project/uncloak.git
cd uncloak

# 2. Create virtual environment
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# 3. Install dependencies in editable mode with development tools
pip install -e ".[dev]"

# 4. Run tests
pytest

# 5. Run linting and type-checking
ruff check .
mypy src/
```

---

### Submitting a Pull Request

1. Create a focused feature branch (`git checkout -b feat/kernel-syn-cache`).
2. Ensure all tests pass (`pytest`) and code passes lint checks (`ruff check .`).
3. Write clear, imperative commit messages (`feat: add IQR jitter calculation to analysis engine`).
4. Submit your PR with a concise description of the problem solved and test evidence.
