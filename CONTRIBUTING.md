# Contributing to Uncloak

Thank you for contributing to **Uncloak**.
Uncloak is engineered as a production-grade Windows C2 beacon detection and socket attribution platform. All contributors must follow strict architectural boundaries, security hygiene, and test verification before opening a Pull Request.

### Core Engineering Rules

1. **Frozen Data Contract (`FlowFeaturesV1`):** Subsystems (Capture, Attribution, Detection, Storage, Manager, UI) communicate through typed dataclass contracts in `src/uncloak/core/models.py` and `data/feature_schema_v1.json`. Do not modify `core/models.py` unless explicitly assigned.
2. **Scope Isolation:** Only modify files listed in your assigned GitHub Issue. Never touch unrelated UI (`src/uncloak/ui/`), CLI (`src/uncloak/cli/`), agent (`src/uncloak/agent/`), or mitigation (`src/uncloak/mitigation/`) modules outside your task scope.
3. **Zero Unsafe Serialization:** Never commit or load `.pkl`, `pickle`, or `joblib` model files. Trained model weights must be exported as safe JSON (`coef`, `intercept`, metadata) or ONNX.
4. **Zero `shell=True` & Hardcoded Secrets:** Never invoke `subprocess.run(..., shell=True)`, and never commit API tokens, passwords, private keys, or personal machine paths.
5. **Test Verification:** Every Pull Request must include unit tests in `tests/` and keep the full test suite green (`python tests/run_tests.py`).

### Development Setup

```powershell
# 1. Clone repository
git clone https://github.com/OussamaBelhane/uncloak.git
cd uncloak

# 2. Create virtual environment
python -m venv .venv
.venv\Scripts\Activate.ps1

# 3. Install package in editable mode with dev tools
pip install -e ".[dev]"

# 4. Run full test suite
python tests/run_tests.py
```

### Submitting a Pull Request

1. Create a focused feature branch from `main` (`git checkout -b feat/your-task-name`).
2. Implement only the scope defined in your assigned GitHub Issue.
3. Run `python tests/run_tests.py` and confirm `0 FAILED`.
4. Open a Pull Request targeting `main` and complete the PR checklist.
