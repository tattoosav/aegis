# Aegis — AI Security Defense System

## Project Overview
Aegis is an autonomous AI security defense system for Windows PCs.
See `docs/plans/2026-02-14-aegis-design.md` for full design.

## Commands
- `pytest` — run all tests
- `pytest tests/test_core/` — run core tests only
- `python -m aegis` — launch Aegis
- `ruff check src/` — lint

## Architecture
- Microservice: independent sensor processes communicate via ZeroMQ PUB/SUB
- Central Event Engine coordinates all data flow
- SQLite (WAL mode) for persistence
- PySide6 desktop app with system tray

## Code Conventions
- Python 3.11+, type hints on all public functions
- All modules have docstrings
- Tests use pytest, follow TDD (test first)
- Imports: stdlib, third-party, local (enforced by ruff isort)
- Max line length: 100 chars
