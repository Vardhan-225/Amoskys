"""
Code Quality Tests - STRICT PRODUCTION CHECKS

This test suite runs the EXACT same code quality checks that CI runs.
If these tests fail locally, CI WILL fail. Fix all issues before pushing.

These tests mirror the CI pipeline quality-check job exactly:
- black: Code formatting (line length 88, black profile)
- isort: Import sorting (black profile, uses pyproject.toml config)
- flake8: Linting (uses .flake8 config file)

Run these tests before every push:
    pytest tests/test_code_quality.py -v

Quick fix all issues:
    python -m black src/ tests/ web/
    python -m isort src/ tests/ web/

Check what CI will see:
    make ci-quality-check
"""

import subprocess
import sys
from pathlib import Path

import pytest

# Get project root
PROJECT_ROOT = Path(__file__).parent.parent

# Directories to check (same as CI)
CHECK_DIRS = ["src", "tests", "web"]


def run_command(
    cmd: list[str], cwd: Path = PROJECT_ROOT
) -> subprocess.CompletedProcess:
    """Run a command and return the result."""
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        cwd=str(cwd),
    )


class TestBlackFormatting:
    """Test that all Python code is formatted with black."""

    @pytest.mark.parametrize("directory", CHECK_DIRS)
    def test_black_formatting(self, directory: str) -> None:
        """Check black formatting for a directory (mirrors CI exactly)."""
        target = PROJECT_ROOT / directory
        if not target.exists():
            pytest.skip(f"Directory {directory} does not exist")

        # Exact CI command: black --check src/ tests/ web/ --exclude="(proto|migrations|\.venv)"
        result = run_command(
            [
                sys.executable,
                "-m",
                "black",
                "--check",
                "--quiet",
                str(target),
                "--exclude=(proto|migrations|\\.venv)",
            ]
        )

        if result.returncode != 0:
            # Get detailed diff for fixing
            diff_result = run_command(
                [
                    sys.executable,
                    "-m",
                    "black",
                    "--check",
                    "--diff",
                    str(target),
                    "--exclude=(proto|migrations|\\.venv)",
                ]
            )
            pytest.fail(
                f"❌ Black formatting issues in {directory}/\n\n"
                f"FIX: python -m black {directory}/\n\n"
                f"Diff:\n{diff_result.stdout[:3000]}"
            )


class TestIsortImports:
    """Test that all imports are sorted correctly with isort."""

    @pytest.mark.parametrize("directory", CHECK_DIRS)
    def test_isort_imports(self, directory: str) -> None:
        """Check isort import ordering (mirrors CI exactly, uses pyproject.toml config)."""
        target = PROJECT_ROOT / directory
        if not target.exists():
            pytest.skip(f"Directory {directory} does not exist")

        # Exact CI command: isort --check-only --diff src/ tests/ web/
        # Config is read from pyproject.toml automatically
        result = run_command(
            [
                sys.executable,
                "-m",
                "isort",
                "--check-only",
                str(target),
            ]
        )

        if result.returncode != 0:
            # Get detailed diff
            diff_result = run_command(
                [
                    sys.executable,
                    "-m",
                    "isort",
                    "--check-only",
                    "--diff",
                    str(target),
                ]
            )
            pytest.fail(
                f"❌ isort import ordering issues in {directory}/\n\n"
                f"FIX: python -m isort {directory}/\n\n"
                f"Diff:\n{diff_result.stdout[:3000]}"
            )


class TestFlake8Linting:
    """Test that code passes flake8 linting."""

    @pytest.mark.parametrize("directory", CHECK_DIRS)
    def test_flake8_linting(self, directory: str) -> None:
        """Check flake8 linting (mirrors CI exactly, uses .flake8 config)."""
        target = PROJECT_ROOT / directory
        if not target.exists():
            pytest.skip(f"Directory {directory} does not exist")

        # Exact CI command: flake8 src/ tests/ web/
        # Config is read from .flake8 automatically
        result = run_command(
            [
                sys.executable,
                "-m",
                "flake8",
                str(target),
            ]
        )

        if result.returncode != 0:
            # Limit output to first 30 errors
            errors = result.stdout.strip().split("\n")
            if len(errors) > 30:
                error_msg = (
                    "\n".join(errors[:30])
                    + f"\n\n... and {len(errors) - 30} more errors"
                )
            else:
                error_msg = result.stdout

            pytest.fail(
                f"❌ Flake8 linting issues in {directory}/\n\n" f"Errors:\n{error_msg}"
            )


class TestFullCIQualityCheck:
    """
    Run the complete CI quality check pipeline locally.

    This test runs all checks in sequence exactly as CI does.
    If this test passes, the CI quality-check job WILL pass.
    """

    def test_ci_quality_check_black(self) -> None:
        """Full black check across all directories."""
        result = run_command(
            [
                sys.executable,
                "-m",
                "black",
                "--check",
                "--quiet",
                "src/",
                "tests/",
                "web/",
                "--exclude=(proto|migrations|\\.venv)",
            ]
        )
        if result.returncode != 0:
            pytest.fail(
                "❌ Black formatting check failed\n"
                "FIX: python -m black src/ tests/ web/"
            )

    def test_ci_quality_check_isort(self) -> None:
        """Full isort check across all directories."""
        result = run_command(
            [
                sys.executable,
                "-m",
                "isort",
                "--check-only",
                "src/",
                "tests/",
                "web/",
            ]
        )
        if result.returncode != 0:
            pytest.fail(
                "❌ isort import ordering check failed\n"
                "FIX: python -m isort src/ tests/ web/"
            )

    def test_ci_quality_check_flake8(self) -> None:
        """Full flake8 check across all directories."""
        result = run_command(
            [
                sys.executable,
                "-m",
                "flake8",
                "src/",
                "tests/",
                "web/",
            ]
        )
        if result.returncode != 0:
            errors = result.stdout.strip().split("\n")
            pytest.fail(
                f"❌ Flake8 linting check failed ({len(errors)} errors)\n"
                f"Run: python -m flake8 src/ tests/ web/"
            )


class TestToolVersions:
    """Verify that code quality tool versions match CI expectations."""

    def test_black_version(self) -> None:
        """Check that black version is pinned correctly."""
        result = run_command([sys.executable, "-m", "black", "--version"])
        version = result.stdout.strip()
        assert "24.10.0" in version, f"Expected black 24.10.0, got: {version}"

    def test_isort_version(self) -> None:
        """Check that isort version is pinned correctly."""
        result = run_command([sys.executable, "-m", "isort", "--version"])
        version = result.stdout.strip()
        assert "5.13.2" in version, f"Expected isort 5.13.2, got: {version}"

    def test_flake8_version(self) -> None:
        """Check that flake8 is available."""
        result = run_command([sys.executable, "-m", "flake8", "--version"])
        assert result.returncode == 0, "flake8 not installed correctly"
