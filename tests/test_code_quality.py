"""
Code Quality Tests

This test suite runs the same code quality checks that CI runs.
If these tests fail locally, CI will also fail. Fix issues before pushing.

These tests check:
- black: Code formatting
- isort: Import sorting
- flake8: Linting and style errors

Run just these tests with:
    pytest tests/test_code_quality.py -v

Run with auto-fix suggestion:
    pytest tests/test_code_quality.py -v --tb=short
"""

import subprocess
import sys
from pathlib import Path

import pytest

# Get project root
PROJECT_ROOT = Path(__file__).parent.parent


class TestBlackFormatting:
    """Test that all Python code is formatted with black."""

    @pytest.mark.parametrize("directory", ["src", "tests", "web"])
    def test_black_formatting(self, directory: str) -> None:
        """Check black formatting for a directory."""
        target = PROJECT_ROOT / directory
        if not target.exists():
            pytest.skip(f"Directory {directory} does not exist")

        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "black",
                "--check",
                "--quiet",
                str(target),
            ],
            capture_output=True,
            text=True,
        )

        if result.returncode != 0:
            # Get list of files that need formatting
            diff_result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "black",
                    "--check",
                    str(target),
                ],
                capture_output=True,
                text=True,
            )
            pytest.fail(
                f"Black formatting issues in {directory}/\n"
                f"Run: python -m black {directory}/\n\n"
                f"{diff_result.stderr}"
            )


class TestIsortImports:
    """Test that all imports are sorted correctly with isort."""

    @pytest.mark.parametrize("directory", ["src", "tests", "web"])
    def test_isort_imports(self, directory: str) -> None:
        """Check isort import ordering for a directory."""
        target = PROJECT_ROOT / directory
        if not target.exists():
            pytest.skip(f"Directory {directory} does not exist")

        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "isort",
                "--check-only",
                "--skip-glob",
                "**/proto/*",
                str(target),
            ],
            capture_output=True,
            text=True,
        )

        if result.returncode != 0:
            # Get detailed diff
            diff_result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "isort",
                    "--check-only",
                    "--diff",
                    "--skip-glob",
                    "**/proto/*",
                    str(target),
                ],
                capture_output=True,
                text=True,
            )
            pytest.fail(
                f"isort import ordering issues in {directory}/\n"
                f"Run: python -m isort {directory}/ --skip-glob='**/proto/*'\n\n"
                f"{diff_result.stdout[:2000]}"  # Limit output
            )


# Flake8 ignore list matching CI configuration
FLAKE8_IGNORES = "E203,W503,F401,F841,F541,E501,E722,F403,F405,E128,E401,E402,F811"


class TestFlake8Linting:
    """Test that code passes flake8 linting."""

    @pytest.mark.parametrize("directory", ["src", "tests"])
    def test_flake8_linting(self, directory: str) -> None:
        """Check flake8 linting for a directory."""
        target = PROJECT_ROOT / directory
        if not target.exists():
            pytest.skip(f"Directory {directory} does not exist")

        # Build command with CI-matching parameters
        cmd = [
            sys.executable,
            "-m",
            "flake8",
            str(target),
            "--max-line-length=88",
            f"--extend-ignore={FLAKE8_IGNORES}",
        ]

        # Add exclude for proto files
        if directory == "src":
            cmd.append("--exclude=src/amoskys/proto")

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            cwd=str(PROJECT_ROOT),
        )

        if result.returncode != 0:
            # Limit output to first 50 errors
            errors = result.stdout.strip().split("\n")
            if len(errors) > 50:
                error_msg = (
                    "\n".join(errors[:50])
                    + f"\n\n... and {len(errors) - 50} more errors"
                )
            else:
                error_msg = result.stdout

            pytest.fail(
                f"Flake8 linting issues in {directory}/\n"
                f"Run: python -m flake8 {directory}/\n\n"
                f"{error_msg}"
            )


class TestCodeQualitySummary:
    """Summary test that runs all code quality checks."""

    def test_all_code_quality_checks(self) -> None:
        """
        Run all code quality checks and provide a summary.

        This test is useful for getting a quick overview of all issues.
        """
        issues = []

        # Check black
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "black",
                "--check",
                "--quiet",
                "src",
                "tests",
                "web",
            ],
            capture_output=True,
            cwd=str(PROJECT_ROOT),
        )
        if result.returncode != 0:
            issues.append("❌ Black formatting issues found")

        # Check isort
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "isort",
                "--check-only",
                "--skip-glob",
                "**/proto/*",
                "src",
                "tests",
                "web",
            ],
            capture_output=True,
            cwd=str(PROJECT_ROOT),
        )
        if result.returncode != 0:
            issues.append("❌ isort import ordering issues found")

        # Check flake8
        result = subprocess.run(
            [sys.executable, "-m", "flake8", "src", "web"],
            capture_output=True,
            cwd=str(PROJECT_ROOT),
        )
        if result.returncode != 0:
            issues.append("❌ Flake8 linting issues found")

        if issues:
            pytest.fail(
                "Code quality issues detected:\n\n" + "\n".join(issues) + "\n\n"
                "Fix these issues before pushing:\n"
                "  python -m black src/ tests/ web/\n"
                "  python -m isort src/ tests/ web/ --skip-glob='**/proto/*'\n"
                "  python -m flake8 src/ web/\n"
            )
