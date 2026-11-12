"""What the distribution declares: dependencies, the lock, commands and import boundaries."""

import ast
import subprocess
import sys
import tomllib
from importlib import import_module
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
PACKAGE = ROOT / "src" / "agent_guard_cartography"
PROJECT = tomllib.loads((ROOT / "pyproject.toml").read_text())
# Import name -> distribution name, for every third-party module the package imports.
DISTRIBUTIONS = {
    "botocore": "botocore",
    "cartography": "cartography",
    "jsonschema": "jsonschema",
    "neo4j": "neo4j",
    "referencing": "referencing",
}


def requirement_name(requirement):
    for index, character in enumerate(requirement):
        if character in "<>=!~ ;[":
            return requirement[:index]
    return requirement


def imported_modules(path):
    for node in ast.walk(ast.parse(path.read_text())):
        if isinstance(node, ast.Import):
            yield from (alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            yield node.module.split(".")[0]


def test_every_directly_imported_distribution_is_a_declared_dependency():
    imported = {name for path in PACKAGE.glob("*.py") for name in imported_modules(path)}
    third_party = imported - set(sys.stdlib_module_names) - {"agent_guard_cartography"}
    assert third_party == set(DISTRIBUTIONS)
    declared = {requirement_name(item) for item in PROJECT["project"]["dependencies"]}
    assert declared == set(DISTRIBUTIONS.values())


def test_test_only_imports_are_declared_in_the_dev_group():
    imported = {
        name for path in (ROOT / "tests" / "unit").glob("*.py") for name in imported_modules(path)
    }
    assert "yaml" in imported
    assert "pyyaml" in {requirement_name(item) for item in PROJECT["dependency-groups"]["dev"]}


def test_lock_records_the_same_requirements_as_the_project():
    if not (ROOT / "uv.lock").is_file():
        pytest.skip("uv.lock is not part of this checkout")
    lock = tomllib.loads((ROOT / "uv.lock").read_text())
    packages = {package["name"]: package for package in lock["package"]}
    root = packages["agent-guard-cartography"]

    def specified(entries):
        return sorted(f"{entry['name']}{entry['specifier']}" for entry in entries)

    assert specified(root["metadata"]["requires-dist"]) == sorted(
        PROJECT["project"]["dependencies"]
    )
    assert specified(root["metadata"]["requires-dev"]["dev"]) == sorted(
        PROJECT["dependency-groups"]["dev"]
    )
    for listed, declared in (
        (root["dependencies"], root["metadata"]["requires-dist"]),
        (root["dev-dependencies"]["dev"], root["metadata"]["requires-dev"]["dev"]),
    ):
        names = [entry["name"] for entry in listed]
        # uv writes each list sorted by name; a hand edit must keep that.
        assert names == sorted(names) == sorted(entry["name"] for entry in declared)
        assert all(name in packages for name in names)


def test_every_command_is_a_console_script_and_still_runs_as_a_module():
    scripts = PROJECT["project"]["scripts"]
    assert scripts == {
        "agent-guard-cartography": "agent_guard_cartography.cli:main",
        "agent-guard-source-lifecycle": "agent_guard_cartography.lifecycle:main",
        "agent-guard-recovery": "agent_guard_cartography.pilot_recovery:main",
        "agent-guard-map-report": "agent_guard_cartography.reference_report:main",
    }
    for name, target in scripts.items():
        module, function = target.split(":")
        assert callable(getattr(import_module(module), function))
        shown = subprocess.run(
            [sys.executable, "-m", module, "--help"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert shown.returncode == 0 and not shown.stderr
        # The usage line names the installed command, not "python -m ...".
        assert shown.stdout.startswith(f"usage: {name} ")


@pytest.mark.parametrize("module", ["lifecycle", "pilot_recovery", "transitions", "archive"])
def test_importing_an_operator_module_does_not_load_the_collector_command(module):
    loaded = subprocess.run(
        [
            sys.executable,
            "-c",
            f"import sys, agent_guard_cartography.{module}; "
            "print('agent_guard_cartography.cli' in sys.modules)",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert loaded.returncode == 0, loaded.stderr
    assert loaded.stdout.strip() == "False"


def test_the_wheel_bundles_no_data_file_the_package_never_reads():
    assert not (PACKAGE / "data").exists()
    assert "aws-permission-relationships" not in (ROOT / "hatch_build.py").read_text()
