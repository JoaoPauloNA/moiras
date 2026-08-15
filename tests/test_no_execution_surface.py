import ast
from pathlib import Path

import moiras
from moiras.supervisor import ShadowReport

PACKAGE_ROOT = Path(moiras.__file__).parent

FORBIDDEN_IMPORT_ROOTS = {
    "asyncssh",
    "http",
    "paramiko",
    "requests",
    "socket",
    "subprocess",
    "urllib",
}


def test_runtime_has_no_process_network_or_remote_client_imports():
    findings = []
    for source_path in PACKAGE_ROOT.glob("*.py"):
        tree = ast.parse(source_path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                roots = {alias.name.split(".", 1)[0] for alias in node.names}
            elif isinstance(node, ast.ImportFrom) and node.module:
                roots = {node.module.split(".", 1)[0]}
            else:
                continue
            forbidden = roots.intersection(FORBIDDEN_IMPORT_ROOTS)
            if forbidden:
                findings.append((source_path.name, sorted(forbidden)))
    assert findings == []


def test_shadow_report_has_no_execution_method():
    public_names = {name for name in dir(ShadowReport) if not name.startswith("_")}
    assert public_names.isdisjoint(
        {"execute", "authorize", "cancel", "retry", "approve", "provide_credential"}
    )
