import ast
import os
import subprocess
import sys
import textwrap
from pathlib import Path

import moiras
from moiras.supervisor import ShadowReport

PACKAGE_ROOT = Path(moiras.__file__).parent

FORBIDDEN_IMPORT_ROOTS = {
    "asyncio",
    "asyncssh",
    "ctypes",
    "ftplib",
    "http",
    "importlib",
    "multiprocessing",
    "os",
    "paramiko",
    "pty",
    "requests",
    "shutil",
    "signal",
    "socket",
    "subprocess",
    "urllib",
}

# Evidence uses only os.PathLike for destination typing/validation. Calls through
# os remain forbidden, so this exception does not permit os.system or process APIs.
ALLOWED_IMPORT_ROOTS = {"evidence.py": {"os"}}

FORBIDDEN_DIRECT_CALLS = {
    "__import__",
    "compile",
    "eval",
    "exec",
    "open",
}

FORBIDDEN_DOTTED_CALLS = {
    "builtins.__import__",
    "builtins.compile",
    "builtins.eval",
    "builtins.exec",
}

FORBIDDEN_ATTRIBUTE_REFERENCES = {
    "Popen",
    "create_subprocess_exec",
    "create_subprocess_shell",
    "eval",
    "exec",
    "execv",
    "execve",
    "execvp",
    "execvpe",
    "fork",
    "forkpty",
    "popen",
    "posix_spawn",
    "posix_spawnp",
    "spawnl",
    "spawnle",
    "spawnlp",
    "spawnlpe",
    "spawnv",
    "spawnve",
    "spawnvp",
    "spawnvpe",
    "system",
    "urlopen",
}

FILESYSTEM_IO_ATTRIBUTES = {
    "chmod",
    "hardlink_to",
    "lchmod",
    "link_to",
    "mkdir",
    "open",
    "read_bytes",
    "read_text",
    "rename",
    "replace",
    "rmdir",
    "symlink_to",
    "touch",
    "unlink",
    "write_bytes",
    "write_text",
}


def _dotted_name(node: ast.expr) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _dotted_name(node.value)
        if prefix is not None:
            return f"{prefix}.{node.attr}"
    return None


def _resolve_alias(name: str | None, aliases: dict[str, str]) -> str | None:
    if name is None:
        return None
    head, separator, tail = name.partition(".")
    resolved_head = aliases.get(head, head)
    return f"{resolved_head}.{tail}" if separator else resolved_head


def _constant_string(node: ast.expr) -> str | None:
    """Evaluate only literal strings joined by ``+``; never execute AST code."""

    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _constant_string(node.left)
        right = _constant_string(node.right)
        if left is not None and right is not None:
            return left + right
    return None


def _is_allowlisted_filesystem_call(filename: str, node: ast.Call) -> bool:
    dotted = _dotted_name(node.func)
    if filename == "evidence.py" and dotted == "self._destination.open":
        return bool(
            node.args
            and isinstance(node.args[0], ast.Constant)
            and node.args[0].value == "a"
        )

    if filename != "__main__.py" or not isinstance(node.func, ast.Attribute):
        return False
    if node.func.attr != "write_text" or not isinstance(node.func.value, ast.Call):
        return False
    path_call = node.func.value
    return bool(
        isinstance(path_call.func, ast.Name)
        and path_call.func.id == "Path"
        and len(path_call.args) == 1
        and isinstance(path_call.args[0], ast.Attribute)
        and isinstance(path_call.args[0].value, ast.Name)
        and path_call.args[0].value.id == "args"
        and path_call.args[0].attr == "json"
    )


def _scan_source(source: str, filename: str) -> list[tuple[int, str]]:
    tree = ast.parse(source, filename=filename)
    aliases: dict[str, str] = {}
    findings: set[tuple[int, str]] = set()
    allowed_roots = ALLOWED_IMPORT_ROOTS.get(filename, set())

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".", 1)[0]
                aliases[alias.asname or root] = alias.name
                if root in FORBIDDEN_IMPORT_ROOTS and root not in allowed_roots:
                    findings.add((node.lineno, f"forbidden import root: {root}"))
        elif isinstance(node, ast.ImportFrom) and node.module:
            root = node.module.split(".", 1)[0]
            for alias in node.names:
                aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"
            if root in FORBIDDEN_IMPORT_ROOTS and root not in allowed_roots:
                findings.add((node.lineno, f"forbidden import root: {root}"))

    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and node.attr in FORBIDDEN_ATTRIBUTE_REFERENCES:
            findings.add((node.lineno, f"forbidden attribute reference: {node.attr}"))
        if not isinstance(node, ast.Call):
            continue

        dotted = _resolve_alias(_dotted_name(node.func), aliases)
        leaf = node.func.attr if isinstance(node.func, ast.Attribute) else None
        reflected_attribute = (
            _constant_string(node.args[1])
            if isinstance(node.func, ast.Name)
            and node.func.id == "getattr"
            and len(node.args) >= 2
            else None
        )
        if isinstance(node.func, ast.Name) and node.func.id in FORBIDDEN_DIRECT_CALLS:
            findings.add((node.lineno, f"forbidden direct call: {node.func.id}"))
        if dotted in FORBIDDEN_DOTTED_CALLS:
            findings.add((node.lineno, f"forbidden dotted call: {dotted}"))
        if (
            reflected_attribute is not None
            and reflected_attribute
            in (FORBIDDEN_ATTRIBUTE_REFERENCES | FORBIDDEN_DIRECT_CALLS)
        ):
            findings.add(
                (node.lineno, f"forbidden reflected attribute: {reflected_attribute}")
            )
        if dotted is not None and dotted.split(".", 1)[0] in FORBIDDEN_IMPORT_ROOTS:
            findings.add((node.lineno, f"call through forbidden root: {dotted}"))
        if leaf in FILESYSTEM_IO_ATTRIBUTES and not _is_allowlisted_filesystem_call(
            filename, node
        ):
            findings.add((node.lineno, f"non-allowlisted filesystem call: {leaf}"))

    return sorted(findings)


def test_package_has_no_unapproved_execution_network_or_filesystem_surface():
    findings = {}
    for source_path in PACKAGE_ROOT.glob("*.py"):
        source_findings = _scan_source(
            source_path.read_text(encoding="utf-8"), source_path.name
        )
        if source_findings:
            findings[source_path.name] = source_findings
    assert findings == {}


def test_static_guard_rejects_representative_mutants():
    mutants = {
        "os_process.py": "import os\nos.system('true')\n",
        "aliased_process.py": "import os as operating\noperating.system('true')\n",
        "dynamic_import.py": "__import__('subprocess').run(['true'])\n",
        "importlib_process.py": (
            "import importlib\nimportlib.import_module('subprocess').run(['true'])\n"
        ),
        "reflection.py": "getattr(__import__('os'), 'system')('true')\n",
        "concatenated_dynamic_import.py": (
            "getattr(__builtins__, '__im' + 'port__')('subprocess')\n"
        ),
        "concatenated_os_system.py": "import os\ngetattr(os, 'sys' + 'tem')('true')\n",
        "concatenated_eval.py": "getattr(__builtins__, 'ev' + 'al')('1 + 1')\n",
        "builtins_eval.py": "import builtins\nbuiltins.eval('1 + 1')\n",
        "filesystem_write.py": (
            "from pathlib import Path\nPath('unexpected').write_text('data')\n"
        ),
    }
    for filename, source in mutants.items():
        assert _scan_source(source, filename), filename


def test_pure_runtime_path_emits_no_execution_network_or_write_audit_event():
    script = textwrap.dedent(
        """
        import os
        import sys

        from moiras.broker import SyntheticCapabilityBroker
        from moiras.harness import SCENARIOS, run_gate
        from moiras.supervisor import supervise

        forbidden_exact = {
            "compile",
            "ctypes.dlopen",
            "exec",
            "os.fork",
            "os.forkpty",
            "os.kill",
            "os.killpg",
            "os.posix_spawn",
            "os.system",
            "subprocess.Popen",
        }
        forbidden_prefixes = (
            "os.exec",
            "os.spawn",
            "shutil.",
            "socket.",
        )
        write_flags = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND

        def deny_forbidden_event(event, args):
            if event in forbidden_exact or event.startswith(forbidden_prefixes):
                raise RuntimeError(f"forbidden audit event: {event}")
            if event == "open":
                mode = args[1] if len(args) > 1 else None
                flags = args[2] if len(args) > 2 else 0
                write_mode = isinstance(mode, str) and any(mark in mode for mark in "wax+")
                write_flag = isinstance(flags, int) and bool(flags & write_flags)
                if write_mode or write_flag:
                    raise RuntimeError("forbidden write audit event")

        sys.addaudithook(deny_forbidden_event)

        gate = run_gate()
        assert gate.success and gate.total == len(SCENARIOS)
        scenario = SCENARIOS[0]
        report = supervise(
            scenario.action,
            scenario.opinions,
            snapshots=scenario.snapshots,
            idle_threshold_s=scenario.idle_threshold_s,
        )
        broker = SyntheticCapabilityBroker(clock=lambda: 1.0, id_factory=lambda: "capability-1")
        capability = broker.mint(report.council_decision, ttl_s=1.0)
        broker.consume(capability.capability_id)
        print("AUDIT_OK")
        """
    )
    environment = os.environ.copy()
    repository_root = str(PACKAGE_ROOT.parent)
    existing_pythonpath = environment.get("PYTHONPATH")
    environment["PYTHONPATH"] = (
        repository_root
        if not existing_pythonpath
        else repository_root + os.pathsep + existing_pythonpath
    )
    completed = subprocess.run(
        [sys.executable, "-c", script],
        cwd=repository_root,
        env=environment,
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == "AUDIT_OK"


def test_shadow_report_has_no_execution_method():
    public_names = {name for name in dir(ShadowReport) if not name.startswith("_")}
    assert public_names.isdisjoint(
        {"execute", "authorize", "cancel", "retry", "approve", "provide_credential"}
    )
