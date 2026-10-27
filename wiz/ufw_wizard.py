import shlex
from rules import ufw_build
from wiz import common


def preview(spec):
    cmd = ufw_build(spec)
    return "ufw --dry-run " + " ".join(shlex.quote(c) for c in cmd[1:])


def apply_rule(spec):
    cmd = ufw_build(spec)
    args = cmd[1:]
    return common.run_helper("ufw-apply", args)


def verify(rule_num):
    out = common.run_helper("ufw-status-numbered", [])
    return out == 0


def rollback(rule_num):
    if not rule_num:
        return 1
    return common.run_helper("ufw-rollback", [str(rule_num)])
