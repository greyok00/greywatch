"""appfw cgroupv2 scope identity (plan Task 4, design §6.1 stage [1]).

The packet layer's question becomes "which APP owns this packet".
cgroup_scope() parses /proc/<pid>/cgroup (v2 unified hierarchy) into a
safe identity; five shapes must all classify without crashing the chain.
"""
from __future__ import annotations

import appfw.scope as scope


def test_systemd_scope_parses(monkeypatch):
    monkeypatch.setattr(scope, "_read_cgroup", lambda pid:
                        "0::/app.slice/app-gnome-firefox@4123.scope")
    assert scope.cgroup_scope(1234) == \
        "/app.slice/app-gnome-firefox@4123.scope"
    ident = scope.identity(scope.cgroup_scope(1234), pid=1234)
    assert ident.scoped is True
    assert ident.level == 2
    assert ident.basename == "app-gnome-firefox@4123.scope"


def test_kernel_thread_shape_is_unscoped(monkeypatch):
    monkeypatch.setattr(scope, "_read_cgroup", lambda pid: "0::/")
    ident = scope.identity(scope.cgroup_scope(1), pid=1)
    assert ident.scoped is False
    assert ident.level == 0
    assert ident.basename == ""


def test_missing_proc_is_safe(monkeypatch):
    def raise_oserror(pid):
        raise OSError(2, "no such process")
    monkeypatch.setattr(scope, "_read_cgroup", raise_oserror)
    ident = scope.identity(scope.cgroup_scope(999999), pid=999999)
    assert ident.scoped is False
    assert ident.basename == ""


def test_flatpak_shape_parses_deeper(monkeypatch):
    monkeypatch.setattr(scope, "_read_cgroup", lambda pid:
                        "0::/user.slice/user-1000.slice/user@1000.service"
                        "/app.slice/app-flatpak-org.mozilla.Firefox@8811.scope")
    ident = scope.identity(scope.cgroup_scope(77), pid=77)
    assert ident.scoped is True
    assert ident.level == 5
    assert ident.basename == "app-flatpak-org.mozilla.Firefox@8811.scope"


def test_v1_hybrid_host_logs_and_is_unscoped(monkeypatch, capsys):
    monkeypatch.setattr(scope, "_read_cgroup", lambda pid:
                        "10:blkio:/system.slice/docker.service\n"
                        "9:net_cls:/\n")
    ident = scope.identity(scope.cgroup_scope(42), pid=42)
    assert ident.scoped is False          # no unified 0:: line: refuse to guess
    assert "v1" in capsys.readouterr().out.lower()


def test_unidentified_programs_share_one_class():
    ident = scope.identity("", pid=None)
    assert ident.scoped is False
    assert ident.class_token == "<unknown>"
