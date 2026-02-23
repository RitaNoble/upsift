from upsift.engine import list_checks

def test_plugins_discoverable():
    checks = list_checks()
    ids = {c.id for c in checks}
    # Ensure our seed plugins are registered
    for expected in {"suid_binaries","path_write","sudo_nopasswd","docker_group","cron_writable","systemd_writable","ssh_weak_config"}:
        assert expected in ids
