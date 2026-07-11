from __future__ import annotations

import tempfile

from usaf.profiles.manager import Profile, ProfileManager, ProfileMatch


class TestProfile:
    def test_create_profile(self):
        p = Profile(
            name="test-profile",
            description="A test profile",
            distro="ubuntu",
            version="24.04",
            expected_packages=["openssh-server", "sudo"],
            expected_services=["ssh"],
            expected_suid=["/usr/bin/sudo"],
        )
        assert p.name == "test-profile"
        assert "sudo" in p.expected_packages

    def test_profile_defaults(self):
        p = Profile(name="minimal")
        assert p.expected_packages == []
        assert p.expected_services == []
        assert p.expected_suid == []


class TestProfileManager:
    def test_builtin_profiles_loaded(self):
        mgr = ProfileManager()
        assert "ubuntu-desktop-24-04" in mgr.all_profiles
        assert "ubuntu-server-24-04" in mgr.all_profiles

    def test_get_profile(self):
        mgr = ProfileManager()
        profile = mgr.get_profile("ubuntu-server-24-04")
        assert profile.distro == "ubuntu"
        assert "ssh" in profile.expected_services

    def test_get_nonexistent_raises(self):
        mgr = ProfileManager()
        try:
            mgr.get_profile("nonexistent")
            assert False, "Should have raised KeyError"
        except KeyError:
            pass

    def test_match_exact_server(self):
        mgr = ProfileManager()
        data = {
            "apt": {
                "ubuntu-server": {"version": "1.0"},
                "openssh-server": {"version": "1.0"},
                "systemd": {"version": "1.0"},
            },
            "systemd": {
                "services": {
                    "ssh": {"state": "running"},
                    "systemd-logind": {"state": "running"},
                    "systemd-journald": {"state": "running"},
                    "dbus": {"state": "running"},
                    "systemd-networkd": {"state": "running"},
                    "systemd-resolved": {"state": "running"},
                    "systemd-timesyncd": {"state": "running"},
                },
            },
            "suid": {
                "files": [
                    {"path": "/usr/bin/sudo", "owner": "root"},
                ],
            },
        }
        match = mgr.match(data, profile_name="ubuntu-server-24-04")
        assert match.is_match
        assert match.score > 0.5

    def test_match_missing_elements(self):
        mgr = ProfileManager()
        data = {
            "apt": {},
            "systemd": {"services": {}},
            "suid": {"files": []},
        }
        match = mgr.match(data, profile_name="ubuntu-server-24-04")
        # Should still return a match even with low score
        assert isinstance(match, ProfileMatch)

    def test_auto_detect_ubuntu_desktop(self):
        mgr = ProfileManager()
        data = {
            "apt": {
                "ubuntu-desktop": {"version": "1.0"},
                "firefox": {"version": "1.0"},
                "gnome-shell": {"version": "1.0"},
                "gdm3": {"version": "1.0"},
                "network-manager": {"version": "1.0"},
            },
        }
        match = mgr.match(data)
        assert match.is_match
        assert "desktop" in match.profile.tags

    def test_deviations_description(self):
        mgr = ProfileManager()
        data = {
            "apt": {},
            "systemd": {"services": {}},
            "suid": {"files": [
                {"path": "/usr/bin/unknown_backdoor", "owner": "root"},
            ]},
        }
        match = mgr.match(data, profile_name="ubuntu-server-24-04")
        devs = match.deviations
        assert len(devs) > 0

    def test_profile_round_trip(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            profile_path = f"{tmpdir}/custom.yaml"
            import yaml
            profile_data = {
                "name": "custom-web-server",
                "description": "A custom web server profile",
                "distro": "ubuntu",
                "expected_packages": ["nginx", "php", "mysql-server"],
                "expected_services": ["nginx", "mysql"],
                "expected_suid": ["/usr/bin/sudo"],
            }
            with open(profile_path, "w") as f:
                yaml.dump(profile_data, f)

            mgr = ProfileManager()
            profile = mgr.load_from_file(profile_path)
            assert profile.name == "custom-web-server"
            assert "nginx" in profile.expected_packages


class TestBuiltinProfiles:
    def test_server_has_expected_suid(self):
        mgr = ProfileManager()
        profile = mgr.get_profile("ubuntu-server-24-04")
        expected = ["/usr/bin/sudo", "/usr/bin/ping", "/usr/bin/passwd"]
        for e in expected:
            assert e in profile.expected_suid, f"Missing: {e}"

    def test_desktop_has_expected_services(self):
        mgr = ProfileManager()
        profile = mgr.get_profile("ubuntu-desktop-24-04")
        expected = ["gdm3", "NetworkManager"]
        for e in expected:
            assert e in profile.expected_services, f"Missing: {e}"

    def test_profiles_have_unique_names(self):
        mgr = ProfileManager()
        names = list(mgr.all_profiles.keys())
        assert len(names) == len(set(names))

    def test_all_profiles_have_distro(self):
        mgr = ProfileManager()
        for name, profile in mgr.all_profiles.items():
            assert profile.distro == "ubuntu", f"Profile {name} missing distro"
