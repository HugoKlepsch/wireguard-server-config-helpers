#!/usr/bin/env python3
"""Unit tests for wgctl's pure functions.

These never touch a WireGuard interface, /etc, or the network:

    python3 -m unittest discover -v
"""

import importlib.util
import ipaddress
import os
import tempfile
import textwrap
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))

# wgctl has no .py extension, so give importlib an explicit source loader.
_loader = importlib.machinery.SourceFileLoader(
    "wgctl", os.path.join(HERE, "wgctl")
)
_spec = importlib.util.spec_from_loader("wgctl", _loader)
wgctl = importlib.util.module_from_spec(_spec)
_loader.exec_module(wgctl)


CONFIG_TEMPLATE = """
[server]
interface = wg0
endpoint = vpn.example.com
listen_port = 51820
wan_interface = eth0
ipv4_subnet = 10.8.0.0/24
ipv4_address = 10.8.0.1
ipv6_subnet = 2600:3c03:e000:0315::/64
private_key_file = {tmp}/privatekey
config_file = {tmp}/wg0.conf
state_dir = {tmp}/state
mtu =
persistent_keepalive = 25
reserved_addresses = 10.8.0.200

[profile:full-vpndns]
description = Everything through the VPN.
allowed_ips = 0.0.0.0/0, ::/0
dns = 10.8.0.22

[profile:split-nodns]
allowed_ips = ${{server:ipv4_subnet}}, ${{server:ipv6_subnet}}
dns =

[defaults]
profiles = full-vpndns, split-nodns
"""


def read(path):
    with open(path) as handle:
        return handle.read()


def make_config(tmpdir, extra=""):
    path = os.path.join(tmpdir, "wgctl.conf")
    with open(path, "w") as handle:
        handle.write(CONFIG_TEMPLATE.format(tmp=tmpdir) + extra)
    return wgctl.Config(path)


class TestIPv6Mapping(unittest.TestCase):
    """The v4 octet is re-read as hex so the text matches."""

    def setUp(self):
        self.net = ipaddress.ip_network("2600:3c03:e000:0315::/64")

    def test_reads_the_same_as_the_v4_octet(self):
        cases = {
            "10.8.0.1": "2600:3c03:e000:315::1",
            "10.8.0.22": "2600:3c03:e000:315::22",
            "10.8.0.99": "2600:3c03:e000:315::99",
            "10.8.0.100": "2600:3c03:e000:315::100",
            "10.8.0.254": "2600:3c03:e000:315::254",
        }
        for v4, expected in cases.items():
            self.assertEqual(
                str(wgctl.ipv6_for_ipv4(v4, self.net)), expected, v4
            )

    def test_every_host_octet_is_unique(self):
        mapped = {
            str(wgctl.ipv6_for_ipv4("10.8.0.%d" % n, self.net))
            for n in range(1, 255)
        }
        self.assertEqual(len(mapped), 254)

    def test_all_results_are_inside_the_subnet(self):
        for n in range(1, 255):
            address = wgctl.ipv6_for_ipv4("10.8.0.%d" % n, self.net)
            self.assertIn(address, self.net)


class TestAllocation(unittest.TestCase):
    def setUp(self):
        self.net = ipaddress.ip_network("10.8.0.0/24")
        self.server = ipaddress.ip_address("10.8.0.1")

    def allocate(self, used=(), reserved=()):
        return str(wgctl.allocate_ipv4(self.net, self.server, used, reserved))

    def test_skips_the_server_address(self):
        self.assertEqual(self.allocate(), "10.8.0.2")

    def test_returns_lowest_free_address(self):
        self.assertEqual(self.allocate(used=["10.8.0.2", "10.8.0.3"]), "10.8.0.4")

    def test_fills_gaps(self):
        used = ["10.8.0.%d" % n for n in range(2, 10) if n != 5]
        self.assertEqual(self.allocate(used=used), "10.8.0.5")

    def test_honours_reserved(self):
        self.assertEqual(self.allocate(reserved=["10.8.0.2"]), "10.8.0.3")

    def test_raises_when_exhausted(self):
        used = ["10.8.0.%d" % n for n in range(2, 255)]
        with self.assertRaises(wgctl.Error):
            self.allocate(used=used)

    def test_never_returns_network_or_broadcast(self):
        for n in range(2, 255):
            used = ["10.8.0.%d" % i for i in range(2, n)]
            address = self.allocate(used=used)
            self.assertNotIn(address, ("10.8.0.0", "10.8.0.255"))


class TestProfileValidation(unittest.TestCase):
    def profile(self, allowed, dns):
        return {"p": wgctl.Profile("p", allowed, dns)}

    def test_dns_inside_full_tunnel_is_fine(self):
        self.assertEqual(
            wgctl.validate_profiles(
                self.profile(["0.0.0.0/0", "::/0"], ["1.1.1.1"])), []
        )

    def test_dns_inside_split_tunnel_is_fine(self):
        self.assertEqual(
            wgctl.validate_profiles(
                self.profile(["10.8.0.0/24"], ["10.8.0.22"])), []
        )

    def test_dns_outside_split_tunnel_is_rejected(self):
        problems = wgctl.validate_profiles(
            self.profile(["10.8.0.0/24"], ["1.1.1.1"]))
        self.assertEqual(len(problems), 1)
        self.assertIn("bypass the tunnel", problems[0])

    def test_no_dns_is_fine(self):
        self.assertEqual(
            wgctl.validate_profiles(self.profile(["10.8.0.0/24"], [])), []
        )

    def test_empty_allowed_ips_is_rejected(self):
        problems = wgctl.validate_profiles(self.profile([], ["1.1.1.1"]))
        self.assertIn("allowed_ips is empty", problems[0])

    def test_search_domains_are_rejected(self):
        problems = wgctl.validate_profiles(
            self.profile(["0.0.0.0/0"], ["example.com"]))
        self.assertIn("not an IP address", problems[0])

    def test_v6_dns_is_matched_against_v6_routes_only(self):
        # A v6 resolver with only a v4 route must not pass.
        problems = wgctl.validate_profiles(
            self.profile(["0.0.0.0/0"], ["2606:4700:4700::1111"]))
        self.assertEqual(len(problems), 1)
        problems = wgctl.validate_profiles(
            self.profile(["0.0.0.0/0", "::/0"], ["2606:4700:4700::1111"]))
        self.assertEqual(problems, [])


class TestConfigLoading(unittest.TestCase):
    def test_interpolation_expands_subnets(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = make_config(tmp)
            self.assertEqual(
                config.profiles["split-nodns"].allowed_ips,
                ["10.8.0.0/24", "2600:3c03:e000:0315::/64"],
            )

    def test_server_ipv6_is_derived(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = make_config(tmp)
            self.assertEqual(str(config.ipv6_address), "2600:3c03:e000:315::1")

    def test_reserved_addresses_are_parsed(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = make_config(tmp)
            self.assertIn(ipaddress.ip_address("10.8.0.200"), config.reserved)

    def test_server_address_outside_subnet_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "bad.conf")
            with open(path, "w") as handle:
                handle.write(
                    CONFIG_TEMPLATE.format(tmp=tmp).replace(
                        "ipv4_address = 10.8.0.1", "ipv4_address = 10.9.0.1")
                )
            with self.assertRaises(wgctl.Error):
                wgctl.Config(path)

    def test_missing_endpoint_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "bad.conf")
            with open(path, "w") as handle:
                handle.write(
                    CONFIG_TEMPLATE.format(tmp=tmp).replace(
                        "endpoint = vpn.example.com", "endpoint =")
                )
            with self.assertRaises(wgctl.Error):
                wgctl.Config(path)

    def test_ipv4_only_is_supported(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "v4.conf")
            with open(path, "w") as handle:
                handle.write(
                    CONFIG_TEMPLATE.format(tmp=tmp)
                    .replace("ipv6_subnet = 2600:3c03:e000:0315::/64",
                             "ipv6_subnet =")
                    .replace("allowed_ips = ${server:ipv4_subnet}, "
                             "${server:ipv6_subnet}",
                             "allowed_ips = ${server:ipv4_subnet}")
                )
            config = wgctl.Config(path)
            self.assertIsNone(config.ipv6_subnet)
            self.assertIsNone(config.ipv6_address)


class TestPathResolution(unittest.TestCase):
    """Relative config paths hang off the config file, not the cwd."""

    def write(self, tmp, replacements):
        body = CONFIG_TEMPLATE.format(tmp=tmp)
        for old, new in replacements:
            body = body.replace(old, new)
        path = os.path.join(tmp, "wgctl.conf")
        with open(path, "w") as handle:
            handle.write(body)
        return wgctl.Config(path)

    def test_relative_state_dir_is_beside_the_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = self.write(
                tmp, [("state_dir = %s/state" % tmp, "state_dir = state")])
            self.assertEqual(config.state_dir, os.path.join(tmp, "state"))
            self.assertEqual(config.registry_file,
                             os.path.join(tmp, "state", "peers.json"))
            self.assertEqual(config.secrets_dir,
                             os.path.join(tmp, "state", "secrets"))

    def test_absolute_paths_are_left_alone(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = self.write(tmp, [
                ("config_file = %s/wg0.conf" % tmp,
                 "config_file = /etc/wireguard/wg0.conf"),
            ])
            self.assertEqual(config.config_file, "/etc/wireguard/wg0.conf")

    def test_resolution_ignores_the_working_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = self.write(
                tmp, [("state_dir = %s/state" % tmp, "state_dir = state")])
            original = os.getcwd()
            try:
                os.chdir("/")
                self.assertEqual(config.state_dir, os.path.join(tmp, "state"))
            finally:
                os.chdir(original)

    def test_nested_relative_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = self.write(tmp, [
                ("private_key_file = %s/privatekey" % tmp,
                 "private_key_file = state/server-privatekey"),
            ])
            self.assertEqual(config.private_key_file,
                             os.path.join(tmp, "state", "server-privatekey"))


class TestRendering(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = self._tmp.name
        self.config = make_config(self.tmp)
        self.peer = wgctl.Peer("phone", {
            "public_key": "PUBKEY_PHONE",
            "ipv4": "10.8.0.5",
            "ipv6": "2600:3c03:e000:315::5",
            "profiles": ["full-vpndns"],
            "enabled": True,
            "has_psk": True,
        })

    def tearDown(self):
        self._tmp.cleanup()

    # ------------------------------------------------------------- server

    def server_config(self, peers, psk=None):
        return wgctl.render_server_config(
            self.config, peers, "SERVER_PRIVATE", (lambda n: psk) if psk else None
        )

    def test_server_config_is_dual_stack(self):
        text = self.server_config([self.peer])
        self.assertIn("Address = 10.8.0.1/24, 2600:3c03:e000:315::1/64", text)

    def test_server_config_has_no_saveconfig_or_postup(self):
        # Only actual directives matter; the header comment mentions them.
        directives = [
            line for line in self.server_config([self.peer]).splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        body = "\n".join(directives)
        self.assertNotIn("SaveConfig", body)
        self.assertNotIn("PostUp", body)
        self.assertNotIn("PostDown", body)
        self.assertNotIn("iptables", body)

    def test_server_config_names_peers_in_comments(self):
        text = self.server_config([self.peer])
        self.assertIn("# peer: phone", text)

    def test_server_peer_allowed_ips_are_host_routes(self):
        text = self.server_config([self.peer])
        self.assertIn(
            "AllowedIPs = 10.8.0.5/32, 2600:3c03:e000:315::5/128", text)

    def test_psk_included_only_when_peer_has_one(self):
        self.assertIn("PresharedKey = PSK",
                      self.server_config([self.peer], psk="PSK"))
        self.peer.has_psk = False
        self.assertNotIn("PresharedKey",
                         self.server_config([self.peer], psk="PSK"))

    def test_disabled_peers_are_the_callers_job_to_filter(self):
        # render_server_config writes what it is given; enabled_peers() filters.
        registry = wgctl.Registry.__new__(wgctl.Registry)
        registry.peers = {"phone": self.peer}
        self.peer.enabled = False
        self.assertEqual(registry.enabled_peers(), [])

    # ------------------------------------------------------------- client

    def client_config(self, profile_name, psk=None):
        return wgctl.render_client_config(
            self.config, self.peer, self.config.profile(profile_name),
            "CLIENT_PRIVATE", "SERVER_PUBLIC", psk,
        )

    def test_client_config_full_profile(self):
        text = self.client_config("full-vpndns")
        self.assertIn("Address = 10.8.0.5/32, 2600:3c03:e000:315::5/128", text)
        self.assertIn("PrivateKey = CLIENT_PRIVATE", text)
        self.assertIn("PublicKey = SERVER_PUBLIC", text)
        self.assertIn("DNS = 10.8.0.22", text)
        self.assertIn("AllowedIPs = 0.0.0.0/0, ::/0", text)
        self.assertIn("Endpoint = vpn.example.com:51820", text)
        self.assertIn("PersistentKeepalive = 25", text)

    def test_client_config_omits_dns_when_profile_has_none(self):
        self.assertNotIn("DNS =", self.client_config("split-nodns"))

    def test_client_config_split_profile_routes_both_families(self):
        text = self.client_config("split-nodns")
        self.assertIn(
            "AllowedIPs = 10.8.0.0/24, 2600:3c03:e000:0315::/64", text)

    def test_client_psk_is_optional(self):
        self.assertIn("PresharedKey = SECRET",
                      self.client_config("full-vpndns", psk="SECRET"))
        self.assertNotIn("PresharedKey", self.client_config("full-vpndns"))

    def test_unknown_profile_raises(self):
        with self.assertRaises(wgctl.Error):
            self.config.profile("nope")


class TestRedaction(unittest.TestCase):
    def test_keys_are_hidden_but_structure_kept(self):
        text = textwrap.dedent("""\
            [Interface]
            PrivateKey = SUPERSECRET
            ListenPort = 51820
            PresharedKey = ALSOSECRET
            PublicKey = NOTSECRET
            """)
        out = wgctl.redact(text)
        self.assertNotIn("SUPERSECRET", out)
        self.assertNotIn("ALSOSECRET", out)
        self.assertIn("PublicKey = NOTSECRET", out)
        self.assertIn("ListenPort = 51820", out)
        self.assertEqual(out.count("<redacted>"), 2)


class TestLegacyImportParsing(unittest.TestCase):
    def make_peer_dir(self, tmp, name, files):
        directory = os.path.join(tmp, name)
        os.makedirs(directory)
        for filename, content in files.items():
            with open(os.path.join(directory, filename), "w") as handle:
                handle.write(content)
        return directory

    def test_reads_address_from_server_conf(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = self.make_peer_dir(tmp, "drake", {
                "public": "PUB\n",
                "private": "PRIV\n",
                "server.conf": "[Peer]\nPublicKey = PUB\n"
                               "AllowedIPs = 10.8.0.7/32\n",
            })
            parsed = wgctl._parse_legacy_peer(directory)
            self.assertEqual(parsed["public_key"], "PUB")
            self.assertEqual(parsed["private_key"], "PRIV")
            self.assertEqual(parsed["ipv4"], "10.8.0.7")

    def test_falls_back_to_client_conf_address(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = self.make_peer_dir(tmp, "drake", {
                "public": "PUB\n",
                "private": "PRIV\n",
                "drake.conf": "[Interface]\nAddress = 10.8.0.9/32\n",
            })
            self.assertEqual(
                wgctl._parse_legacy_peer(directory)["ipv4"], "10.8.0.9")

    def test_non_peer_directory_is_ignored(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = self.make_peer_dir(tmp, "notapeer", {"README": "hi"})
            self.assertIsNone(wgctl._parse_legacy_peer(directory))

    def test_missing_private_key_is_reported_not_fatal(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = self.make_peer_dir(tmp, "drake", {
                "public": "PUB\n",
                "server.conf": "AllowedIPs = 10.8.0.7/32\n",
            })
            parsed = wgctl._parse_legacy_peer(directory)
            self.assertIsNone(parsed["private_key"])


class TestRegistryRoundTrip(unittest.TestCase):
    def test_save_and_reload(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = make_config(tmp)
            registry = wgctl.Registry(config)
            registry.peers["phone"] = wgctl.Peer("phone", {
                "public_key": "PUB", "ipv4": "10.8.0.5",
                "ipv6": "2600:3c03:e000:315::5",
                "profiles": ["full-vpndns"], "enabled": True,
                "has_psk": True, "created": "2026-09-13T12:00:00",
            })
            registry.save()

            again = wgctl.Registry(config)
            self.assertEqual(list(again.peers), ["phone"])
            peer = again.peers["phone"]
            self.assertEqual(peer.ipv4, "10.8.0.5")
            self.assertTrue(peer.has_psk)
            self.assertEqual(peer.addresses,
                             ["10.8.0.5/32", "2600:3c03:e000:315::5/128"])

    def test_registry_file_is_not_secret(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = make_config(tmp)
            registry = wgctl.Registry(config)
            registry.peers["phone"] = wgctl.Peer("phone", {
                "public_key": "PUB", "ipv4": "10.8.0.5",
            })
            registry.save()
            text = read(config.registry_file)
            self.assertNotIn("PrivateKey", text)
            self.assertNotIn("private", text)

    def test_peers_sort_by_address_numerically(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = make_config(tmp)
            registry = wgctl.Registry(config)
            for name, address in (("c", "10.8.0.100"), ("a", "10.8.0.9"),
                                  ("b", "10.8.0.20")):
                registry.peers[name] = wgctl.Peer(
                    name, {"public_key": name, "ipv4": address})
            self.assertEqual(
                [p.name for p in registry.sorted_peers()], ["a", "b", "c"])


class TestNameValidation(unittest.TestCase):
    def test_accepts_reasonable_names(self):
        for name in ("drake", "hugo-iphone", "debian13mac", "a.b_c-1"):
            self.assertEqual(wgctl.check_name(name), name)

    def test_rejects_path_traversal_and_junk(self):
        for name in ("../evil", "a/b", "", ".hidden", "-lead", "a b", "a$b"):
            with self.assertRaises(wgctl.Error):
                wgctl.check_name(name)


class TestAtomicWrite(unittest.TestCase):
    def test_writes_content_and_mode(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "secret")
            wgctl.write_atomic(path, "hello\n", 0o600)
            self.assertEqual(read(path), "hello\n")
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)

    def test_leaves_no_temp_files_behind(self):
        with tempfile.TemporaryDirectory() as tmp:
            wgctl.write_atomic(os.path.join(tmp, "f"), "x", 0o644)
            self.assertEqual(os.listdir(tmp), ["f"])

    def test_overwrites_in_place(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "f")
            wgctl.write_atomic(path, "one\n")
            wgctl.write_atomic(path, "two\n")
            self.assertEqual(read(path), "two\n")


class TestHandshakeFormatting(unittest.TestCase):
    def test_never(self):
        self.assertEqual(wgctl.handshake_age(0), "never")

    def test_recent_and_old(self):
        import datetime as dt
        now = int(dt.datetime.now().timestamp())
        self.assertTrue(wgctl.handshake_age(now - 30).endswith("s ago"))
        self.assertTrue(wgctl.handshake_age(now - 300).endswith("m ago"))
        self.assertTrue(wgctl.handshake_age(now - 7200).endswith("h ago"))
        self.assertTrue(wgctl.handshake_age(now - 200000).endswith("d ago"))


if __name__ == "__main__":
    unittest.main()
