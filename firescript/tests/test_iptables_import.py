from firescript.iptables_import import import_iptables


def rules_of(result):
    """The FireScript rule lines (without the header comment)."""
    return [l.split("  #")[0] for l in result.text.splitlines() if not l.startswith("#")]


def test_basic_accept():
    r = import_iptables("-A INPUT -p tcp -m tcp --dport 80 -j ACCEPT")
    assert rules_of(r) == ["allow tcp from any to any port 80"]
    assert r.converted == 1 and r.complete


def test_drop_with_source_subnet():
    r = import_iptables("-A INPUT -s 10.0.0.0/24 -p tcp --dport 22 -j DROP")
    assert rules_of(r) == ["deny tcp from 10.0.0.0/24 to any port 22"]


def test_reject_becomes_deny():
    assert rules_of(import_iptables("-A INPUT -p udp --dport 53 -j REJECT")) == \
        ["deny udp from any to any port 53"]


def test_port_range_uses_dash():
    r = import_iptables("-A INPUT -p tcp --dport 8000:9000 -j ACCEPT")
    assert rules_of(r) == ["allow tcp from any to any port 8000-9000"]


def test_multiport_expands_to_several_rules():
    r = import_iptables("-A INPUT -p tcp -m multiport --dports 80,443,8000:8100 -j ACCEPT")
    assert rules_of(r) == ["allow tcp from any to any port 80",
                           "allow tcp from any to any port 443",
                           "allow tcp from any to any port 8000-8100"]
    assert r.converted == 1


def test_protocol_all_and_numbers():
    assert rules_of(import_iptables("-A INPUT -p all -j DROP")) == \
        ["deny any from any to any port any"]
    assert rules_of(import_iptables("-A INPUT -p 6 --dport 22 -j ACCEPT")) == \
        ["allow tcp from any to any port 22"]


def test_netmask_and_host_addresses():
    r = import_iptables("-A INPUT -s 10.0.0.0/255.255.255.0 -d 192.168.1.5 -p icmp -j ACCEPT")
    assert rules_of(r) == ["allow icmp from 10.0.0.0/24 to 192.168.1.5/32 port any"]


def test_zero_prefix_means_any():
    r = import_iptables("-A INPUT -s 0.0.0.0/0 -p tcp --dport 22 -j DROP")
    assert rules_of(r) == ["deny tcp from any to any port 22"]


def test_other_chains_are_ignored():
    r = import_iptables("-A FORWARD -p tcp --dport 80 -j ACCEPT\n-A INPUT -p tcp --dport 22 -j DROP")
    assert rules_of(r) == ["deny tcp from any to any port 22"]
    assert import_iptables("-A FORWARD -p tcp --dport 80 -j ACCEPT", chain="FORWARD").converted == 1


def test_conntrack_rule_is_skipped_with_warning():
    r = import_iptables("-A INPUT -m conntrack --ctstate ESTABLISHED -j ACCEPT")
    assert r.skipped == 1 and rules_of(r) == [] and not r.complete
    assert any("conntrack" in w for w in r.warnings)


def test_interface_rule_is_skipped():
    r = import_iptables("-A INPUT -i lo -j ACCEPT")
    assert r.skipped == 1 and any("-i" in w for w in r.warnings)


def test_negation_is_skipped():
    r = import_iptables("-A INPUT ! -s 10.0.0.0/24 -p tcp --dport 22 -j DROP")
    assert r.skipped == 1 and any("negation" in w for w in r.warnings)


def test_jump_to_custom_chain_is_skipped():
    r = import_iptables("-A INPUT -j LOGGING")
    assert r.skipped == 1 and any("LOGGING" in w for w in r.warnings)


def test_ports_without_tcp_udp_are_skipped():
    assert import_iptables("-A INPUT --dport 80 -j ACCEPT").skipped == 1


def test_ipv6_and_hostnames_are_skipped():
    assert import_iptables("-A INPUT -s 2001:db8::/32 -j DROP").skipped == 1
    assert import_iptables("-A INPUT -s example.com -j DROP").skipped == 1


def test_comment_module_is_ignored():
    r = import_iptables('-A INPUT -p tcp -m tcp --dport 22 -m comment --comment "allow ssh" -j ACCEPT')
    assert rules_of(r) == ["allow tcp from any to any port 22"]


def test_policy_accept_adds_catch_all_rule():
    r = import_iptables("-P INPUT ACCEPT\n-A INPUT -p tcp --dport 22 -j DROP")
    assert r.policy == "ACCEPT"
    assert rules_of(r)[-1] == "allow any from any to any port any"


def test_policy_drop_adds_nothing():
    r = import_iptables("-P INPUT DROP\n-A INPUT -p tcp --dport 22 -j ACCEPT")
    assert r.policy == "DROP" and len(rules_of(r)) == 1


def test_iptables_save_format():
    text = "*filter\n:INPUT DROP [0:0]\n-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT\nCOMMIT\n"
    r = import_iptables(text)
    assert r.policy == "DROP" and rules_of(r) == ["allow tcp from any to any port 22"]


def test_missing_chain_gives_warning():
    r = import_iptables("-A FORWARD -p tcp --dport 80 -j ACCEPT")
    assert any("No rules found" in w for w in r.warnings)


def test_sample_file_counts():
    text = open("sample_iptables.txt").read()
    r = import_iptables(text)
    assert (r.converted, r.skipped) == (6, 3)
    assert len(rules_of(r)) == 7


def test_pipeline_output_parses_with_firescript():
    """Needs the real Lark parser: the imported text must be valid FireScript."""
    from firescript.parser import parse_rules
    r = import_iptables(open("sample_iptables.txt").read())
    parsed = parse_rules(r.text)
    assert parsed.ok and len(parsed.rules) == 7
