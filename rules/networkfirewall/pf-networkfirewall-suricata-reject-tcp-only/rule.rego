package cdk_preflight

import rego.v1

# Protocol words measured to answer "<protocol> reject is not supported"
# (CreateRuleGroup DryRun, us-east-1, 2026-09-25). The service really keeps an
# allow-list - tcp, http, tls, smb, ssh, smtp and dcerpc are the only words it
# takes, and even an invented protocol gets this message - but a deny-list only
# loses findings if AWS adds a protocol, where an allow-list would start
# refusing valid templates.
_pf_nfwrej_unsupported := {
	"dhcp", "dns", "dnp3", "enip", "ftp", "ftp-data", "http2", "icmp",
	"ike", "ikev2", "imap", "ip", "krb5", "ldap", "modbus", "mqtt",
	"msn", "nfs", "ntp", "pgsql", "pop3", "quic", "rdp", "rfb",
	"s7comm", "sip", "smb2", "snmp", "ssl", "telnet", "tftp", "udp",
	"websocket",
}

violation contains make_diag_full("pf-networkfirewall-suricata-reject-tcp-only", "ERROR", name,
	"Properties.RuleGroup.RulesSource.RulesString",
	sprintf("the rule '%s' rejects %s traffic; reject answers with a TCP reset, so CreateRuleGroup says \"reason: %s reject is not supported\" (it takes tcp, http, tls, smb, ssh, smtp and dcerpc)", [_pf_nfwlib_snip(l), p, p]),
	"Use drop for this protocol, or point the reject rule at tcp",
	"https://docs.aws.amazon.com/network-firewall/latest/developerguide/rule-action.html") if {
	some [name, _, l] in _pf_nfwlib_line
	_pf_nfwlib_rule_action(l) == "reject"
	p := _pf_nfwlib_rule_protocol(l)
	p in _pf_nfwrej_unsupported
}

violation contains make_diag_full("pf-networkfirewall-suricata-reject-tcp-only", "ERROR", name,
	sprintf("Properties.RuleGroup.RulesSource.StatefulRules[%d].Action", [i]),
	sprintf("this rule rejects %s traffic; reject answers with a TCP reset, so CreateRuleGroup says \"reason: %s reject is not supported\" (it takes TCP, HTTP, TLS, SMB, SSH, SMTP and DCERPC)", [p, p]),
	"Use DROP for this protocol, or set Header.Protocol to TCP",
	"https://docs.aws.amazon.com/network-firewall/latest/developerguide/rule-action.html") if {
	some [name, i, r] in _pf_nfwlib_stateful_rule
	object.get(r, "Action", null) == "REJECT"
	raw := object.get(r, ["Header", "Protocol"], null)
	is_string(raw)
	p := lower(raw)
	p in _pf_nfwrej_unsupported
}
