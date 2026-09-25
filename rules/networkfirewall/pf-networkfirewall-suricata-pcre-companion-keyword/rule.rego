package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-networkfirewall-suricata-pcre-companion-keyword", "ERROR", name,
	"Properties.RuleGroup.RulesSource.RulesString",
	sprintf("the rule '%s' uses pcre on its own; CreateRuleGroup answers \"reason: Using pcre without one of the following options is not allowed: [tls.sni, http.host, dns.query, http.uri, content].\"", [_pf_nfwlib_snip(l)]),
	"Add one of content, tls.sni, http.host, dns.query or http.uri to the rule",
	"https://docs.aws.amazon.com/network-firewall/latest/developerguide/suricata-limitations-caveats.html") if {
	some [name, _, l] in _pf_nfwlib_line
	names := _pf_nfwlib_option_names(l)
	"pcre" in names
	count(names & {"content", "tls.sni", "http.host", "dns.query", "http.uri"}) == 0
}
