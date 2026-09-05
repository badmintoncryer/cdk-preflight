package cdk_preflight

import rego.v1

_pf_wafrb_url := "https://docs.aws.amazon.com/waf/latest/APIReference/API_RateBasedStatement.html"

_pf_wafrb_fix := "Match AggregateKeyType with its companion property (CUSTOM_KEYS -> CustomKeys with at least one non-IP key, FORWARDED_IP or a ForwardedIP key -> ForwardedIPConfig, CONSTANT -> ScopeDownStatement), use each singleton key once, end LabelNamespace with a colon, and keep to 10 rate-based rules per web ACL / 4 per rule group"

_pf_wafrb contains [name, i, pp, b] if {
	some [name, i, p, kind, b] in _pf_waflib_leaves
	kind == "RateBasedStatement"
	pp := _pf_waflib_path(i, array.concat(p, ["RateBasedStatement"]))
}

_pf_wafrb_has(b, k) if object.get(b, k, "__pf_absent") != "__pf_absent"

_pf_wafrb_keys(b) := ks if {
	ks := b.CustomKeys
	is_array(ks)
}

_pf_wafrb_nkeys(b) := count(_pf_wafrb_keys(b))

_pf_wafrb_nkeys(b) := 0 if not _pf_wafrb_keys(b)

violation contains make_diag_full("pf-wafv2-rate-based-statement", "ERROR", name, pp,
	"AggregateKeyType CUSTOM_KEYS needs at least one entry in CustomKeys (the create call fails with \"You are missing at-least one of condition between some parameters or all parameters of object.\")",
	_pf_wafrb_fix, _pf_wafrb_url) if {
	some [name, i, pp, b] in _pf_wafrb
	b.AggregateKeyType == "CUSTOM_KEYS"
	_pf_wafrb_nkeys(b) == 0
}

violation contains make_diag_full("pf-wafv2-rate-based-statement", "ERROR", name, pp,
	"AggregateKeyType FORWARDED_IP requires ForwardedIPConfig (the create call fails with \"A required field is missing from the parameter.\")",
	_pf_wafrb_fix, _pf_wafrb_url) if {
	some [name, i, pp, b] in _pf_wafrb
	b.AggregateKeyType == "FORWARDED_IP"
	not _pf_wafrb_has(b, "ForwardedIPConfig")
}

violation contains make_diag_full("pf-wafv2-rate-based-statement", "ERROR", name, pp,
	"AggregateKeyType CONSTANT requires a ScopeDownStatement (the create call fails with \"A required field is missing from the parameter.\")",
	_pf_wafrb_fix, _pf_wafrb_url) if {
	some [name, i, pp, b] in _pf_wafrb
	b.AggregateKeyType == "CONSTANT"
	not _pf_wafrb_has(b, "ScopeDownStatement")
}

violation contains make_diag_full("pf-wafv2-rate-based-statement", "ERROR", name, sprintf("%s.CustomKeys", [pp]),
	sprintf("CustomKeys is only valid with AggregateKeyType CUSTOM_KEYS, not %s (the create call fails with \"Your request in not valid.\")", [b.AggregateKeyType]),
	_pf_wafrb_fix, _pf_wafrb_url) if {
	some [name, i, pp, b] in _pf_wafrb
	b.AggregateKeyType in {"IP", "CONSTANT", "FORWARDED_IP"}
	_pf_wafrb_nkeys(b) > 0
}

violation contains make_diag_full("pf-wafv2-rate-based-statement", "ERROR", name, sprintf("%s.CustomKeys", [pp]),
	"CustomKeys only holds IP / ForwardedIP keys; combine them with another key, or use AggregateKeyType IP / FORWARDED_IP instead (the create call fails with \"IP or ForwardedIP can't be independent keys for CUSTOM_KEYS\")",
	_pf_wafrb_fix, _pf_wafrb_url) if {
	some [name, i, pp, b] in _pf_wafrb
	b.AggregateKeyType == "CUSTOM_KEYS"
	ks := _pf_wafrb_keys(b)
	count(ks) > 0
	count({k | some k; some kk in object.keys(ks[k]); not kk in {"IP", "ForwardedIP"}}) == 0
}

violation contains make_diag_full("pf-wafv2-rate-based-statement", "ERROR", name, sprintf("%s.CustomKeys[%d].ForwardedIP", [pp, k]),
	"a ForwardedIP key requires ForwardedIPConfig on the statement (the create call fails with \"A required field is missing from the parameter.\")",
	_pf_wafrb_fix, _pf_wafrb_url) if {
	some [name, i, pp, b] in _pf_wafrb
	ks := _pf_wafrb_keys(b)
	some k
	ks[k].ForwardedIP
	not _pf_wafrb_has(b, "ForwardedIPConfig")
}

_pf_wafrb_single := {"HTTPMethod", "UriPath", "QueryString", "JA3Fingerprint", "JA4Fingerprint", "IP", "ForwardedIP", "ASN"}

violation contains make_diag_full("pf-wafv2-rate-based-statement", "ERROR", name, sprintf("%s.CustomKeys[%d].%s", [pp, m, kk]),
	sprintf("%s key is already used by CustomKeys[%d]; this key type can be used once (the create call fails with \"You have duplicated some of the information in the parameter.\")", [kk, k]),
	_pf_wafrb_fix, _pf_wafrb_url) if {
	some [name, i, pp, b] in _pf_wafrb
	ks := _pf_wafrb_keys(b)
	some k, m
	k < m
	some kk in _pf_wafrb_single
	ks[k][kk]
	ks[m][kk]
}

violation contains make_diag_full("pf-wafv2-rate-based-statement", "ERROR", name, sprintf("%s.CustomKeys[%d].LabelNamespace.Namespace", [pp, k]),
	sprintf("'%s' must end with a colon (the create call fails with \"Member must satisfy regular expression pattern: ^[0-9A-Za-z_\\-:]+:$\")", [ns]),
	_pf_wafrb_fix, _pf_wafrb_url) if {
	some [name, i, pp, b] in _pf_wafrb
	ks := _pf_wafrb_keys(b)
	some k
	ns := ks[k].LabelNamespace.Namespace
	is_string(ns)
	not endswith(ns, ":")
}

_pf_wafrb_count(name) := count({i | some [nm, i, kind] in _pf_waflib_tops; nm == name; kind == "RateBasedStatement"})

violation contains make_diag_full("pf-wafv2-rate-based-statement", "ERROR", name, "Properties.Rules",
	sprintf("%d rate-based rules; a web ACL allows at most 10 (the create call fails with WAFLimitsExceededException NUM_RATEBASED_STATEMENT_IN_WEBACL)", [n]),
	_pf_wafrb_fix, _pf_wafrb_url) if {
	some name in resources_of_type("AWS::WAFv2::WebACL")
	n := _pf_wafrb_count(name)
	n > 10
}

violation contains make_diag_full("pf-wafv2-rate-based-statement", "ERROR", name, "Properties.Rules",
	sprintf("%d rate-based rules; a rule group allows at most 4 (the create call fails with WAFLimitsExceededException NUM_RATEBASED_STATEMENT_IN_RULE_GROUP)", [n]),
	_pf_wafrb_fix, _pf_wafrb_url) if {
	some name in resources_of_type("AWS::WAFv2::RuleGroup")
	n := _pf_wafrb_count(name)
	n > 4
}
