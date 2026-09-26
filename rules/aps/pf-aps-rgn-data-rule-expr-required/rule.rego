package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-aps-rgn-data-rule-expr-required", "ERROR", name,
	"Properties.Data",
	sprintf("rule %v has no expr:; CreateRuleGroupsNamespace fails with \"field 'expr' must be set in rule\"", [v]),
	"Give every rule item a PromQL expr:",
	"https://docs.aws.amazon.com/prometheus/latest/userguide/AMP-Ruler-Config.html") if {
	some name in resources_of_type("AWS::APS::RuleGroupsNamespace")
	lines := _pf_aps_yaml_lines(_pf_aps_str(name, "Properties.Data"))
	some l in lines
	l.dash
	pairs := _pf_aps_yaml_item(lines, l)
	keys := _pf_aps_keys(pairs)
	some k in keys
	k in {"record", "alert"}
	not "expr" in keys
	some v in _pf_aps_values(pairs, k)
}
