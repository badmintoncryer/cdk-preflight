package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-aps-rgn-data-group-unknown-field", "ERROR", name,
	"Properties.Data",
	sprintf("rule group key %v is not one of name/interval/query_offset/limit/rules/labels; CreateRuleGroupsNamespace fails with \"field %v not found in type rulefmt.RuleGroup\"", [l.key, l.key]),
	"Remove or fix the misspelled rule group key",
	"https://docs.aws.amazon.com/prometheus/latest/userguide/AMP-Ruler-Config.html") if {
	some name in resources_of_type("AWS::APS::RuleGroupsNamespace")
	lines := _pf_aps_yaml_lines(_pf_aps_str(name, "Properties.Data"))
	groupIndents := {g.indent | some g in lines; g.key == "rules"}
	some l in lines
	l.indent in groupIndents
	not l.key in {"name", "interval", "query_offset", "limit", "rules", "labels"}
}
