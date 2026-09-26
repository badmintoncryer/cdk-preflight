package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-aps-rgn-data-group-name-required", "ERROR", name,
	"Properties.Data",
	"a rule group has an empty name:; CreateRuleGroupsNamespace fails with \"Groupname must not be empty\"",
	"Give every rule group a non-empty name",
	"https://docs.aws.amazon.com/prometheus/latest/userguide/AMP-Ruler-Config.html") if {
	some name in resources_of_type("AWS::APS::RuleGroupsNamespace")
	lines := _pf_aps_yaml_lines(_pf_aps_str(name, "Properties.Data"))
	some l in lines
	l.dash
	l.key == "name"
	l.value == ""
}
