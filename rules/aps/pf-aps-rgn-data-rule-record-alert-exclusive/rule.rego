package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-aps-rgn-data-rule-record-alert-exclusive", "ERROR", name,
	"Properties.Data",
	"a rule item sets both record: and alert:; CreateRuleGroupsNamespace fails with \"only one of 'record' and 'alert' must be set\"",
	"Split the recording rule and the alerting rule into two rule items",
	"https://docs.aws.amazon.com/prometheus/latest/userguide/AMP-Ruler-Config.html") if {
	some name in resources_of_type("AWS::APS::RuleGroupsNamespace")
	lines := _pf_aps_yaml_lines(_pf_aps_str(name, "Properties.Data"))
	some l in lines
	l.dash
	keys := _pf_aps_keys(_pf_aps_yaml_item(lines, l))
	"record" in keys
	"alert" in keys
}
