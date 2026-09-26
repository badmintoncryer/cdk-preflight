package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-aps-rgn-data-rule-record-or-alert-required", "ERROR", name,
	"Properties.Data",
	"a rule item sets neither record: nor alert:; CreateRuleGroupsNamespace fails with \"one of 'record' or 'alert' must be set\"",
	"Name the rule with record: (recording rule) or alert: (alerting rule)",
	"https://docs.aws.amazon.com/prometheus/latest/userguide/AMP-Ruler-Config.html") if {
	some name in resources_of_type("AWS::APS::RuleGroupsNamespace")
	lines := _pf_aps_yaml_lines(_pf_aps_str(name, "Properties.Data"))
	some l in lines
	l.dash
	keys := _pf_aps_keys(_pf_aps_yaml_item(lines, l))
	some k in keys
	k in {"expr", "for", "keep_firing_for", "annotations"}
	not "record" in keys
	not "alert" in keys
}
