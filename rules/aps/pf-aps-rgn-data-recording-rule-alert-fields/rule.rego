package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-aps-rgn-data-recording-rule-alert-fields", "ERROR", name,
	"Properties.Data",
	sprintf("a recording rule sets %v:, which only an alerting rule may have; CreateRuleGroupsNamespace fails with \"invalid field '%v' in recording rule\"", [f, f]),
	"Drop for / keep_firing_for / annotations from the recording rule, or turn it into an alert:",
	"https://docs.aws.amazon.com/prometheus/latest/userguide/AMP-Ruler-Config.html") if {
	some name in resources_of_type("AWS::APS::RuleGroupsNamespace")
	lines := _pf_aps_yaml_lines(_pf_aps_str(name, "Properties.Data"))
	some l in lines
	l.dash
	keys := _pf_aps_keys(_pf_aps_yaml_item(lines, l))
	"record" in keys
	not "alert" in keys
	some f in keys
	f in {"for", "keep_firing_for", "annotations"}
}
