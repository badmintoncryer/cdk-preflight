package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-aps-rgn-data-groups-key", "ERROR", name,
	"Properties.Data",
	sprintf("the rules file declares top-level key %v; CreateRuleGroupsNamespace fails with \"field %v not found in type rulefmt.RuleGroups\"", [l.key, l.key]),
	"Nest every rule group under a single top-level groups: key",
	"https://docs.aws.amazon.com/prometheus/latest/userguide/AMP-Ruler-Config.html") if {
	some name in resources_of_type("AWS::APS::RuleGroupsNamespace")
	lines := _pf_aps_yaml_lines(_pf_aps_str(name, "Properties.Data"))
	some l in lines
	l.indent == 0
	l.key != "groups"
}
