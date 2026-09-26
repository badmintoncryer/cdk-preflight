package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-aps-rgn-data-group-name-unique", "ERROR", name,
	"Properties.Data",
	sprintf("the rules file declares group %v twice; CreateRuleGroupsNamespace fails with \"groupname: %v is repeated in the same file\"", [names[i], names[i]]),
	"Give each rule group in one namespace a distinct name",
	"https://docs.aws.amazon.com/prometheus/latest/userguide/AMP-Ruler-Config.html") if {
	some name in resources_of_type("AWS::APS::RuleGroupsNamespace")
	lines := _pf_aps_yaml_lines(_pf_aps_str(name, "Properties.Data"))
	names := [l.value | some l in lines; l.dash; l.key == "name"; l.value != ""]
	some i, j
	i < j
	names[i] == names[j]
}
