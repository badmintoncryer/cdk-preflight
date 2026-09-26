package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-aps-rgn-name-ascii-alnum", "ERROR", name,
	"Properties.Name",
	sprintf("Name %v has no ASCII letter or digit; CreateRuleGroupsNamespace fails with \"Invalid name: Member must satisfy regular expression pattern: .*[0-9A-Za-z][-.0-9A-Z_a-z]*.*\"", [n]),
	"Put at least one ASCII letter or digit in the namespace name",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-aps-rulegroupsnamespace.html") if {
	some name in resources_of_type("AWS::APS::RuleGroupsNamespace")
	n := _pf_aps_str(name, "Properties.Name")
	not regex.match(`[0-9A-Za-z]`, n)
}
