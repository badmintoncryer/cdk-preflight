package cdk_preflight

import rego.v1

_pf_cfgsri_err := "the rule create fails: a resource id is meaningless without the one type it belongs to"

violation contains make_diag_full("pf-config-rule-scope-resource-id-requires-single-type", "ERROR", name,
	"Properties.Scope.ComplianceResourceTypes",
	sprintf("Scope pins ComplianceResourceId with %d ComplianceResourceTypes; %s", [count(types), _pf_cfgsri_err]),
	"List exactly one resource type in Scope.ComplianceResourceTypes",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-config-configrule-scope.html") if {
	some name in resources_of_type("AWS::Config::ConfigRule")
	sc := _pf_cfglib_scope(name)
	_pf_cfglib_present(sc, "ComplianceResourceId")
	types := _pf_cfglib_list(sc, "ComplianceResourceTypes")
	count(types) != 1
}
