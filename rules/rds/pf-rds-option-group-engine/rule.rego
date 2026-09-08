package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-rds-option-group-engine", "ERROR", name,
	"Properties.OptionGroupName",
	sprintf("Option group %v is for %v, but the instance runs %v (\"The option group default:postgres-16 is for postgres 16, and your DB instance is mysql 8.4.\")", [og, en, e]),
	"Match the option group engine to the instance engine",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-rds-optiongroup.html") if {
	some name in resources_of_type("AWS::RDS::DBInstance")
	og := resolve(name, "Properties.OptionGroupName")
	is_string(og)
	input.resources[og].resourceType == "AWS::RDS::OptionGroup"
	en := resolve(og, "Properties.EngineName")
	is_string(en)
	e := _pf_rds_engine(name)
	_pf_rds_famof(en) != _pf_rds_famof(e)
}
