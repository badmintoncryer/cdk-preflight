package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-rds-parameter-group-family-engine", "ERROR", name,
	"Properties.DBParameterGroupName",
	sprintf("Parameter group %v has DBParameterGroupFamily %v, but the instance runs %v (\"The parameter group cdkpf-p-pg16 with DBParameterGroupFamily postgres16 can't be used for this instance. Use a parameter group with DBParameterGroupFamily mysql8.4.\")", [pg, fam, e]),
	"Match the parameter group family to the engine",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-rds-dbparametergroup.html") if {
	some name in resources_of_type("AWS::RDS::DBInstance")
	pg := resolve(name, "Properties.DBParameterGroupName")
	is_string(pg)
	input.resources[pg].resourceType == "AWS::RDS::DBParameterGroup"
	f0 := resolve(pg, "Properties.Family")
	is_string(f0)
	fam := lower(f0)
	e := _pf_rds_engine(name)
	not startswith(fam, e)
}
