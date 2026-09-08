package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-rds-iam-auth-engine", "ERROR", name,
	"Properties.EnableIAMDatabaseAuthentication",
	sprintf("IAM database authentication is not supported by engine %v (\"IAM Database Authentication is not supported for this configuration.\")", [e]),
	"Drop EnableIAMDatabaseAuthentication for this engine",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-rds-dbinstance.html") if {
	some name in resources_of_type("AWS::RDS::DBInstance")
	_pf_rds_true(name, "EnableIAMDatabaseAuthentication")
	e := _pf_rds_engine(name)
	_pf_rds_engine_in(name, {"oracle-", "sqlserver-", "db2-"})
}
