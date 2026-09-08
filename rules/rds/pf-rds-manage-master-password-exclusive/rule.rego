package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-rds-manage-master-password-exclusive", "ERROR", name,
	"Properties.ManageMasterUserPassword",
	"ManageMasterUserPassword is set together with MasterUserPassword (\"MasterUserPassword and ManageMasterUserPassword are mutually exclusive. Specify only one of these parameters.\")",
	"Keep only one of the two",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-rds-dbinstance.html") if {
	some name in resources_of_type("AWS::RDS::DBInstance")
	_pf_rds_true(name, "ManageMasterUserPassword")
	_pf_rds_has(name, "MasterUserPassword")
}
