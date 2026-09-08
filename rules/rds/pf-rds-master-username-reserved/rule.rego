package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-rds-master-username-reserved", "ERROR", name,
	"Properties.MasterUsername",
	sprintf("MasterUsername %v is reserved by the engine (\"MasterUsername rdsadmin cannot be used as it is a reserved word used by the engine\")", [u]),
	"Pick another master user name",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-rds-dbinstance.html") if {
	some name in resources_of_type("AWS::RDS::DBInstance")
	u := resolve(name, "Properties.MasterUsername")
	is_string(u)
	lower(u) == "rdsadmin"
}
