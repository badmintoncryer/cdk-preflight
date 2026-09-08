package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-rds-subnet-group-name-reserved", "ERROR", name,
	"Properties.DBSubnetGroupName",
	"DBSubnetGroupName \"default\" is reserved (\"Subnet group name default is reserved. Please specify another name.\")",
	"Pick another subnet group name",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-rds-dbsubnetgroup.html") if {
	some name in resources_of_type("AWS::RDS::DBSubnetGroup")
	n := resolve(name, "Properties.DBSubnetGroupName")
	is_string(n)
	lower(n) == "default"
}
