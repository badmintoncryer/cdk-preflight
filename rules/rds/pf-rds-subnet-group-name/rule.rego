package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-rds-subnet-group-name", "ERROR", name,
	"Properties.DBSubnetGroupName",
	sprintf("DBSubnetGroupName '%s' is rejected with \"Invalid subnet group name\": RDS accepts only letters, numbers, spaces, dot, underscore and hyphen", [n]),
	"Rename the subnet group using [a-zA-Z0-9 ._-] only",
	"https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_CreateDBSubnetGroup.html") if {
	some name in resources_of_type("AWS::RDS::DBSubnetGroup")
	n := resolve(name, "Properties.DBSubnetGroupName")
	is_string(n)
	not regex.match(`^[a-zA-Z0-9 ._-]{1,255}$`, n)
}
