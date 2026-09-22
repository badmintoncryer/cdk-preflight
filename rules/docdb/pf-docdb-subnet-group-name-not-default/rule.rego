package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-docdb-subnet-group-name-not-default", "ERROR", name,
	"Properties.DBSubnetGroupName",
	"DBSubnetGroupName \"default\" is reserved (\"Subnet group name default is reserved. Please specify another name.\")",
	"Pick another subnet group name",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-docdb-dbsubnetgroup.html") if {
	some name in resources_of_type("AWS::DocDB::DBSubnetGroup")
	n := _pf_docdb_lit(name, "Properties.DBSubnetGroupName")
	lower(n) == "default"
}
