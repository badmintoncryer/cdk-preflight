package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-rds-magnetic-storage-deprecated", "ERROR", name,
	"Properties.StorageType",
	"StorageType: standard is magnetic storage (\"RDS can't create the DB instance because magnetic storage is deprecated. Set StorageType to gp2, gp3, or io2.\")",
	"Use gp2, gp3 or io2",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-rds-dbinstance.html") if {
	some name in resources_of_type("AWS::RDS::DBInstance")
	resolve(name, "Properties.StorageType") == "standard"
}
