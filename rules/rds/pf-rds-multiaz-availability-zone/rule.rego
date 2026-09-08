package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-rds-multiaz-availability-zone", "ERROR", name,
	"Properties.AvailabilityZone",
	"AvailabilityZone is set on a Multi-AZ instance (\"Requesting a specific availability zone is not valid for Multi-AZ instances.\")",
	"Drop AvailabilityZone, or turn MultiAZ off",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-rds-dbinstance.html") if {
	some name in resources_of_type("AWS::RDS::DBInstance")
	_pf_rds_true(name, "MultiAZ")
	_pf_rds_has(name, "AvailabilityZone")
}
