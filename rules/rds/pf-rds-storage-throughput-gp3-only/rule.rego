package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-rds-storage-throughput-gp3-only", "ERROR", name,
	"Properties.StorageThroughput",
	sprintf("StorageThroughput is set with StorageType %v (\"You can't specify storage throughput for storage type gp2.\")", [st]),
	"Use StorageType gp3, or drop StorageThroughput",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-rds-dbinstance.html") if {
	some name in resources_of_type("AWS::RDS::DBInstance")
	_pf_rds_has(name, "StorageThroughput")
	st := resolve(name, "Properties.StorageType")
	is_string(st)
	st != "gp3"
}
