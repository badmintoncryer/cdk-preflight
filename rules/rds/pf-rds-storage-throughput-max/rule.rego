package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-rds-storage-throughput-max", "ERROR", name,
	"Properties.StorageThroughput",
	sprintf("StorageThroughput %v is above the gp3 maximum of 4000 (\"Invalid storage throughput value for engine name postgres and storage type gp3: 4001\")", [n]),
	"Use at most 4000 MiBps",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-rds-dbinstance.html") if {
	some name in resources_of_type("AWS::RDS::DBInstance")
	resolve(name, "Properties.StorageType") == "gp3"
	n := to_number(resolve(name, "Properties.StorageThroughput"))
	n > 4000
}
