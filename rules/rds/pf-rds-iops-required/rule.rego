package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-rds-iops-required", "ERROR", name,
	"Properties.Iops",
	sprintf("StorageType %s requires Iops (\"The storage type %s requires iops to be specified.\")", [st, st]),
	"Set Iops alongside the provisioned-IOPS storage type",
	"https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_CreateDBInstance.html") if {
	some name in resources_of_type("AWS::RDS::DBInstance")
	st := resolve(name, "Properties.StorageType")
	st in {"io1", "io2"}
	props := input.resources[name].properties
	is_object(props)
	object.get(props, "Iops", "__pf_absent") == "__pf_absent"
}
