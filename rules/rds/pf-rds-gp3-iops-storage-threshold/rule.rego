package cdk_preflight

import rego.v1

_pf_rdsgp3_has(name, key) if {
	props := input.resources[name].properties
	is_object(props)
	object.get(props, key, "__pf_absent") != "__pf_absent"
}

_pf_rdsgp3_custom(name) if _pf_rdsgp3_has(name, "Iops")

_pf_rdsgp3_custom(name) if _pf_rdsgp3_has(name, "StorageThroughput")

violation contains make_diag_full("pf-rds-gp3-iops-storage-threshold", "ERROR", name,
	"Properties.Iops",
	sprintf("gp3 with %v GiB cannot take custom Iops/StorageThroughput below 400 GiB for engine %s (\"You can't specify IOPS or storage throughput ... less than 400.\")", [s, eng]),
	"Drop the custom Iops/StorageThroughput, or allocate at least 400 GiB",
	"https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/CHAP_Storage.html") if {
	some name in resources_of_type("AWS::RDS::DBInstance")
	eng := resolve(name, "Properties.Engine")
	eng in {"postgres", "mysql"}
	resolve(name, "Properties.StorageType") == "gp3"
	s := to_number(resolve(name, "Properties.AllocatedStorage"))
	s < 400
	_pf_rdsgp3_custom(name)
}
