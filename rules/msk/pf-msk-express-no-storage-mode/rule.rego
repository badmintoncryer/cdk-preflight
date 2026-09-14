package cdk_preflight

import rego.v1

# Tiered storage is a Standard broker feature; on Express the create fails with "The storageMode
# parameter is not supported for Express instance types. ... InvalidParameter: storageMode".
violation contains make_diag_full("pf-msk-express-no-storage-mode", "ERROR", name,
	"Properties.StorageMode",
	sprintf("Express instance type '%s' with StorageMode '%s'; the create fails with \"The storageMode parameter is not supported for Express instance types\"", [itype, mode]),
	"Drop StorageMode - Express brokers have no tiered-storage switch",
	"https://docs.aws.amazon.com/msk/latest/developerguide/msk-broker-types-express.html") if {
	some name in resources_of_type("AWS::MSK::Cluster")
	itype := resolve(name, "Properties.BrokerNodeGroupInfo.InstanceType")
	is_string(itype)
	startswith(itype, "express.")
	mode := resolve(name, "Properties.StorageMode")
	is_string(mode)
}
