package cdk_preflight

import rego.v1

# Express brokers manage their own storage, so the create rejects any StorageInfo: "The
# storageInfo parameter is not supported for Express instance types. ... InvalidParameter:
# brokerNodeGroupInfo". Standard brokers require it, so the property cannot be schema-forbidden.
violation contains make_diag_full("pf-msk-express-no-ebs-storage", "ERROR", name,
	"Properties.BrokerNodeGroupInfo.StorageInfo",
	sprintf("Express instance type '%s' with StorageInfo; the create fails with \"The storageInfo parameter is not supported for Express instance types\"", [itype]),
	"Drop StorageInfo - Express brokers size their own storage",
	"https://docs.aws.amazon.com/msk/latest/developerguide/msk-broker-types-express.html") if {
	some name in resources_of_type("AWS::MSK::Cluster")
	itype := resolve(name, "Properties.BrokerNodeGroupInfo.InstanceType")
	is_string(itype)
	startswith(itype, "express.")
	props := input.resources[name].properties
	is_object(props)
	object.get(props, ["BrokerNodeGroupInfo", "StorageInfo"], "__pf_absent") != "__pf_absent"
}
