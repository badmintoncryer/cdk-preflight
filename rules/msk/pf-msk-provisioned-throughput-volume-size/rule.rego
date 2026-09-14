package cdk_preflight

import rego.v1

# VolumeSize accepts 1..16384 in the schema; provisioned throughput narrows the floor to 10 GiB.
# The create fails with "To enable ProvisionedThroughput, you must set volume size to a value that
# is greater than or equal to 10. ... InvalidParameter: volumeSize".
violation contains make_diag_full("pf-msk-provisioned-throughput-volume-size", "ERROR", name,
	"Properties.BrokerNodeGroupInfo.StorageInfo.EBSStorageInfo.VolumeSize",
	sprintf("ProvisionedThroughput is enabled on a %d GiB volume; the create fails with \"you must set volume size to a value that is greater than or equal to 10\"", [s]),
	"Give the broker volume at least 10 GiB, or turn ProvisionedThroughput off",
	"https://docs.aws.amazon.com/msk/latest/developerguide/msk-provision-throughput-management.html") if {
	some name in resources_of_type("AWS::MSK::Cluster")
	props := input.resources[name].properties
	is_object(props)
	ebs := object.get(props, ["BrokerNodeGroupInfo", "StorageInfo", "EBSStorageInfo"], {})
	object.get(ebs, ["ProvisionedThroughput", "Enabled"], false) == true
	v := object.get(ebs, "VolumeSize", null)
	v != null
	s := to_number(v)
	s < 10
}
