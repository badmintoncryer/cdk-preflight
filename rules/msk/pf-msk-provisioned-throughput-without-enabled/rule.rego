package cdk_preflight

import rego.v1

# Both members of ProvisionedThroughput are Required: No, so naming a throughput without the
# switch passes every earlier layer; the create fails with "To specify a value for
# VolumeThroughput, you must enable ProvisionedThroughput. ... InvalidParameter: volumeThroughput".
violation contains make_diag_full("pf-msk-provisioned-throughput-without-enabled", "ERROR", name,
	"Properties.BrokerNodeGroupInfo.StorageInfo.EBSStorageInfo.ProvisionedThroughput.Enabled",
	"VolumeThroughput is set while ProvisionedThroughput.Enabled is not true; the create fails with \"To specify a value for VolumeThroughput, you must enable ProvisionedThroughput\"",
	"Set ProvisionedThroughput.Enabled to true, or drop VolumeThroughput",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-msk-cluster-provisionedthroughput.html") if {
	some name in resources_of_type("AWS::MSK::Cluster")
	props := input.resources[name].properties
	is_object(props)
	prov := object.get(props, ["BrokerNodeGroupInfo", "StorageInfo", "EBSStorageInfo", "ProvisionedThroughput"], null)
	is_object(prov)
	object.get(prov, "VolumeThroughput", "__pf_absent") != "__pf_absent"
	object.get(prov, "Enabled", false) != true
}
