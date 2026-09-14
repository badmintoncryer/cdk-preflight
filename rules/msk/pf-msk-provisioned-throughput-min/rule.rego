package cdk_preflight

import rego.v1

# VolumeThroughput is a plain Integer in the schema; the service floor is 250 MiB/s and the
# create fails with "EBS volume throughput should be between 250 and 1000 MiB/s. ...
# InvalidParameter: volumeThroughput". The per-broker-size ceiling is pf-msk-provisioned-throughput-max-per-instance.
violation contains make_diag_full("pf-msk-provisioned-throughput-min", "ERROR", name,
	"Properties.BrokerNodeGroupInfo.StorageInfo.EBSStorageInfo.ProvisionedThroughput.VolumeThroughput",
	sprintf("VolumeThroughput %d MiB/s; the create fails with \"EBS volume throughput should be between 250 and 1000 MiB/s\"", [t]),
	"Ask for at least 250 MiB/s, or turn ProvisionedThroughput off to keep the baseline throughput",
	"https://docs.aws.amazon.com/msk/latest/developerguide/msk-provision-throughput-management.html") if {
	some name in resources_of_type("AWS::MSK::Cluster")
	props := input.resources[name].properties
	is_object(props)
	prov := object.get(props, ["BrokerNodeGroupInfo", "StorageInfo", "EBSStorageInfo", "ProvisionedThroughput"], {})
	object.get(prov, "Enabled", false) == true
	v := object.get(prov, "VolumeThroughput", null)
	v != null
	t := to_number(v)
	t < 250
}
