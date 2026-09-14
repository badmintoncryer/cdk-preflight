package cdk_preflight

import rego.v1

# "To provision storage throughput, you must choose broker size kafka.m5.4xlarge or larger (or
# kafka.m7g.2xlarge or larger)" - the create fails on anything below with "Provisioned throughput
# is not supported for the specified broker type. ... InvalidParameter: provisionedThroughput".
# Written as a deny list of the sizes below the floor: an allow list would turn every broker size
# AWS adds into a false positive.
violation contains make_diag_full("pf-msk-provisioned-throughput-instance-type", "ERROR", name,
	"Properties.BrokerNodeGroupInfo.InstanceType",
	sprintf("ProvisionedThroughput is enabled on '%s'; the create fails with \"Provisioned throughput is not supported for the specified broker type\"", [itype]),
	"Move to kafka.m5.4xlarge or kafka.m7g.2xlarge (or larger), or turn ProvisionedThroughput off",
	"https://docs.aws.amazon.com/msk/latest/developerguide/msk-provision-throughput-management.html") if {
	some name in resources_of_type("AWS::MSK::Cluster")
	props := input.resources[name].properties
	is_object(props)
	object.get(props, ["BrokerNodeGroupInfo", "StorageInfo", "EBSStorageInfo", "ProvisionedThroughput", "Enabled"], false) == true
	itype := object.get(props, ["BrokerNodeGroupInfo", "InstanceType"], "")
	itype in _pf_mskptit_too_small
}

# Standard broker sizes below the provisioned-throughput floor.
_pf_mskptit_too_small := {
	"kafka.t3.small",
	"kafka.m5.large", "kafka.m5.xlarge", "kafka.m5.2xlarge",
	"kafka.m7g.large", "kafka.m7g.xlarge",
}
