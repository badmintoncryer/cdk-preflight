package cdk_preflight

import rego.v1

# The smallest Standard broker has no tiered tier: "Tiered storage doesn't support broker size
# t3.small" (user guide), and CreateClusterV2 answers "Tiered storage is not supported for the
# specified broker type. ... InvalidParameter: instanceType". Express brokers reject StorageMode
# for a different reason and are covered by pf-msk-express-no-storage-mode.
violation contains make_diag_full("pf-msk-tiered-storage-instance-type", "ERROR", name,
	"Properties.StorageMode",
	"StorageMode TIERED on a kafka.t3.small broker; the create fails with \"Tiered storage is not supported for the specified broker type\"",
	"Move to kafka.m5.large or larger, or drop StorageMode",
	"https://docs.aws.amazon.com/msk/latest/developerguide/msk-tiered-storage.html") if {
	some name in resources_of_type("AWS::MSK::Cluster")
	resolve(name, "Properties.BrokerNodeGroupInfo.InstanceType") == "kafka.t3.small"
	resolve(name, "Properties.StorageMode") == "TIERED"
}
