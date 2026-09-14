package cdk_preflight

import rego.v1

# The 1000 MiB/s top of the range is only reachable on the largest brokers - every size carries
# its own ceiling (user guide table), and the create fails with "For brokers of type m5.4xlarge,
# the maximum value for VolumeThroughput cannot exceed 593.75 MiB/s. ... InvalidParameter:
# volumeThroughput". VolumeThroughput is an Integer, so the table holds the largest integer the
# service accepts for each size.
violation contains make_diag_full("pf-msk-provisioned-throughput-max-per-instance", "ERROR", name,
	"Properties.BrokerNodeGroupInfo.StorageInfo.EBSStorageInfo.ProvisionedThroughput.VolumeThroughput",
	sprintf("VolumeThroughput %d MiB/s on '%s', which tops out at %d MiB/s; the create fails with \"the maximum value for VolumeThroughput cannot exceed\"", [t, itype, cap]),
	"Lower VolumeThroughput to the ceiling for this broker size, or move to a larger broker",
	"https://docs.aws.amazon.com/msk/latest/developerguide/msk-provision-throughput-management.html") if {
	some name in resources_of_type("AWS::MSK::Cluster")
	props := input.resources[name].properties
	is_object(props)
	prov := object.get(props, ["BrokerNodeGroupInfo", "StorageInfo", "EBSStorageInfo", "ProvisionedThroughput"], {})
	object.get(prov, "Enabled", false) == true
	itype := object.get(props, ["BrokerNodeGroupInfo", "InstanceType"], "")
	cap := object.get(_pf_mskptmax_caps, itype, null)
	cap != null
	v := object.get(prov, "VolumeThroughput", null)
	v != null
	t := to_number(v)
	t > cap
}

# Maximum storage throughput per broker size (user guide table, 2026-09-14), floored to the
# largest integer VolumeThroughput accepts. Sizes the table does not list are not checked.
_pf_mskptmax_caps := {
	"kafka.m5.4xlarge": 593,
	"kafka.m5.8xlarge": 850,
	"kafka.m5.12xlarge": 1000,
	"kafka.m5.16xlarge": 1000,
	"kafka.m5.24xlarge": 1000,
	"kafka.m7g.2xlarge": 312,
	"kafka.m7g.4xlarge": 625,
	"kafka.m7g.8xlarge": 1000,
	"kafka.m7g.12xlarge": 1000,
	"kafka.m7g.16xlarge": 1000,
}
