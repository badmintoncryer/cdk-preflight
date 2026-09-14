package cdk_preflight

import rego.v1

# One subnet per Availability Zone: repeating a subnet id is rejected with "The list provided
# contains duplicate items. ... InvalidParameter: clientSubnets". The property carries no
# uniqueItems in the engine's schema, so nothing earlier sees the repeat.
violation contains make_diag_full("pf-msk-client-subnets-distinct", "ERROR", name,
	"Properties.BrokerNodeGroupInfo.ClientSubnets",
	sprintf("%d client subnets but only %d distinct ones; the create fails with \"The list provided contains duplicate items\"", [n, u]),
	"Give each Availability Zone its own subnet - no repeats",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-msk-cluster-brokernodegroupinfo.html") if {
	some name in resources_of_type("AWS::MSK::Cluster")
	subnets := [it.value | some it in flatten_list(name, "Properties.BrokerNodeGroupInfo.ClientSubnets"); is_string(it.value)]
	n := count(subnets)
	u := count({s | some s in subnets})
	u != n
}
