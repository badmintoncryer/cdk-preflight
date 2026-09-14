package cdk_preflight

import rego.v1

# One Availability Zone per client subnet, and the brokers are spread evenly over them, so
# NumberOfBrokerNodes has to divide by the number of subnets. CreateCluster answers with "The
# target number of broker nodes must be a multiple of the number of Availability Zones in the
# Client subnets parameter ... InvalidParameter: numberOfBrokerNodes".
violation contains make_diag_full("pf-msk-broker-count-multiple-of-az", "ERROR", name,
	"Properties.NumberOfBrokerNodes",
	sprintf("%d broker nodes over %d client subnets is not a whole number per Availability Zone; the create fails with \"The target number of broker nodes must be a multiple of the number of Availability Zones in the Client subnets parameter\"", [n, s]),
	"Set NumberOfBrokerNodes to a multiple of the number of client subnets",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-msk-cluster.html") if {
	some name in resources_of_type("AWS::MSK::Cluster")
	s := count(flatten_list(name, "Properties.BrokerNodeGroupInfo.ClientSubnets"))
	s > 0
	n := to_number(resolve(name, "Properties.NumberOfBrokerNodes"))
	floor(n / s) * s != n
}
