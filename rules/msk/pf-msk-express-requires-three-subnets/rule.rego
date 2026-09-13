package cdk_preflight

import rego.v1

# Express brokers only come in a three Availability Zone shape: "Clusters with Express instance
# types require 3 subnets. ... InvalidParameter: brokerNodeGroupInfo". Standard brokers accept
# two, so nothing generic can carry this check.
violation contains make_diag_full("pf-msk-express-requires-three-subnets", "ERROR", name,
	"Properties.BrokerNodeGroupInfo.ClientSubnets",
	sprintf("Express instance type '%s' with %d client subnets; the create fails with \"Clusters with Express instance types require 3 subnets\"", [itype, n]),
	"Give an Express cluster three client subnets, one per Availability Zone",
	"https://docs.aws.amazon.com/msk/latest/developerguide/msk-broker-types-express.html") if {
	some name in resources_of_type("AWS::MSK::Cluster")
	itype := resolve(name, "Properties.BrokerNodeGroupInfo.InstanceType")
	is_string(itype)
	startswith(itype, "express.")
	n := count(flatten_list(name, "Properties.BrokerNodeGroupInfo.ClientSubnets"))
	n > 0
	n != 3
}
