package cdk_preflight

import rego.v1

# A provisioned cluster spans two or three Availability Zones - one client subnet each. Both ends
# are rejected by CreateCluster with "Specify either two or three client subnets. ...
# InvalidParameter: brokerNodeGroupInfo"; the engine's schema carries no minItems/maxItems here.
violation contains make_diag_full("pf-msk-client-subnets-count", "ERROR", name,
	"Properties.BrokerNodeGroupInfo.ClientSubnets",
	sprintf("only %d client subnet(s); the create fails with \"Specify either two or three client subnets\"", [n]),
	"List two or three client subnets, each in its own Availability Zone",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-msk-cluster-brokernodegroupinfo.html") if {
	some name in resources_of_type("AWS::MSK::Cluster")
	_pf_countable_list(name, "Properties.BrokerNodeGroupInfo.ClientSubnets")
	n := count(flatten_list(name, "Properties.BrokerNodeGroupInfo.ClientSubnets"))
	n > 0
	n < 2
}

violation contains make_diag_full("pf-msk-client-subnets-count", "ERROR", name,
	"Properties.BrokerNodeGroupInfo.ClientSubnets",
	sprintf("%d client subnets; the create fails with \"Specify either two or three client subnets\"", [n]),
	"List two or three client subnets, each in its own Availability Zone",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-msk-cluster-brokernodegroupinfo.html") if {
	some name in resources_of_type("AWS::MSK::Cluster")
	_pf_countable_list(name, "Properties.BrokerNodeGroupInfo.ClientSubnets")
	n := count(flatten_list(name, "Properties.BrokerNodeGroupInfo.ClientSubnets"))
	n > 3
}
