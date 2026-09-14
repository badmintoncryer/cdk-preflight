package cdk_preflight

import rego.v1

# ZookeeperAccess exists only in CloudFormation - CreateClusterV2 has no such parameter - and
# its documentation page carries no description at all, so nothing says it is an update-only
# switch. The resource handler rejects it outright: "Zookeeper Access cannot be configured during
# cluster creation. 'ZookeeperAccess'".
violation contains make_diag_full("pf-msk-zookeeper-access-not-at-create", "ERROR", name,
	"Properties.ZookeeperAccess",
	"ZookeeperAccess is set on a cluster being created; the create fails with \"Zookeeper Access cannot be configured during cluster creation\"",
	"Drop ZookeeperAccess from the template and set it in a later update",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-msk-cluster-zookeeperaccess.html") if {
	some name in resources_of_type("AWS::MSK::Cluster")
	props := input.resources[name].properties
	is_object(props)
	is_object(object.get(props, "ZookeeperAccess", null))
}
