package cdk_preflight

import rego.v1

# The schema lists IPV4 | DUAL, but DUAL is reachable only by updating an existing cluster: the
# create fails with "Invalid NetworkType value in ConnectivityInfo. When creating a cluster, only
# IPV4 is supported. ... InvalidParameter: networkType".
violation contains make_diag_full("pf-msk-network-type-ipv4-at-create", "ERROR", name,
	"Properties.BrokerNodeGroupInfo.ConnectivityInfo.NetworkType",
	sprintf("NetworkType '%s'; the create fails with \"When creating a cluster, only IPV4 is supported\"", [t]),
	"Create the cluster as IPV4 and switch it to DUAL in a later update",
	"https://docs.aws.amazon.com/msk/latest/developerguide/mskp-choose-cluster-network-type.html") if {
	some name in resources_of_type("AWS::MSK::Cluster")
	t := resolve(name, "Properties.BrokerNodeGroupInfo.ConnectivityInfo.NetworkType")
	is_string(t)
	t != "IPV4"
}
