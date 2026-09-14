package cdk_preflight

import rego.v1

# Every VpcConnectivity auth switch is an ordinary Boolean in the schema, but the service only
# accepts them on an existing cluster: "When creating a cluster, all vpcConnectivity auth schemes
# must be disabled ('enabled' : false). You can enable auth schemes after the cluster is created.
# ... InvalidParameter: vpcConnectivity.clientAuthentication".
violation contains make_diag_full("pf-msk-vpc-connectivity-auth-not-at-create", "ERROR", name,
	"Properties.BrokerNodeGroupInfo.ConnectivityInfo.VpcConnectivity.ClientAuthentication",
	"a VpcConnectivity authentication scheme is enabled; the create fails with \"When creating a cluster, all vpcConnectivity auth schemes must be disabled\"",
	"Create the cluster with every VpcConnectivity auth scheme false and enable them in a later update",
	"https://docs.aws.amazon.com/msk/latest/developerguide/aws-access-mult-vpc.html") if {
	some name in resources_of_type("AWS::MSK::Cluster")
	props := input.resources[name].properties
	is_object(props)
	auth := object.get(props, ["BrokerNodeGroupInfo", "ConnectivityInfo", "VpcConnectivity", "ClientAuthentication"], {})
	some path in [["Sasl", "Iam", "Enabled"], ["Sasl", "Scram", "Enabled"], ["Tls", "Enabled"]]
	object.get(auth, path, false) == true
}
