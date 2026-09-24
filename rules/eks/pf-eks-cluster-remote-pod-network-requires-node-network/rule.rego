package cdk_preflight

import rego.v1

# RemotePodNetworks on its own is refused; node networks on their own are
# accepted (measured 2026-09-25 against CreateCluster).
violation contains make_diag_full("pf-eks-cluster-remote-pod-network-requires-node-network", "ERROR", name,
	"Properties.RemoteNetworkConfig.RemoteNodeNetworks",
	"RemoteNetworkConfig is set without RemoteNodeNetworks (\"remoteNodeNetworks are required when specifying remoteNetworkConfig.\")",
	"List the on-premises node CIDRs in RemoteNodeNetworks (pod networks alone are refused)",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-eks-cluster-remotenetworkconfig.html") if {
	some name in resources_of_type("AWS::EKS::Cluster")
	rnc := _pf_ekslib_get(name, "RemoteNetworkConfig")
	is_object(rnc)
	not _pf_eksrn_has_nodes(rnc)
}

_pf_eksrn_has_nodes(rnc) if {
	n := _pf_ekslib_oget(rnc, "RemoteNodeNetworks")
	n != []
}
