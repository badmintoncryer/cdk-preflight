package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-eks-cluster-remote-node-pod-network-overlap", "ERROR", name,
	"Properties.RemoteNetworkConfig.RemotePodNetworks",
	sprintf("remote pod network %v overlaps remote node network %v (\"Invalid remote pod network: CIDR %v overlaps with already existing CIDR %v\")", [pc, nc, pc, nc]),
	"Give the remote pods a block that does not sit inside a remote node block",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-eks-cluster-remotenetworkconfig.html") if {
	some name in resources_of_type("AWS::EKS::Cluster")
	some nc in _pf_ekslib_remote_cidrs(name, "RemoteNodeNetworks")
	some pc in _pf_ekslib_remote_cidrs(name, "RemotePodNetworks")
	_pf_ekslib_lit(nc)
	_pf_ekslib_lit(pc)
	_pf_ec2lib_cidr_overlap(nc, pc)
}
