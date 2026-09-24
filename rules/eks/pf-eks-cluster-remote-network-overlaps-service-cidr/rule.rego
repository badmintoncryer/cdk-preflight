package cdk_preflight

import rego.v1

# Only decidable when ServiceIpv4Cidr is written out: EKS picks the range
# itself otherwise and the template cannot know it.
violation contains make_diag_full("pf-eks-cluster-remote-network-overlaps-service-cidr", "ERROR", name,
	"Properties.RemoteNetworkConfig",
	sprintf("remote network %v overlaps the service range %v (\"Invalid remote node network: CIDR %v overlaps with service CIDR %v\")", [c, svc, c, svc]),
	"Move the remote network off the block given as ServiceIpv4Cidr",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-eks-cluster-remotenetworkconfig.html") if {
	some name in resources_of_type("AWS::EKS::Cluster")
	svc := _pf_ekslib_oget(_pf_ekslib_get(name, "KubernetesNetworkConfig"), "ServiceIpv4Cidr")
	_pf_ekslib_lit(svc)
	some k in ["RemoteNodeNetworks", "RemotePodNetworks"]
	some c in _pf_ekslib_remote_cidrs(name, k)
	_pf_ekslib_lit(c)
	_pf_ec2lib_cidr_overlap(c, svc)
}
