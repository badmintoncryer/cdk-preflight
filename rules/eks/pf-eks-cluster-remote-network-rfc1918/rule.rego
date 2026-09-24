package cdk_preflight

import rego.v1

# The four allowed blocks were measured one by one on 2026-09-25:
# 100.64.0.0/10 is accepted, 100.64.0.0/9 is not, and 10.0.0.0/8 exactly is
# accepted - so this is containment, not a prefix-length range.
violation contains make_diag_full("pf-eks-cluster-remote-network-rfc1918", "ERROR", name,
	"Properties.RemoteNetworkConfig",
	sprintf("remote network %v is outside RFC 1918 and the CGNAT block (\"Invalid remote node network: CIDR %v is not part of RFC 1918 or CGNAT\")", [c, c]),
	"Use a block inside 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 or 100.64.0.0/10",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-eks-cluster-remotenetworkconfig.html") if {
	some name in resources_of_type("AWS::EKS::Cluster")
	some k in ["RemoteNodeNetworks", "RemotePodNetworks"]
	some c in _pf_ekslib_remote_cidrs(name, k)
	_pf_ekslib_lit(c)
	_pf_ec2lib_cidr(c)
	not _pf_ekslib_cidr_in_any(c, _pf_ekslib_remote_ranges)
}
