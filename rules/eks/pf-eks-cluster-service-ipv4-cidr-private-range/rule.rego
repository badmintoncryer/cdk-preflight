package cdk_preflight

import rego.v1

# Containment, not prefix length: a block inside RFC 1918 with a prefix
# outside /12../24 draws the netmask message instead (own rule).
violation contains make_diag_full("pf-eks-cluster-service-ipv4-cidr-private-range", "ERROR", name,
	"Properties.KubernetesNetworkConfig.ServiceIpv4Cidr",
	sprintf("ServiceIpv4Cidr %v is outside 10.0.0.0/8, 172.16.0.0/12 and 192.168.0.0/16 (\"must be within RFC1918 range\")", [c]),
	"Pick a block inside 10.0.0.0/8, 172.16.0.0/12 or 192.168.0.0/16",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-eks-cluster-kubernetesnetworkconfig.html") if {
	some name in resources_of_type("AWS::EKS::Cluster")
	c := _pf_ekslib_oget(_pf_ekslib_get(name, "KubernetesNetworkConfig"), "ServiceIpv4Cidr")
	_pf_ekslib_lit(c)
	_pf_ec2lib_cidr(c)
	not _pf_ekslib_cidr_in_any(c, _pf_ekslib_rfc1918)
}
