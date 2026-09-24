package cdk_preflight

import rego.v1

# Measured 2026-09-25 against CreateCluster: /11 and /25 are both refused,
# /12 and /24 both reach the next check.
violation contains make_diag_full("pf-eks-cluster-service-ipv4-cidr-prefix-range", "ERROR", name,
	"Properties.KubernetesNetworkConfig.ServiceIpv4Cidr",
	sprintf("ServiceIpv4Cidr %v has netmask /%v (\"must have netmask size between /12 and /24 inclusive\")", [c, p]),
	"Size the service range between /12 and /24",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-eks-cluster-kubernetesnetworkconfig.html") if {
	some name in resources_of_type("AWS::EKS::Cluster")
	c := _pf_ekslib_oget(_pf_ekslib_get(name, "KubernetesNetworkConfig"), "ServiceIpv4Cidr")
	_pf_ekslib_lit(c)
	parts := split(c, "/")
	count(parts) == 2
	p := to_number(parts[1])
	_pf_ekssvc_outside(p)
}

_pf_ekssvc_outside(p) if p < 12

_pf_ekssvc_outside(p) if p > 24
