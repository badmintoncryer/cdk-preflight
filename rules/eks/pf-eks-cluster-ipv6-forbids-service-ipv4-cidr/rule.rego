package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-eks-cluster-ipv6-forbids-service-ipv4-cidr", "ERROR", name,
	"Properties.KubernetesNetworkConfig.ServiceIpv4Cidr",
	sprintf("the cluster runs IpFamily ipv6 but also sets ServiceIpv4Cidr %v (\"serviceIpv4Cidr cannot be specified when creating an \\\"ipv6\\\" cluster\")", [c]),
	"Drop ServiceIpv4Cidr on an ipv6 cluster; EKS picks the service range itself",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-eks-cluster-kubernetesnetworkconfig.html") if {
	some name in resources_of_type("AWS::EKS::Cluster")
	knc := _pf_ekslib_get(name, "KubernetesNetworkConfig")
	_pf_ekslib_oget(knc, "IpFamily") == "ipv6"
	c := _pf_ekslib_oget(knc, "ServiceIpv4Cidr")
	_pf_ekslib_lit(c)
}
