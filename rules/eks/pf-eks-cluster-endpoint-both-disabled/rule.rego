package cdk_preflight

import rego.v1

# Both default to a value that keeps one endpoint up (public true, private
# false), so only a template that writes false twice reaches the refusal.
violation contains make_diag_full("pf-eks-cluster-endpoint-both-disabled", "ERROR", name,
	"Properties.ResourcesVpcConfig",
	"EndpointPublicAccess and EndpointPrivateAccess are both false (\"Private and public endpoint access cannot be false\")",
	"Leave EndpointPrivateAccess true (the usual private-only cluster) or keep the public endpoint",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-eks-cluster-resourcesvpcconfig.html") if {
	some name in resources_of_type("AWS::EKS::Cluster")
	vpc := _pf_ekslib_get(name, "ResourcesVpcConfig")
	_pf_ekslib_oget(vpc, "EndpointPublicAccess") == false
	_pf_ekslib_oget(vpc, "EndpointPrivateAccess") == false
}
