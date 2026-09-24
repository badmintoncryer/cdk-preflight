package cdk_preflight

import rego.v1

# CloudFormation defaults AccessConfig.AuthenticationMode to CONFIG_MAP, so a
# hybrid-node cluster that never mentions AccessConfig is refused outright.
violation contains make_diag_full("pf-eks-cluster-remote-network-requires-api-auth", "ERROR", name,
	"Properties.AccessConfig.AuthenticationMode",
	sprintf("RemoteNetworkConfig is set but the cluster authenticates with %v (\"AccessConfig AuthMode must be API_AND_CONFIG_MAP or API when remoteNetworkConfig is specified\")", [mode]),
	"Set AccessConfig.AuthenticationMode to API or API_AND_CONFIG_MAP",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-eks-cluster-remotenetworkconfig.html") if {
	some name in resources_of_type("AWS::EKS::Cluster")
	_pf_ekslib_has(name, "RemoteNetworkConfig")
	mode := _pf_ekslib_auth_mode(name)
	not mode in {"API", "API_AND_CONFIG_MAP"}
}
