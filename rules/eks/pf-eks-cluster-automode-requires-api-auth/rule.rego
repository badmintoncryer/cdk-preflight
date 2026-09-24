package cdk_preflight

import rego.v1

# CloudFormation defaults AccessConfig.AuthenticationMode to CONFIG_MAP, so
# the case that bites is a template that says nothing at all about it.
violation contains make_diag_full("pf-eks-cluster-automode-requires-api-auth", "ERROR", name,
	"Properties.AccessConfig.AuthenticationMode",
	sprintf("Auto Mode is enabled but the cluster authenticates with %v (\"When EKS Auto Mode is enabled, you must use an EKS access config authentication mode of API_AND_CONFIG_MAP or API\")", [mode]),
	"Set AccessConfig.AuthenticationMode to API or API_AND_CONFIG_MAP",
	"https://docs.aws.amazon.com/eks/latest/userguide/automode-get-started-cli.html") if {
	some name in resources_of_type("AWS::EKS::Cluster")
	_pf_ekslib_flag(name, ["ComputeConfig", "Enabled"]) == true
	mode := _pf_ekslib_auth_mode(name)
	not mode in {"API", "API_AND_CONFIG_MAP"}
}
