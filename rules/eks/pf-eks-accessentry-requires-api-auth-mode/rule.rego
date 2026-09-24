package cdk_preflight

import rego.v1

# CloudFormation defaults AccessConfig.AuthenticationMode to CONFIG_MAP, so the
# case that bites is the one where the template says nothing at all - absence is
# read as CONFIG_MAP here. Cross-resource: silent when the cluster is imported.
violation contains make_diag_full("pf-eks-accessentry-requires-api-auth-mode", "ERROR", name,
	"Properties.ClusterName",
	sprintf("cluster %v uses authentication mode %v, which refuses access entries (\"The cluster's authentication mode must be set to one of [API, API_AND_CONFIG_MAP] to perform this operation.\")", [cl, mode]),
	"Set AccessConfig.AuthenticationMode to API or API_AND_CONFIG_MAP on the cluster",
	"https://docs.aws.amazon.com/eks/latest/userguide/grant-k8s-access.html") if {
	some name in resources_of_type("AWS::EKS::AccessEntry")
	cl := resolve(name, "Properties.ClusterName")
	cl in resources_of_type("AWS::EKS::Cluster")
	mode := _pf_aeauth_mode(cl)
	mode != "API"
	mode != "API_AND_CONFIG_MAP"
}

_pf_aeauth_mode(cl) := m if {
	m := _pf_ekslib_oget(_pf_ekslib_get(cl, "AccessConfig"), "AuthenticationMode")
	is_string(m)
}

_pf_aeauth_mode(cl) := "CONFIG_MAP" if {
	not _pf_ekslib_ohas(_pf_ekslib_get(cl, "AccessConfig"), "AuthenticationMode")
	cl in resources_of_type("AWS::EKS::Cluster")
}
