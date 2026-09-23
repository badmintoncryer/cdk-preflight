package cdk_preflight

import rego.v1

_pf_dbeun_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-docdbelastic-cluster.html#cfn-docdbelastic-cluster-adminusername"

_pf_dbeun_fix := "Start AdminUserName with a letter (1-63 letters or numbers)"

violation contains make_diag_full("pf-docdbelastic-admin-username-first-char", "ERROR", name,
	"Properties.AdminUserName",
	sprintf("AdminUserName '%s' does not start with a letter; CreateCluster fails with \"Invalid admin user name - %s.\"", [u, u]),
	_pf_dbeun_fix, _pf_dbeun_url) if {
	some name in resources_of_type("AWS::DocDBElastic::Cluster")
	u := resolve(name, "Properties.AdminUserName")
	is_string(u)
	not input.resources[u]
	not regex.match(`^[A-Za-z]`, u)
}
