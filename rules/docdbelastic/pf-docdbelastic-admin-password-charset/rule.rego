package cdk_preflight

import rego.v1

_pf_dbepwc_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-docdbelastic-cluster.html#cfn-docdbelastic-cluster-adminuserpassword"

_pf_dbepwc_fix := "Remove the forward slash, double quote or at sign from AdminUserPassword, or set AuthType SECRET_ARN and pass a Secrets Manager secret ARN"

_pf_dbepwc_forbidden := {"/", "\"", "@"}

violation contains make_diag_full("pf-docdbelastic-admin-password-charset", "ERROR", name,
	"Properties.AdminUserPassword",
	sprintf("AdminUserPassword contains '%s'; a forward slash, double quote or at sign is not allowed and CreateCluster fails with \"Invalid password set in the AdminUserPassword.\"", [ch]),
	_pf_dbepwc_fix, _pf_dbepwc_url) if {
	some name in resources_of_type("AWS::DocDBElastic::Cluster")
	pw := resolve(name, "Properties.AdminUserPassword")
	is_string(pw)
	not input.resources[pw]
	some ch in _pf_dbepwc_forbidden
	contains(pw, ch)
}
