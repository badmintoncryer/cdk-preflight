package cdk_preflight

import rego.v1

_pf_dbepwl_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-docdbelastic-cluster.html#cfn-docdbelastic-cluster-adminuserpassword"

_pf_dbepwl_fix := "Give AdminUserPassword 8-99 characters, or set AuthType SECRET_ARN and pass a Secrets Manager secret ARN"

violation contains make_diag_full("pf-docdbelastic-admin-password-length", "ERROR", name,
	"Properties.AdminUserPassword",
	sprintf("AdminUserPassword is %d characters; CreateCluster fails with \"Invalid password set in the AdminUserPassword. Password must be longer than 8 ASCII characters.\"", [count(pw)]),
	_pf_dbepwl_fix, _pf_dbepwl_url) if {
	some name in resources_of_type("AWS::DocDBElastic::Cluster")
	pw := resolve(name, "Properties.AdminUserPassword")
	is_string(pw)
	not input.resources[pw]
	count(pw) < 8
}

violation contains make_diag_full("pf-docdbelastic-admin-password-length", "ERROR", name,
	"Properties.AdminUserPassword",
	sprintf("AdminUserPassword is %d characters; CreateCluster accepts 8-99 (\"Invalid password set in the AdminUserPassword.\")", [count(pw)]),
	_pf_dbepwl_fix, _pf_dbepwl_url) if {
	some name in resources_of_type("AWS::DocDBElastic::Cluster")
	pw := resolve(name, "Properties.AdminUserPassword")
	is_string(pw)
	not input.resources[pw]
	count(pw) > 99
}
