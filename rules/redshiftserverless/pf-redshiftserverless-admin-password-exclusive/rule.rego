package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-redshiftserverless-admin-password-exclusive", "ERROR", name,
	"Properties.AdminUserPassword",
	"ManageAdminPassword is true and AdminUserPassword is also set; CreateNamespace fails with \"The AdminUserPassword parameter cannot be provided if ManagedAdminPassword is true.\"",
	"Drop AdminUserPassword and let Secrets Manager hold the credential, or set ManageAdminPassword to false",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-redshiftserverless-namespace.html") if {
	some name in resources_of_type("AWS::RedshiftServerless::Namespace")
	_pf_rsslib_true(name, "ManageAdminPassword")
	_pf_rsslib_has(name, "AdminUserPassword")
}
