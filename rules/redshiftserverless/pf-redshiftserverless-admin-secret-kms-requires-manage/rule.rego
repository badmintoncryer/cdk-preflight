package cdk_preflight

import rego.v1

# Absent or literally false. An unresolved token is neither, so the rule skips it.
_pf_rsskms_unmanaged(name) if not _pf_rsslib_has(name, "ManageAdminPassword")

_pf_rsskms_unmanaged(name) if _pf_rsslib_false(name, "ManageAdminPassword")

violation contains make_diag_full("pf-redshiftserverless-admin-secret-kms-requires-manage", "ERROR", name,
	"Properties.AdminPasswordSecretKmsKeyId",
	"AdminPasswordSecretKmsKeyId is set but ManageAdminPassword is not true; CreateNamespace fails with \"The AdminPasswordSecretKmsKeyId parameter cannot be provided unless ManagedAdminPassword is true.\"",
	"Set ManageAdminPassword to true, or drop AdminPasswordSecretKmsKeyId",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-redshiftserverless-namespace.html") if {
	some name in resources_of_type("AWS::RedshiftServerless::Namespace")
	_pf_rsslib_has(name, "AdminPasswordSecretKmsKeyId")
	_pf_rsskms_unmanaged(name)
}
