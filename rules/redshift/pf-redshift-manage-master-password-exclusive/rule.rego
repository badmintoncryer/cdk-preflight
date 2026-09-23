package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-redshift-manage-master-password-exclusive", "ERROR", name,
	"Properties.ManageMasterPassword",
	"ManageMasterPassword is true and MasterUserPassword is also set; CreateCluster rejects the pair (\"Your Amazon Redshift cluster is opting in to manage your password using AWS Secrets Manager. To provide your own password, opt out of managing your password with Secrets Manager.\")",
	"Keep only one: ManageMasterPassword: true (Secrets Manager) or MasterUserPassword",
	"https://docs.aws.amazon.com/redshift/latest/APIReference/API_CreateCluster.html") if {
	some name in resources_of_type("AWS::Redshift::Cluster")
	_pf_redshiftlib_true(name, "ManageMasterPassword")
	_pf_redshiftlib_has(name, "MasterUserPassword")
}
