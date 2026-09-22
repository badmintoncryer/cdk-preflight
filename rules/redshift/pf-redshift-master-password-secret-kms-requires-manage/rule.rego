package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-redshift-master-password-secret-kms-requires-manage", "ERROR", name,
	"Properties.MasterPasswordSecretKmsKeyId",
	"MasterPasswordSecretKmsKeyId is set but ManageMasterPassword is not true; CreateCluster rejects it (\"You can't set the secret encryption KMS key for this cluster without opting in to manage your admin credentials using AWS Secrets Manager.\")",
	"Set ManageMasterPassword: true (and drop MasterUserPassword), or remove MasterPasswordSecretKmsKeyId",
	"https://docs.aws.amazon.com/redshift/latest/APIReference/API_CreateCluster.html") if {
	some name in resources_of_type("AWS::Redshift::Cluster")
	_pf_redshiftlib_has(name, "MasterPasswordSecretKmsKeyId")
	_pf_redshiftlib_false_or_absent(name, "ManageMasterPassword")
}
