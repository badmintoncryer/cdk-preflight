package cdk_preflight

import rego.v1

# Claim scope: ManageMasterUserPassword absent. An explicit false was not probed and stays silent.
violation contains make_diag_full("pf-docdb-master-user-secret-kms-requires-manage", "ERROR", name,
	"Properties.MasterUserSecretKmsKeyId",
	"MasterUserSecretKmsKeyId is set without ManageMasterUserPassword (\"A ManageMasterUserPassword value is required when MasterUserSecretKmsKeyId is specified.\")",
	"Set ManageMasterUserPassword: true (and drop MasterUserPassword), or drop MasterUserSecretKmsKeyId",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-docdb-dbcluster.html") if {
	some name in _pf_docdb_clusters
	_pf_docdb_has(name, "MasterUserSecretKmsKeyId")
	not _pf_docdb_has(name, "ManageMasterUserPassword")
}
