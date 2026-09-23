package cdk_preflight

import rego.v1

# StorageEncrypted が無い（既定 false）か false と書かれているのに KmsKeyId がある。
# スナップショット / ソースクラスタからの復元は暗号化を継承するので判定しない。
_pf_nepkms_unencrypted(name) if not _pf_neptunelib_has(name, "StorageEncrypted")

_pf_nepkms_unencrypted(name) if _pf_neptunelib_false(name, "StorageEncrypted")

violation contains make_diag_full("pf-neptune-kms-requires-storage-encrypted", "ERROR", name,
	"Properties.KmsKeyId",
	"KmsKeyId is set but StorageEncrypted is not true; Neptune rejects the cluster (\"You cannot specify KMS key for unencrypted clusters.\")",
	"Set StorageEncrypted: true (or drop KmsKeyId)",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-neptune-dbcluster.html") if {
	some name in resources_of_type("AWS::Neptune::DBCluster")
	_pf_neptunelib_has(name, "KmsKeyId")
	not _pf_neptunelib_has(name, "SnapshotIdentifier")
	not _pf_neptunelib_has(name, "SourceDBClusterIdentifier")
	_pf_nepkms_unencrypted(name)
}
