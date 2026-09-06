package cdk_preflight

import rego.v1

_pf_mdbkms_url := "https://docs.aws.amazon.com/memorydb/latest/APIReference/API_CreateCluster.html"

_pf_mdbkms_fix := "Point KmsKeyId at a key in the same region as the cluster"

violation contains make_diag_full("pf-memorydb-kms-key-region", "ERROR", name,
	"Properties.KmsKeyId",
	sprintf("the key is in region '%s' but the cluster deploys to '%s'; CreateCluster fails with \"KMS key does not exist with key id\"", [parts[3], region]),
	_pf_mdbkms_fix, _pf_mdbkms_url) if {
	region := data.cdk_preflight.deploy_region
	some name in resources_of_type("AWS::MemoryDB::Cluster")
	parts := _pf_cachelib_arn(resolve(name, "Properties.KmsKeyId"))
	parts[2] == "kms"
	parts[3] != region
}
