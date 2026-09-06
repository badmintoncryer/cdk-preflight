package cdk_preflight

import rego.v1

_pf_eckms_url := "https://docs.aws.amazon.com/AmazonElastiCache/latest/APIReference/API_CreateReplicationGroup.html"

_pf_eckms_fix := "Set AtRestEncryptionEnabled: true next to KmsKeyId and point it at a key in the same region as the replication group"

violation contains make_diag_full("pf-elasticache-kms-key", "ERROR", name,
	"Properties.KmsKeyId",
	"KmsKeyId is set but AtRestEncryptionEnabled is not true; the create call fails with \"Please enable encryption at rest to use Customer Managed CMK\"",
	_pf_eckms_fix, _pf_eckms_url) if {
	some name in resources_of_type("AWS::ElastiCache::ReplicationGroup")
	not _pf_cachelib_absent(name, "KmsKeyId")
	not _pf_eckms_atrest(name)
}

_pf_eckms_atrest(name) if resolve(name, "Properties.AtRestEncryptionEnabled") == true

violation contains make_diag_full("pf-elasticache-kms-key", "ERROR", name,
	"Properties.KmsKeyId",
	sprintf("the key is in region '%s' but the replication group deploys to '%s'; the create call fails with \"KMS key does not exist with key id\"", [parts[3], region]),
	_pf_eckms_fix, _pf_eckms_url) if {
	region := data.cdk_preflight.deploy_region
	some name in resources_of_type("AWS::ElastiCache::ReplicationGroup")
	parts := _pf_cachelib_arn(resolve(name, "Properties.KmsKeyId"))
	parts[2] == "kms"
	parts[3] != region
}
