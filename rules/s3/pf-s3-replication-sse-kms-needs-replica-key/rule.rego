package cdk_preflight

import rego.v1

_pf_s3rsk_fix := "Set Destination.EncryptionConfiguration.ReplicaKmsKeyID when SseKmsEncryptedObjects is Enabled"

_pf_s3rsk_url := "https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketReplication.html"

violation contains make_diag_full("pf-s3-replication-sse-kms-needs-replica-key", "ERROR", name,
	sprintf("Properties.ReplicationConfiguration.Rules.%d.Destination.EncryptionConfiguration", [rule.index]),
	"SourceSelectionCriteria enables SSE-KMS replication but Destination.EncryptionConfiguration.ReplicaKmsKeyID is missing",
	_pf_s3rsk_fix, _pf_s3rsk_url) if {
	some name in resources_of_type("AWS::S3::Bucket")
	some rule in flatten_list(name, "Properties.ReplicationConfiguration.Rules")
	is_object(rule.value)
	ssc := object.get(rule.value, "SourceSelectionCriteria", {})
	is_object(ssc)
	sse := object.get(ssc, "SseKmsEncryptedObjects", {})
	is_object(sse)
	object.get(sse, "Status", "") == "Enabled"
	d := object.get(rule.value, "Destination", {})
	is_object(d)
	enc := object.get(d, "EncryptionConfiguration", {})
	is_object(enc)
	object.get(enc, "ReplicaKmsKeyID", "__pf_absent") == "__pf_absent"
}
