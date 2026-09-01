package cdk_preflight

import rego.v1

# Status がリテラルで "Suspended" 以外（= "Enabled"）、または未解決トークンなら OK 扱い。
# VersioningConfiguration 自体が無い / Suspended のときだけ違反にする。
_pf_s3repl_versioning_ok(name) if {
	s := resolve(name, "Properties.VersioningConfiguration.Status")
	not s == "Suspended"
}

violation contains make_diag_full("pf-s3-replication-requires-versioning", "ERROR", name,
	"Properties.ReplicationConfiguration",
	"ReplicationConfiguration is set but bucket versioning is not enabled; S3 rejects the replication configuration at deploy time (InvalidRequest: Versioning must be 'Enabled' on the bucket)",
	"Set VersioningConfiguration.Status to 'Enabled' on the source bucket",
	"https://docs.aws.amazon.com/AmazonS3/latest/userguide/replication-requirements.html") if {
	some name in resources_of_type("AWS::S3::Bucket")
	is_object(resolve(name, "Properties.ReplicationConfiguration"))
	not _pf_s3repl_versioning_ok(name)
}
