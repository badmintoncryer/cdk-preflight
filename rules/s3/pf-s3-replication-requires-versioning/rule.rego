package cdk_preflight

import rego.v1

# 違反にするのは VersioningConfiguration が文字どおり不在（input.resources で
# 証明、AGENTS.md 参照）か、Status がリテラルで "Suspended" のときだけ。
# 未解決トークンは OK 扱い（resolve() はキー不在と未解決の両方で undefined に
# なるため、`not resolve(...)` では不在を証明できない — 2026-09-02 実測）。
_pf_s3repl_bad_versioning(name) if {
	props := input.resources[name].properties
	is_object(props)
	object.get(props, "VersioningConfiguration", "__pf_absent") == "__pf_absent"
}

_pf_s3repl_bad_versioning(name) if {
	resolve(name, "Properties.VersioningConfiguration.Status") == "Suspended"
}

violation contains make_diag_full("pf-s3-replication-requires-versioning", "ERROR", name,
	"Properties.ReplicationConfiguration",
	"ReplicationConfiguration is set but bucket versioning is not enabled; S3 rejects the replication configuration at deploy time (InvalidRequest: Versioning must be 'Enabled' on the bucket)",
	"Set VersioningConfiguration.Status to 'Enabled' on the source bucket",
	"https://docs.aws.amazon.com/AmazonS3/latest/userguide/replication-requirements.html") if {
	some name in resources_of_type("AWS::S3::Bucket")
	is_object(resolve(name, "Properties.ReplicationConfiguration"))
	_pf_s3repl_bad_versioning(name)
}
