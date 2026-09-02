package cdk_preflight

import rego.v1

# The destination side of what pf-s3-replication-requires-versioning checks on
# the source. Destination.Bucket is normally Fn::GetAtt/Ref to an in-template
# bucket; resolve() turns both into the target's logical ID, so the
# destination's own properties are readable. External destination ARNs resolve
# to strings that are not logical IDs and skip. Versioning is "not enabled"
# when VersioningConfiguration is literally absent (proven via
# input.resources, see AGENTS.md) or Status resolves to "Suspended"; an
# unresolvable Status skips.
_pf_s3rdv_bad_versioning(dest) if {
	props := input.resources[dest].properties
	is_object(props)
	object.get(props, "VersioningConfiguration", "__pf_absent") == "__pf_absent"
}

_pf_s3rdv_bad_versioning(dest) if {
	resolve(dest, "Properties.VersioningConfiguration.Status") == "Suspended"
}

violation contains make_diag_full("pf-s3-replication-dest-versioning", "ERROR", name,
	sprintf("Properties.ReplicationConfiguration.Rules.%d.Destination.Bucket", [r.index]),
	sprintf("Replication destination bucket '%s' does not have versioning enabled; S3 rejects the configuration with \"Destination bucket must have versioning enabled\"", [dest]),
	"Set VersioningConfiguration.Status to 'Enabled' on the destination bucket",
	"https://docs.aws.amazon.com/AmazonS3/latest/userguide/replication-requirements.html") if {
	some name in resources_of_type("AWS::S3::Bucket")
	some r in flatten_list(name, "Properties.ReplicationConfiguration.Rules")
	dest := resolve(name, sprintf("Properties.ReplicationConfiguration.Rules.%d.Destination.Bucket", [r.index]))
	is_string(dest)
	dest in resources_of_type("AWS::S3::Bucket")
	_pf_s3rdv_bad_versioning(dest)
}
