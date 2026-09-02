package cdk_preflight

import rego.v1

# ObjectLockConfiguration on its own does NOT require ObjectLockEnabled —
# S3 accepts Object Lock on an existing versioned bucket (bench s05b deployed
# clean). What it does require is versioning. When ObjectLockEnabled is true
# the bucket is created lock-enabled and versioning comes with it, so the rule
# fires only when lock-enablement is provably off (key literally absent or
# literal false) and versioning is provably not enabled.
_pf_s3olrv_no_lock_enabled(name) if {
	props := input.resources[name].properties
	is_object(props)
	object.get(props, "ObjectLockEnabled", "__pf_absent") == "__pf_absent"
}

_pf_s3olrv_no_lock_enabled(name) if {
	coerce_to_bool(resolve(name, "Properties.ObjectLockEnabled")) == false
}

_pf_s3olrv_bad_versioning(name) if {
	props := input.resources[name].properties
	is_object(props)
	object.get(props, "VersioningConfiguration", "__pf_absent") == "__pf_absent"
}

_pf_s3olrv_bad_versioning(name) if {
	resolve(name, "Properties.VersioningConfiguration.Status") == "Suspended"
}

violation contains make_diag_full("pf-s3-objectlock-requires-versioning", "ERROR", name,
	"Properties.ObjectLockConfiguration",
	"ObjectLockConfiguration is set on a bucket whose versioning is not enabled; S3 rejects it with \"Versioning must be 'Enabled' on the bucket to apply a Object Lock configuration\"",
	"Set VersioningConfiguration.Status to 'Enabled', or set ObjectLockEnabled: true to create the bucket lock-enabled",
	"https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html") if {
	some name in resources_of_type("AWS::S3::Bucket")
	is_object(resolve(name, "Properties.ObjectLockConfiguration"))
	_pf_s3olrv_no_lock_enabled(name)
	_pf_s3olrv_bad_versioning(name)
}
