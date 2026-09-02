package cdk_preflight

import rego.v1

# Object Lock force-enables versioning at creation, so a template that also
# suspends versioning contradicts itself and the handler's PutBucketVersioning
# call is rejected. Fires only on a literal "Suspended".
violation contains make_diag_full("pf-s3-objectlock-versioning-suspended", "ERROR", name,
	"Properties.VersioningConfiguration.Status",
	"ObjectLockEnabled is true but VersioningConfiguration suspends versioning; S3 rejects it with \"An Object Lock configuration is present on this bucket, so the versioning state cannot be changed.\"",
	"Set VersioningConfiguration.Status to 'Enabled' (or drop it — Object Lock enables versioning itself)",
	"https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html") if {
	some name in resources_of_type("AWS::S3::Bucket")
	coerce_to_bool(resolve(name, "Properties.ObjectLockEnabled")) == true
	resolve(name, "Properties.VersioningConfiguration.Status") == "Suspended"
}
