package cdk_preflight

import rego.v1

_pf_s3vsr_fix := "Set VersioningConfiguration.Status to Enabled on the replication source bucket"

_pf_s3vsr_url := "https://docs.aws.amazon.com/AmazonS3/latest/userguide/replication-add-config.html"

violation contains make_diag_full("pf-s3-versioning-suspended-with-replication", "ERROR", name,
	"Properties.VersioningConfiguration.Status",
	"the bucket suspends versioning while a ReplicationConfiguration is attached; S3 requires versioning to stay enabled on a replication source",
	_pf_s3vsr_fix, _pf_s3vsr_url) if {
	some name in resources_of_type("AWS::S3::Bucket")
	resolve(name, "Properties.VersioningConfiguration.Status") == "Suspended"
	is_object(resolve(name, "Properties.ReplicationConfiguration"))
}
