package cdk_preflight

import rego.v1

_pf_s3xlna_fix := "Give the rule ExpirationInDays or AbortIncompleteMultipartUpload"

_pf_s3xlna_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3express-directorybucket-rule.html"

violation contains make_diag_full("pf-s3express-lifecycle-rule-no-action", "ERROR", name,
	sprintf("Properties.LifecycleConfiguration.Rules.%d", [r.index]),
	"the lifecycle rule declares neither ExpirationInDays nor AbortIncompleteMultipartUpload; a directory bucket rule must carry at least one action",
	_pf_s3xlna_fix, _pf_s3xlna_url) if {
	some name in resources_of_type("AWS::S3Express::DirectoryBucket")
	some r in flatten_list(name, "Properties.LifecycleConfiguration.Rules")
	is_object(r.value)
	object.get(r.value, "ExpirationInDays", "__pf_absent") == "__pf_absent"
	object.get(r.value, "AbortIncompleteMultipartUpload", "__pf_absent") == "__pf_absent"
}
