package cdk_preflight

import rego.v1

# The ten action fields, verbatim from the service error. A field whose value
# is an unresolvable intrinsic still counts as present (fail closed).
_pf_s3lna_actions := {
	"AbortIncompleteMultipartUpload",
	"ExpirationDate",
	"ExpirationInDays",
	"ExpiredObjectDeleteMarker",
	"NoncurrentVersionExpiration",
	"NoncurrentVersionExpirationInDays",
	"NoncurrentVersionTransition",
	"NoncurrentVersionTransitions",
	"Transition",
	"Transitions",
}

_pf_s3lna_has_action(rule) if {
	some k in _pf_s3lna_actions
	object.get(rule, k, "__pf_absent") != "__pf_absent"
}

violation contains make_diag_full("pf-s3-lifecycle-rule-no-action", "ERROR", name,
	sprintf("Properties.LifecycleConfiguration.Rules.%d", [r.index]),
	"The lifecycle rule specifies no action; S3 rejects it with \"At least one of [ExpirationDate,ExpirationInDays,AbortIncompleteMultipartUpload,Transition,...] needs to be specified\"",
	"Add an expiration, transition, or abort-incomplete-multipart-upload action to the rule, or remove the rule",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-s3-bucket-rule.html") if {
	some name in resources_of_type("AWS::S3::Bucket")
	some r in flatten_list(name, "Properties.LifecycleConfiguration.Rules")
	is_object(r.value)
	not _pf_s3lna_has_action(r.value)
}
