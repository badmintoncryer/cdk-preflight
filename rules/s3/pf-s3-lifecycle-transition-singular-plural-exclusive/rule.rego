package cdk_preflight

import rego.v1

_pf_s3lsp_fix := "Keep only Transitions (or only NoncurrentVersionTransitions) in the rule"

_pf_s3lsp_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-s3-bucket-lifecycleconfiguration.html"

violation contains make_diag_full("pf-s3-lifecycle-transition-singular-plural-exclusive", "ERROR", name,
	sprintf("Properties.LifecycleConfiguration.Rules.%d.%v", [rule.index, pair[0]]),
	sprintf("the rule sets both %v and %v; S3 accepts only one of the pair", [pair[0], pair[1]]),
	_pf_s3lsp_fix, _pf_s3lsp_url) if {
	some name in resources_of_type("AWS::S3::Bucket")
	some rule in flatten_list(name, "Properties.LifecycleConfiguration.Rules")
	is_object(rule.value)
	some pair in [["Transition", "Transitions"], ["NoncurrentVersionTransition", "NoncurrentVersionTransitions"]]
	object.get(rule.value, pair[0], "__pf_absent") != "__pf_absent"
	object.get(rule.value, pair[1], "__pf_absent") != "__pf_absent"
}
