package cdk_preflight

import rego.v1

_pf_s3lid_fix := "Give every lifecycle rule its own Id"

_pf_s3lid_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-s3-bucket-lifecycleconfiguration.html"

violation contains make_diag_full("pf-s3-lifecycle-rule-id-duplicate", "ERROR", name,
	sprintf("Properties.LifecycleConfiguration.Rules.%d.Id", [r2.index]),
	sprintf("lifecycle rule id '%v' is used by rule %d as well; ids must be unique within the configuration", [id, r1.index]),
	_pf_s3lid_fix, _pf_s3lid_url) if {
	some name in resources_of_type("AWS::S3::Bucket")
	some r1 in flatten_list(name, "Properties.LifecycleConfiguration.Rules")
	some r2 in flatten_list(name, "Properties.LifecycleConfiguration.Rules")
	r1.index < r2.index
	is_object(r1.value)
	is_object(r2.value)
	id := object.get(r1.value, "Id", "")
	id != ""
	id == object.get(r2.value, "Id", "")
}
