package cdk_preflight

import rego.v1

_pf_s3bpv_fix := "Set PolicyDocument.Version to 2012-10-17"

_pf_s3bpv_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-s3-bucketpolicy.html"

violation contains make_diag_full("pf-s3-bucket-policy-version", "ERROR", p, "Properties.PolicyDocument.Version",
	sprintf("PolicyDocument.Version is '%v'; IAM only knows 2012-10-17 and 2008-10-17", [v]),
	_pf_s3bpv_fix, _pf_s3bpv_url) if {
	some p in resources_of_type("AWS::S3::BucketPolicy")
	v := _pf_s3lib_lit(resolve(p, "Properties.PolicyDocument.Version"))
	not v in {"2012-10-17", "2008-10-17"}
}
