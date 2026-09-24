package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-synthetics-canary-code-script-s3-exclusive", "ERROR", name,
	"Properties.Code.Script",
	"Code.Script and Code.S3Bucket/S3Key are both set; the canary's source comes from exactly one of the two and CreateCanary answers \"Both source location and source are specified.\"",
	"Keep either the inline Script or the S3Bucket/S3Key pair, not both",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-synthetics-canary-code.html") if {
	some name in resources_of_type("AWS::Synthetics::Canary")
	_pf_synlib_present(name, ["Code", "Script"])
	_pf_synlib_code_has_s3(name)
}
