package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-synthetics-canary-code-source-required", "ERROR", name,
	"Properties.Code",
	"Code names no script: it carries neither Script (inline), nor S3Bucket/S3Key, nor SourceLocationArn. Every property of Code is optional on its own, so the schema cannot see that the canary has no code to run",
	"Add Code.Script, or Code.S3Bucket plus Code.S3Key, or Code.SourceLocationArn",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-synthetics-canary-code.html") if {
	some name in resources_of_type("AWS::Synthetics::Canary")
	_pf_synlib_present(name, ["Code"])
	not _pf_synlib_code_source(name)
}
