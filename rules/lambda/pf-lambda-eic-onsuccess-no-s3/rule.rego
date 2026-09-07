package cdk_preflight

import rego.v1

_pf_leios_fix := "Use SQS, SNS, Lambda or EventBridge for OnSuccess, and keep S3 for OnFailure"

_pf_leios_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lambda-eventinvokeconfig.html"

violation contains make_diag_full("pf-lambda-eic-onsuccess-no-s3", "ERROR", name,
	"Properties.DestinationConfig.OnSuccess.Destination",
	"an S3 bucket as the OnSuccess destination; S3 takes failed-invocation records only and the config create is rejected",
	_pf_leios_fix, _pf_leios_url) if {
	some [name, side, dest] in _pf_lam_eic_dest
	side == "OnSuccess"
	parts := _pf_lam_arn(dest)
	parts[2] == "s3"
}
