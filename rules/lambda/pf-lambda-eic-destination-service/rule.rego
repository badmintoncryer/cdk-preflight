package cdk_preflight

import rego.v1

_pf_leids_fix := "Point the destination at an SQS queue, SNS topic, S3 bucket, Lambda function or EventBridge bus"

_pf_leids_url := "https://docs.aws.amazon.com/lambda/latest/api/API_PutFunctionEventInvokeConfig.html"

_pf_leids_ok := {"sqs", "sns", "s3", "lambda", "events"}

violation contains make_diag_full("pf-lambda-eic-destination-service", "ERROR", name,
	sprintf("Properties.DestinationConfig.%v.Destination", [side]),
	sprintf("%v destination names the '%v' service; Lambda delivers invocation records only to SQS, SNS, S3, Lambda and EventBridge", [side, parts[2]]),
	_pf_leids_fix, _pf_leids_url) if {
	some [name, side, dest] in _pf_lam_eic_dest
	parts := _pf_lam_arn(dest)
	not parts[2] in _pf_leids_ok
}
