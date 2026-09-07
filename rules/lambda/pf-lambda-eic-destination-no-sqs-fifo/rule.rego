package cdk_preflight

import rego.v1

_pf_leidq_fix := "Send asynchronous invocation results to a standard SQS queue"

_pf_leidq_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-lambda-eventinvokeconfig-destinationconfig.html"

violation contains make_diag_full("pf-lambda-eic-destination-no-sqs-fifo", "ERROR", name,
	sprintf("Properties.DestinationConfig.%v.Destination", [side]),
	sprintf("%v destination '%v' is a FIFO queue; asynchronous invocation destinations are delivered without ordering guarantees and Lambda only accepts standard queues", [side, dest]),
	_pf_leidq_fix, _pf_leidq_url) if {
	some [name, side, dest] in _pf_lam_eic_dest
	parts := _pf_lam_arn(dest)
	parts[2] == "sqs"
	endswith(dest, ".fifo")
}
