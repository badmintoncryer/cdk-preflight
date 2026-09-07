package cdk_preflight

import rego.v1

_pf_ldnf_fix := "Point DeadLetterConfig.TargetArn at a standard SQS queue or SNS topic"

_pf_ldnf_url := "https://docs.aws.amazon.com/lambda/latest/dg/invocation-async-retain-records.html"

violation contains make_diag_full("pf-lambda-dlq-no-fifo", "ERROR", name,
	"Properties.DeadLetterConfig.TargetArn",
	sprintf("FIFO dead-letter target '%v'; asynchronous invocation records carry no message group and Lambda accepts standard queues and topics only", [arn]),
	_pf_ldnf_fix, _pf_ldnf_url) if {
	some name in _pf_lam_fn
	props := _pf_lam_props(name)
	arn := _pf_lam_str(_pf_lam_obj(props, "DeadLetterConfig"), "TargetArn")
	_pf_lam_lit(arn)
	endswith(arn, ".fifo")
}
