package cdk_preflight

import rego.v1

_pf_leidn_fix := "Send asynchronous invocation results to a standard SNS topic"

_pf_leidn_url := "https://docs.aws.amazon.com/lambda/latest/dg/invocation-async-retain-records.html"

violation contains make_diag_full("pf-lambda-eic-destination-no-sns-fifo", "ERROR", name,
	sprintf("Properties.DestinationConfig.%v.Destination", [side]),
	sprintf("%v destination '%v' is a FIFO topic; asynchronous invocation destinations are delivered without ordering guarantees and Lambda only accepts standard topics", [side, dest]),
	_pf_leidn_fix, _pf_leidn_url) if {
	some [name, side, dest] in _pf_lam_eic_dest
	parts := _pf_lam_arn(dest)
	parts[2] == "sns"
	endswith(dest, ".fifo")
}
