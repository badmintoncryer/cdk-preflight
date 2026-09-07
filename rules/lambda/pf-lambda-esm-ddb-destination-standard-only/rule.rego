package cdk_preflight

import rego.v1

_pf_ledds_fix := "Point OnFailure.Destination at a standard SQS queue or SNS topic"

_pf_ledds_url := "https://docs.aws.amazon.com/lambda/latest/dg/services-ddb-params.html"

violation contains make_diag_full("pf-lambda-esm-ddb-destination-standard-only", "ERROR", name,
	"Properties.DestinationConfig.OnFailure.Destination",
	"the on-failure destination is a FIFO queue or topic; Lambda writes failure records out of order, so only standard queues and topics are accepted",
	_pf_ledds_fix, _pf_ledds_url) if {
	some name in _pf_lam_esm
	d := resolve(name, "Properties.DestinationConfig.OnFailure.Destination")
	_pf_lam_lit(d)
	endswith(d, ".fifo")
}
