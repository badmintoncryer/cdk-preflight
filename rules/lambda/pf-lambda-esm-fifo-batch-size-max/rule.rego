package cdk_preflight

import rego.v1

_pf_lefbs_fix := "Lower BatchSize to 10 or less for a FIFO queue"

_pf_lefbs_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-lambda-eventsourcemapping.html"

violation contains make_diag_full("pf-lambda-esm-fifo-batch-size-max", "ERROR", name,
	"Properties.BatchSize",
	sprintf("BatchSize %v on a FIFO queue; ordering is per message group, so Lambda caps FIFO batches at 10", [n]),
	_pf_lefbs_fix, _pf_lefbs_url) if {
	some name in _pf_lam_esm
	q := resolve(name, "Properties.EventSourceArn")
	_pf_lam_lit(q)
	endswith(q, ".fifo")
	n := to_number(_pf_lam_get(name, "BatchSize"))
	n > 10
}
