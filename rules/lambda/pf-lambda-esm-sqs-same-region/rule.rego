package cdk_preflight

import rego.v1

_pf_lessr_fix := "Point EventSourceArn at a queue in the deploy region"

_pf_lessr_url := "https://docs.aws.amazon.com/lambda/latest/dg/services-sqs-configure.html"

violation contains make_diag_full("pf-lambda-esm-sqs-same-region", "ERROR", name,
	"Properties.EventSourceArn",
	sprintf("source queue region '%v' is not the deploy region '%v'; Lambda only polls queues in its own region and the mapping create is rejected", [parts[3], region]),
	_pf_lessr_fix, _pf_lessr_url) if {
	region := data.cdk_preflight.deploy_region
	some name in _pf_lam_esm
	parts := _pf_lam_arn(resolve(name, "Properties.EventSourceArn"))
	parts[2] == "sqs"
	parts[3] != region
}
