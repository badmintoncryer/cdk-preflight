package cdk_preflight

import rego.v1

_pf_ledcr_fix := "Point EventSourceArn at a stream in the deploy region"

_pf_ledcr_url := "https://docs.aws.amazon.com/lambda/latest/dg/services-dynamodb-eventsourcemapping.html"

violation contains make_diag_full("pf-lambda-esm-ddb-cross-region", "ERROR", name,
	"Properties.EventSourceArn",
	sprintf("DynamoDB stream region '%v' is not the deploy region '%v'; cross-region stream triggers are not supported", [parts[3], region]),
	_pf_ledcr_fix, _pf_ledcr_url) if {
	region := data.cdk_preflight.deploy_region
	some name in _pf_lam_esm
	parts := _pf_lam_arn(resolve(name, "Properties.EventSourceArn"))
	parts[2] == "dynamodb"
	parts[3] != region
}
