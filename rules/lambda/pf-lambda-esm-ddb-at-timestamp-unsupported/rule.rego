package cdk_preflight

import rego.v1

_pf_ledat_fix := "Use TRIM_HORIZON or LATEST for a DynamoDB stream"

_pf_ledat_url := "https://docs.aws.amazon.com/lambda/latest/api/API_CreateEventSourceMapping.html"

violation contains make_diag_full("pf-lambda-esm-ddb-at-timestamp-unsupported", "ERROR", name,
	"Properties.StartingPosition",
	"StartingPosition AT_TIMESTAMP on a DynamoDB stream; DynamoDB Streams shards have no timestamp index, so only TRIM_HORIZON and LATEST are accepted",
	_pf_ledat_fix, _pf_ledat_url) if {
	some name in _pf_lam_esm
	_pf_lam_is(name, "dynamodb")
	resolve(name, "Properties.StartingPosition") == "AT_TIMESTAMP"
}
