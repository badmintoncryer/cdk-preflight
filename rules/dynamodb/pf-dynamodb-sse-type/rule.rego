package cdk_preflight

import rego.v1

_pf_ddbsse_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-dynamodb-table-ssespecification.html"

# The engine reports the enum half as W3030 (WARN) only; the
# "SSEEnabled: false with an SSEType" half is entirely silent
# (measured 2026-09-08, 1.7.0-beta).
violation contains make_diag_full("pf-dynamodb-sse-type", "ERROR", name,
	"Properties.SSESpecification.SSEType",
	sprintf("SSEType '%s' is not a table encryption type; CreateTable fails with \"SSEType %s is not supported\" (KMS is the only value)", [st, st]),
	"Set SSEType to KMS, or drop it and let the table use the default AWS owned key",
	_pf_ddbsse_url) if {
	some name in resources_of_type("AWS::DynamoDB::Table")
	st := resolve(name, "Properties.SSESpecification.SSEType")
	is_string(st)
	st != "KMS"
}

violation contains make_diag_full("pf-dynamodb-sse-type", "ERROR", name,
	"Properties.SSESpecification.SSEType",
	"SSEType is set while SSEEnabled is false; CreateTable fails with \"SSEType can not be specified if Enabled is false\"",
	"Remove SSEType (and KMSMasterKeyId) when SSEEnabled is false, or set SSEEnabled to true",
	_pf_ddbsse_url) if {
	some name in resources_of_type("AWS::DynamoDB::Table")
	resolve(name, "Properties.SSESpecification.SSEEnabled") == false
	is_string(resolve(name, "Properties.SSESpecification.SSEType"))
}
