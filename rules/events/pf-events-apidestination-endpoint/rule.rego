package cdk_preflight

import rego.v1

# An API destination posts over HTTPS and can only use a connection from its
# own Region. Measured 2026-09-07, events:CreateApiDestination, us-east-1: an
# http:// endpoint gives "Parameter InvocationEndpoint is not valid. Reason:
# Endpoint '...' is not valid", and a us-west-2 connection ARN gives
# "Invalid ARN: 'arn:aws:events:us-west-2:...'".
_pf_evapid_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-events-apidestination.html"

violation contains make_diag_full("pf-events-apidestination-endpoint", "ERROR", name,
	"Properties.InvocationEndpoint",
	sprintf("'%s' is not HTTPS; CreateApiDestination fails with \"Parameter InvocationEndpoint is not valid\"", [ep]),
	"Use an https:// invocation endpoint",
	_pf_evapid_url) if {
	some name in resources_of_type("AWS::Events::ApiDestination")
	ep := resolve(name, "Properties.InvocationEndpoint")
	is_string(ep)
	not startswith(ep, "https://")
}

violation contains make_diag_full("pf-events-apidestination-endpoint", "ERROR", name,
	"Properties.ConnectionArn",
	sprintf("The connection is in '%s' but the API destination deploys to '%s'; CreateApiDestination fails with \"Invalid ARN: '%s'\"", [r, region, arn]),
	"Use a connection in the API destination's own Region",
	_pf_evapid_url) if {
	some name in resources_of_type("AWS::Events::ApiDestination")
	region := data.cdk_preflight.deploy_region
	arn := resolve(name, "Properties.ConnectionArn")
	is_string(arn)
	parts := split(arn, ":")
	count(parts) > 3
	r := parts[3]
	r != ""
	r != region
}
