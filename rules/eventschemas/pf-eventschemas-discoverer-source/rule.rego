package cdk_preflight

import rego.v1

# A discoverer watches one event bus, in its own Region. Measured 2026-09-07,
# schemas:CreateDiscoverer, us-east-1: an SQS ARN gives "Source ARN must be a
# valid event bus ARN" and a us-west-2 bus gives "Cross region Event Bus
# sourcing is not supported."
_pf_schdisc_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-eventschemas-discoverer.html"

_pf_schdisc_arn(name) := a if {
	a := resolve(name, "Properties.SourceArn")
	is_string(a)
	startswith(a, "arn:")
}

violation contains make_diag_full("pf-eventschemas-discoverer-source", "ERROR", name,
	"Properties.SourceArn",
	sprintf("'%s' is not an event bus; CreateDiscoverer fails with \"Source ARN must be a valid event bus ARN\"", [arn]),
	"Point SourceArn at an AWS::Events::EventBus ARN",
	_pf_schdisc_url) if {
	some name in resources_of_type("AWS::EventSchemas::Discoverer")
	arn := _pf_schdisc_arn(name)
	not contains(arn, ":event-bus/")
}

violation contains make_diag_full("pf-eventschemas-discoverer-source", "ERROR", name,
	"Properties.SourceArn",
	sprintf("The event bus is in '%s' but the discoverer deploys to '%s'; CreateDiscoverer fails with \"Cross region Event Bus sourcing is not supported\"", [r, region]),
	"Discover schemas from a bus in the discoverer's own Region",
	_pf_schdisc_url) if {
	some name in resources_of_type("AWS::EventSchemas::Discoverer")
	region := data.cdk_preflight.deploy_region
	arn := _pf_schdisc_arn(name)
	contains(arn, ":event-bus/")
	parts := split(arn, ":")
	count(parts) > 3
	r := parts[3]
	r != ""
	r != region
}
