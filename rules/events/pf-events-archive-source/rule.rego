package cdk_preflight

import rego.v1

# An archive records one event bus, in its own Region. Measured 2026-09-07,
# events:CreateArchive, us-east-1: an SQS ARN fails the eventSourceArn
# pattern, and a bus in us-west-2 is reported as "Event bus <name> does not
# exist" even when that bus really exists there — isolated by creating the
# bus in us-west-2 and confirming the same-Region control is accepted.
_pf_evarch_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-events-archive.html"

_pf_evarch_arn(name) := a if {
	a := resolve(name, "Properties.SourceArn")
	is_string(a)
	startswith(a, "arn:")
}

violation contains make_diag_full("pf-events-archive-source", "ERROR", name,
	"Properties.SourceArn",
	sprintf("'%s' is not an event bus; CreateArchive rejects it because eventSourceArn must be an event bus ARN", [arn]),
	"Point SourceArn at an AWS::Events::EventBus ARN",
	_pf_evarch_url) if {
	some name in resources_of_type("AWS::Events::Archive")
	arn := _pf_evarch_arn(name)
	not contains(arn, ":event-bus/")
}

violation contains make_diag_full("pf-events-archive-source", "ERROR", name,
	"Properties.SourceArn",
	sprintf("The event bus is in '%s' but the archive deploys to '%s'; CreateArchive fails with \"Event bus ... does not exist\" because it only looks in its own Region", [r, region]),
	"Archive a bus in the archive's own Region",
	_pf_evarch_url) if {
	some name in resources_of_type("AWS::Events::Archive")
	region := data.cdk_preflight.deploy_region
	arn := _pf_evarch_arn(name)
	contains(arn, ":event-bus/")
	parts := split(arn, ":")
	count(parts) > 3
	r := parts[3]
	r != ""
	r != region
}
