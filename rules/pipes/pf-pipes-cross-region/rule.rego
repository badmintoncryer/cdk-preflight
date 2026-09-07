package cdk_preflight

import rego.v1

# "Creating cross-region pipe is not permitted." — both ends must sit in the
# pipe's own Region. Measured 2026-09-07, pipes:CreatePipe, us-east-1.
_pf_pipereg_region(arn) := parts[3] if {
	parts := split(arn, ":")
	count(parts) > 3
	parts[3] != ""
}

violation contains make_diag_full("pf-pipes-cross-region", "ERROR", name,
	sprintf("Properties.%s", [prop]),
	sprintf("The pipe %s is in '%s' but the pipe deploys to '%s'; CreatePipe fails with \"Creating cross-region pipe is not permitted\"", [lower(prop), r, region]),
	sprintf("Use a %s in the pipe's own Region", [lower(prop)]),
	"https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-pipes.html") if {
	some name in resources_of_type("AWS::Pipes::Pipe")
	region := data.cdk_preflight.deploy_region
	some prop in ["Source", "Target"]
	arn := resolve(name, sprintf("Properties.%s", [prop]))
	is_string(arn)
	r := _pf_pipereg_region(arn)
	r != region
}
