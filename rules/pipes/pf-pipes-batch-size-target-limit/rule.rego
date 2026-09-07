package cdk_preflight

import rego.v1

# "The configured batch size N is greater than the max supported ..." — the
# source batch size is capped by what the target can take in one call.
# Measured 2026-09-07, pipes:CreatePipe, us-east-1: sqs, sns and an event bus
# accept 10 and refuse 11; Step Functions takes more, so it is not listed.
_pf_pipebs_max := {"sqs": 10, "sns": 10, "events": 10}

_pf_pipebs_target(name) := parts[2] if {
	arn := resolve(name, "Properties.Target")
	is_string(arn)
	parts := split(arn, ":")
	count(parts) > 2
}

violation contains make_diag_full("pf-pipes-batch-size-target-limit", "ERROR", name,
	sprintf("Properties.SourceParameters.%s.BatchSize", [block]),
	sprintf("BatchSize %v exceeds the %v events a %s target accepts per call; CreatePipe fails with \"The configured batch size %v is greater than the max supported\"", [bs, max, svc, bs]),
	sprintf("Lower BatchSize to %v or less", [max]),
	"https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-pipes-batching-concurrency.html") if {
	some name in resources_of_type("AWS::Pipes::Pipe")
	svc := _pf_pipebs_target(name)
	max := _pf_pipebs_max[svc]
	sp := input.resources[name].properties.SourceParameters
	is_object(sp)
	some block, cfg in sp
	is_object(cfg)
	bs := to_number(object.get(cfg, "BatchSize", "__pf_absent"))
	bs > max
}
