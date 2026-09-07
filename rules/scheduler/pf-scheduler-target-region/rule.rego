package cdk_preflight

import rego.v1

# "The target ARN provided does not match the current region <region>."
# Measured 2026-09-07, scheduler:CreateSchedule, us-east-1, for a Lambda
# function and for an event bus alike. Universal targets carry no Region
# segment and are skipped.
violation contains make_diag_full("pf-scheduler-target-region", "ERROR", name,
	"Properties.Target.Arn",
	sprintf("The target is in '%s' but the schedule deploys to '%s'; CreateSchedule fails with \"The target ARN provided does not match the current region %s\"", [r, region, region]),
	"Invoke a target in the schedule's own Region",
	"https://docs.aws.amazon.com/scheduler/latest/UserGuide/managing-targets.html") if {
	some name in resources_of_type("AWS::Scheduler::Schedule")
	region := data.cdk_preflight.deploy_region
	arn := resolve(name, "Properties.Target.Arn")
	is_string(arn)
	parts := split(arn, ":")
	count(parts) > 3
	r := parts[3]
	r != ""
	r != region
}
