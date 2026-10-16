package cdk_preflight

import rego.v1

# EventBridge Scheduler assumes Target.RoleArn for every target, and
# CreateSchedule rejects a role whose trust policy does not name
# scheduler.amazonaws.com, which rolls the stack back after the role and
# everything before the schedule were created.
violation contains make_diag_full("pf-scheduler-target-role-trust", "ERROR", name,
	"Properties.Target.RoleArn",
	sprintf("The schedule uses role '%s', whose trust policy does not let scheduler.amazonaws.com assume it; CreateSchedule rejects it", [role]),
	sprintf("Add scheduler.amazonaws.com to the Service principals of %s's AssumeRolePolicyDocument", [role]),
	"https://docs.aws.amazon.com/scheduler/latest/UserGuide/setting-up.html#setting-up-execution-role") if {
	some name in resources_of_type("AWS::Scheduler::Schedule")
	t := input.resources[name].properties.Target
	is_object(t)
	role := _pf_iamlib_role_without_service(object.get(t, "RoleArn", null), "scheduler.amazonaws.com")
}
