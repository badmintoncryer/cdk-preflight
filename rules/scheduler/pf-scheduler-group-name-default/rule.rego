package cdk_preflight

import rego.v1

# "This operation cannot be performed on schedule group default." — every
# account already has the default group and it cannot be created or modified.
# Measured 2026-09-07, scheduler:CreateScheduleGroup, us-east-1, with and
# without tags.
violation contains make_diag_full("pf-scheduler-group-name-default", "ERROR", name,
	"Properties.Name",
	"'default' is the account's built-in schedule group; CreateScheduleGroup fails with \"This operation cannot be performed on schedule group default\"",
	"Give the group its own name, or drop the resource and rely on the built-in group",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-scheduler-schedulegroup.html") if {
	some name in resources_of_type("AWS::Scheduler::ScheduleGroup")
	resolve(name, "Properties.Name") == "default"
}
