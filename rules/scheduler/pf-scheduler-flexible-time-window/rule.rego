package cdk_preflight

import rego.v1

# "MaximumWindowInMinutes must not be provided when FlexibleTimeWindowMode is
# set to OFF." Measured 2026-09-07, scheduler:CreateSchedule, us-east-1.
violation contains make_diag_full("pf-scheduler-flexible-time-window", "ERROR", name,
	"Properties.FlexibleTimeWindow.MaximumWindowInMinutes",
	"FlexibleTimeWindow Mode is OFF, so a window length is meaningless; CreateSchedule fails with \"MaximumWindowInMinutes must not be provided when FlexibleTimeWindowMode is set to OFF\"",
	"Drop MaximumWindowInMinutes, or set Mode to FLEXIBLE",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-scheduler-schedule-flexibletimewindow.html") if {
	some name in resources_of_type("AWS::Scheduler::Schedule")
	ftw := input.resources[name].properties.FlexibleTimeWindow
	is_object(ftw)
	object.get(ftw, "Mode", null) == "OFF"
	object.get(ftw, "MaximumWindowInMinutes", "__pf_absent") != "__pf_absent"
}
