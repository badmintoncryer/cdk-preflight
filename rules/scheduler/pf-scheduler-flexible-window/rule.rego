package cdk_preflight

import rego.v1

_pf_schfw_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-scheduler-schedule-flexibletimewindow.html"

_pf_schfw_ftw(name) := ftw if {
	ftw := resolve(name, "Properties.FlexibleTimeWindow")
	is_object(ftw)
}

violation contains make_diag_full("pf-scheduler-flexible-window", "ERROR", name,
	"Properties.FlexibleTimeWindow.MaximumWindowInMinutes",
	"FlexibleTimeWindow.Mode is FLEXIBLE but MaximumWindowInMinutes is missing; CreateSchedule fails with \"MaximumWindowInMinutes must be provided when FlexibleTimeWindowMode is set to FLEXIBLE\"",
	"Set MaximumWindowInMinutes (1-1440), or switch Mode to OFF",
	_pf_schfw_url) if {
	some name in resources_of_type("AWS::Scheduler::Schedule")
	ftw := _pf_schfw_ftw(name)
	object.get(ftw, "Mode", null) == "FLEXIBLE"
	object.get(ftw, "MaximumWindowInMinutes", "__pf_absent") == "__pf_absent"
}

violation contains make_diag_full("pf-scheduler-flexible-window", "ERROR", name,
	"Properties.FlexibleTimeWindow.MaximumWindowInMinutes",
	"FlexibleTimeWindow.Mode is OFF but MaximumWindowInMinutes is set; CreateSchedule fails with \"MaximumWindowInMinutes must not be provided when FlexibleTimeWindowMode is set to OFF\"",
	"Drop MaximumWindowInMinutes, or switch Mode to FLEXIBLE",
	_pf_schfw_url) if {
	some name in resources_of_type("AWS::Scheduler::Schedule")
	ftw := _pf_schfw_ftw(name)
	object.get(ftw, "Mode", null) == "OFF"
	object.get(ftw, "MaximumWindowInMinutes", "__pf_absent") != "__pf_absent"
}
