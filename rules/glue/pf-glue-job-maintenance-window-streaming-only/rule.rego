package cdk_preflight

import rego.v1

# Streaming jobs run indefinitely, so only they have a restart window.
violation contains make_diag_full("pf-glue-job-maintenance-window-streaming-only", "ERROR", name,
	"Properties.MaintenanceWindow",
	sprintf("MaintenanceWindow %v on a %v job; the window only applies to gluestreaming jobs", [mw, cmd]),
	"Remove MaintenanceWindow, or change Command.Name to gluestreaming",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-job.html") if {
	some name in resources_of_type("AWS::Glue::Job")
	mw := _pf_gluelib_get(name, "MaintenanceWindow")
	cmd := _pf_gluelib_command_name(name)
	cmd != "gluestreaming"
}
