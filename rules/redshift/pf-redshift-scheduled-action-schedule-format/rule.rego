package cdk_preflight

import rego.v1

# Only the wrapper is judged (case-folded); the body of at()/cron() is left to the service.
violation contains make_diag_full("pf-redshift-scheduled-action-schedule-format", "ERROR", name,
	"Properties.Schedule",
	sprintf("Schedule '%s' is neither at(...) nor cron(...); CreateScheduledAction rejects it (\"Invalid schedule provided. The schedule expression must be encapsulated by cron() or at().\")", [s]),
	"Write at(yyyy-mm-ddThh:mm:ss) or cron(Minutes Hours Day-of-month Month Day-of-week Year)",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-redshift-scheduledaction.html") if {
	some name in resources_of_type("AWS::Redshift::ScheduledAction")
	s := _pf_redshiftlib_str(name, "Schedule")
	not regex.match(`^(at|cron)\(.+\)$`, lower(s))
}
