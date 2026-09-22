package cdk_preflight

import rego.v1

# ISO 8601 timestamps of the same shape compare correctly as strings (no
# time.parse_rfc3339_ns in this engine); mixed shapes do not match and skip.
_pf_rssase_iso(v) if regex.match(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?Z?$`, v)

violation contains make_diag_full("pf-redshift-scheduled-action-start-before-end", "ERROR", name,
	"Properties.StartTime",
	sprintf("StartTime %s is not earlier than EndTime %s; CreateScheduledAction rejects it (\"The StartTime must be earlier than EndTime.\")", [s, e]),
	"Set StartTime before EndTime, or drop one of them",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-redshift-scheduledaction.html") if {
	some name in resources_of_type("AWS::Redshift::ScheduledAction")
	s := _pf_redshiftlib_str(name, "StartTime")
	e := _pf_redshiftlib_str(name, "EndTime")
	_pf_rssase_iso(s)
	_pf_rssase_iso(e)
	s >= e
}
