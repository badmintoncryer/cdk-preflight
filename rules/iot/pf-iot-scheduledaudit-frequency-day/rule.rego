package cdk_preflight

import rego.v1

# Each schema has the day properties and the frequency enum, but not the table
# that ties them together. UNSET_VALUE is a member of both day enums and means
# exactly what it says, so a daily audit carrying it is not carrying a day.
violation contains make_diag_full("pf-iot-scheduledaudit-frequency-day", "ERROR", name,
	"Properties.DayOfMonth",
	"the audit runs MONTHLY but sets no DayOfMonth; CreateScheduledAudit answers \"Invalid combination of frequency and day-of-week/day-of-month\"",
	"Add DayOfMonth (1-31 or LAST) for a monthly audit",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-iot-scheduledaudit.html") if {
	some name in resources_of_type("AWS::IoT::ScheduledAudit")
	_pf_iotlib_lit(name, "Properties.Frequency") == "MONTHLY"
	not _pf_iotlib_has(name, "DayOfMonth")
}

violation contains make_diag_full("pf-iot-scheduledaudit-frequency-day", "ERROR", name,
	"Properties.DayOfWeek",
	sprintf("the audit runs %s but sets no DayOfWeek; CreateScheduledAudit answers \"Invalid combination of frequency and day-of-week/day-of-month\"", [f]),
	"Add DayOfWeek (SUN-SAT) for a weekly or biweekly audit",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-iot-scheduledaudit.html") if {
	some name in resources_of_type("AWS::IoT::ScheduledAudit")
	f := _pf_iotlib_lit(name, "Properties.Frequency")
	f in {"WEEKLY", "BIWEEKLY"}
	not _pf_iotlib_has(name, "DayOfWeek")
}

violation contains make_diag_full("pf-iot-scheduledaudit-frequency-day", "ERROR", name,
	sprintf("Properties.%s", [day]),
	sprintf("the audit runs DAILY but also sets %s; CreateScheduledAudit answers \"Invalid combination of frequency and day-of-week/day-of-month\"", [day]),
	"Drop the day property from a daily audit",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-iot-scheduledaudit.html") if {
	some name in resources_of_type("AWS::IoT::ScheduledAudit")
	_pf_iotlib_lit(name, "Properties.Frequency") == "DAILY"
	some day in ["DayOfWeek", "DayOfMonth"]
	v := object.get(_pf_iotlib_props(name), day, "__pf_absent")
	is_string(v)
	v != "UNSET_VALUE"
}
