package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-synthetics-canary-schedule-rate-unit", "ERROR", name,
	"Properties.Schedule.Expression",
	sprintf("Schedule.Expression '%s' spells the unit '%s'; a canary's rate() only accepts minute, minutes or hour (not the plural 'hours', and no day or week), and CreateCanary answers \"Invalid Schedule Expression.\"", [expr, r[1]]),
	"Write the interval as rate(<n> minutes) or rate(1 hour)",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-synthetics-canary-schedule.html") if {
	some name in resources_of_type("AWS::Synthetics::Canary")
	expr := resolve(name, "Properties.Schedule.Expression")
	r := _pf_synlib_rate(expr)
	not r[1] in _pf_synlib_rate_units
}
