package cdk_preflight

import rego.v1

_pf_asgsctz_url := "https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_PutScheduledUpdateGroupAction.html"

_pf_asgsctz_area := {
	"Africa", "America", "Antarctica", "Arctic", "Asia", "Atlantic", "Australia",
	"Brazil", "Canada", "Chile", "Etc", "Europe", "Indian", "Mexico", "Pacific", "US",
}

_pf_asgsctz_ok(v) if v in ["UTC", "GMT", "Local"]

_pf_asgsctz_ok(v) if {
	parts := split(v, "/")
	count(parts) >= 2
	parts[0] in _pf_asgsctz_area
	regex.match("^[A-Za-z][A-Za-z0-9_+-]*(/[A-Za-z0-9_+-]+){1,2}$", v)
}

violation contains make_diag_full("pf-asg-sched-timezone-iana-only", "ERROR", name,
	"Properties.TimeZone",
	sprintf("TimeZone '%s' is not an IANA zone name; abbreviations and UTC offsets are rejected with \"Time zone specified does not conform to standardized time zones found in IANA Time Zone Database\"", [v]),
	"Use a canonical IANA name such as Asia/Tokyo or America/New_York", _pf_asgsctz_url) if {
	some name in resources_of_type("AWS::AutoScaling::ScheduledAction")
	v := resolve(name, "Properties.TimeZone")
	_pf_aslib_lit(v)
	not _pf_asgsctz_ok(v)
}
