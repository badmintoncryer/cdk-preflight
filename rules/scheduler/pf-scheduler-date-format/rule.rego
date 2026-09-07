package cdk_preflight

import rego.v1

# The CloudFormation handler demands milliseconds on StartDate and EndDate:
# "Invalid request provided: EndDate needs to follow the format
# yyyy-MM-ddTHH:mm:ss.SSSZ". Measured 2026-09-07 (bench, us-east-1). The
# scheduler:CreateSchedule API itself accepts the second-precision form, so
# this is a handler-only constraint that no API probe would surface.
#
# Only the measured shape — a timestamp with no fractional part — is
# reported, so other spellings (offsets, other precisions) stay silent
# rather than risk a false positive.
violation contains make_diag_full("pf-scheduler-date-format", "ERROR", name,
	sprintf("Properties.%s", [prop]),
	sprintf("'%s' has no milliseconds; the CloudFormation handler fails with \"%s needs to follow the format yyyy-MM-ddTHH:mm:ss.SSSZ\"", [v, prop]),
	sprintf("Write %s as yyyy-MM-ddTHH:mm:ss.SSSZ, e.g. 2030-01-01T00:00:00.000Z", [prop]),
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-scheduler-schedule.html") if {
	some name in resources_of_type("AWS::Scheduler::Schedule")
	some prop in ["StartDate", "EndDate"]
	v := resolve(name, sprintf("Properties.%s", [prop]))
	is_string(v)
	regex.match(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z?$`, v)
}
