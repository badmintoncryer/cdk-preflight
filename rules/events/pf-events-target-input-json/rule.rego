package cdk_preflight

import rego.v1

# Target Input is passed to the target verbatim and must be valid JSON;
# PutTargets fails with "JSON syntax error in input for target <id>".
# A JSON scalar is fine ("\"hello\"" deploys), a bare word is not.
# Measured 2026-09-07, events:PutTargets, us-east-1.
violation contains make_diag_full("pf-events-target-input-json", "ERROR", name,
	sprintf("Properties.Targets.%d.Input", [t.index]),
	sprintf("Input for target '%s' is not valid JSON; PutTargets fails with \"JSON syntax error in input for target %s\"", [tid, tid]),
	"Write Input as a JSON value (an object, array, quoted string, number, boolean or null)",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-rule-target.html") if {
	some name in resources_of_type("AWS::Events::Rule")
	some t in flatten_list(name, "Properties.Targets")
	is_object(t.value)
	inp := object.get(t.value, "Input", null)
	is_string(inp)
	not json.is_valid(inp)
	tid := object.get(t.value, "Id", "<target>")
}
