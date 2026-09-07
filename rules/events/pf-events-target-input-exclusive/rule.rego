package cdk_preflight

import rego.v1

# "Only one of Input, InputPath, or InputTransformer must be provided for
# target <id>" — measured 2026-09-07, events:PutTargets, us-east-1.
violation contains make_diag_full("pf-events-target-input-exclusive", "ERROR", name,
	sprintf("Properties.Targets.%d", [t.index]),
	sprintf("Target '%s' sets %v; PutTargets fails with \"Only one of Input, InputPath, or InputTransformer must be provided for target %s\"", [tid, sort(present), tid]),
	"Keep only one of Input, InputPath and InputTransformer",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-rule-target.html") if {
	some name in resources_of_type("AWS::Events::Rule")
	some t in flatten_list(name, "Properties.Targets")
	is_object(t.value)
	present := {k | some k in ["Input", "InputPath", "InputTransformer"]; object.get(t.value, k, "__pf_absent") != "__pf_absent"}
	count(present) > 1
	tid := object.get(t.value, "Id", "<target>")
}
