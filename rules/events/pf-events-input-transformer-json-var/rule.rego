package cdk_preflight

import rego.v1

# <aws.events.event.json> substitutes the raw event document, so it is only
# accepted when the InputTemplate is itself a JSON object. Measured
# 2026-09-07, events:PutTargets, us-east-1: '{"e": <aws.events.event.json>}'
# is accepted, while '[<aws.events.event.json>]' and a quoted string holding
# it both give "InputTemplate for target t1 contains placeholder
# aws.events.event.json valid only for JSON template." Ordinary placeholders
# are unaffected — '"event was <k> today"' is accepted.
violation contains make_diag_full("pf-events-input-transformer-json-var", "ERROR", name,
	sprintf("Properties.Targets.%d.InputTransformer.InputTemplate", [t.index]),
	sprintf("<aws.events.event.json> needs an InputTemplate that is a JSON object; PutTargets fails with \"InputTemplate for target %s contains placeholder aws.events.event.json valid only for JSON template\"", [tid]),
	"Write the template as {\"key\": <aws.events.event.json>}",
	"https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-transform-target-input.html") if {
	some name in resources_of_type("AWS::Events::Rule")
	some t in flatten_list(name, "Properties.Targets")
	is_object(t.value)
	it := object.get(t.value, "InputTransformer", null)
	is_object(it)
	tmpl := object.get(it, "InputTemplate", null)
	is_string(tmpl)
	contains(tmpl, "<aws.events.event.json>")
	not startswith(trim_space(tmpl), "{")
	tid := object.get(t.value, "Id", "<target>")
}
