package cdk_preflight

import rego.v1

# Every <placeholder> in InputTemplate must be declared in InputPathsMap,
# except the aws.events.* predefined variables. An InputPathsMap that is an
# unresolvable intrinsic (normalized with __-prefixed marker keys) makes the
# declared set unknowable, so the rule skips.
_pf_evitp_placeholders(tmpl) := {substring(f, 1, count(f) - 2) | some f in regex.find_n(`<([A-Za-z0-9_.-]+)>`, tmpl, -1)}

_pf_evitp_plain_map(pm) if {
	is_object(pm)
	every k, _ in pm {
		not startswith(k, "__")
	}
}

violation contains make_diag_full("pf-events-input-transformer-placeholders", "ERROR", name,
	sprintf("Properties.Targets.%d.InputTransformer.InputTemplate", [t.index]),
	sprintf("InputTemplate uses <%s> but InputPathsMap does not declare it; PutTargets fails with \"InputTemplate for target %s contains invalid placeholder %s\"", [p, tid, p]),
	sprintf("Add '%s' to InputPathsMap, or remove the placeholder from the template", [p]),
	"https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-transform-target-input.html") if {
	some name in resources_of_type("AWS::Events::Rule")
	some t in flatten_list(name, "Properties.Targets")
	is_object(t.value)
	it := object.get(t.value, "InputTransformer", null)
	is_object(it)
	tmpl := object.get(it, "InputTemplate", null)
	is_string(tmpl)
	pm := object.get(it, "InputPathsMap", {})
	_pf_evitp_plain_map(pm)
	some p in _pf_evitp_placeholders(tmpl)
	not startswith(p, "aws.events.")
	not pm[p]
	tid := object.get(t.value, "Id", "<target>")
}
