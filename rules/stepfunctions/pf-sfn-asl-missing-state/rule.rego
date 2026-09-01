package cdk_preflight

import rego.v1

_pf_sfn_fix := "Point Next/Default/Choices at an existing state name"

_pf_sfn_url := "https://docs.aws.amazon.com/step-functions/latest/dg/amazon-states-language-states.html"

_pf_sfn_asl(name) := asl if {
	def := resolve(name, "Properties.DefinitionString")
	is_string(def)
	asl := json.unmarshal(def)
	is_object(asl)
}

_pf_sfn_defined(asl) := {sn | some sn, _ in object.get(asl, "States", {})}

# NOTE: a dangling StartAt is deliberately NOT checked here — the engine's
# built-in rule E3601 (ERROR/CFN_LINT) already covers it. Verified against
# @aws/cloudformation-validate 1.7.0-beta on 2026-09-01: E3601 fires for
# StartAt only and does not check Next/Default/Choices, which is what this
# rule adds.

violation contains make_diag_full("pf-sfn-asl-missing-state", "ERROR", name,
	"Properties.DefinitionString",
	sprintf("state '%s' references state '%s' via %s, but no state with that name is defined", [sname, target, key]),
	_pf_sfn_fix, _pf_sfn_url) if {
	some name in resources_of_type("AWS::StepFunctions::StateMachine")
	asl := _pf_sfn_asl(name)
	some sname, st in object.get(asl, "States", {})
	is_object(st)
	some key in {"Next", "Default"}
	target := object.get(st, key, null)
	is_string(target)
	not target in _pf_sfn_defined(asl)
}

violation contains make_diag_full("pf-sfn-asl-missing-state", "ERROR", name,
	"Properties.DefinitionString",
	sprintf("state '%s' has a Choice rule referencing state '%s', but no state with that name is defined", [sname, target]),
	_pf_sfn_fix, _pf_sfn_url) if {
	some name in resources_of_type("AWS::StepFunctions::StateMachine")
	asl := _pf_sfn_asl(name)
	some sname, st in object.get(asl, "States", {})
	is_object(st)
	choices := object.get(st, "Choices", [])
	is_array(choices)
	some c in choices
	is_object(c)
	target := object.get(c, "Next", null)
	is_string(target)
	not target in _pf_sfn_defined(asl)
}
