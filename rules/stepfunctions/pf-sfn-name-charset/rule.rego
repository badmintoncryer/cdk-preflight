package cdk_preflight

import rego.v1

_pf_sfnname_url := "https://docs.aws.amazon.com/step-functions/latest/dg/service-quotas.html"

_pf_sfnname_fix := "Use letters, digits, - and _ in the name"

# Measured 2026-09-05: 'my machine', 'a/b' and 'a<b>' are rejected with
# InvalidName; 'テスト' is accepted (so no ASCII-only check here — see
# pf-sfn-logging-name-ascii for the logging case). The schema carries only
# the 80-character maximum (F3033).
_pf_sfnname_bad := "[\\s<>{}\\[\\]?*\"#%\\\\^|~`$&,;:/\\x00-\\x1f\\x7f-\\x9f]"

_pf_sfnname_prop contains ["AWS::StepFunctions::StateMachine", "Properties.StateMachineName"]

_pf_sfnname_prop contains ["AWS::StepFunctions::Activity", "Properties.Name"]

violation contains make_diag_full("pf-sfn-name-charset", "ERROR", name,
	prop,
	sprintf("name '%s' contains a character Step Functions rejects (whitespace, < > { } [ ] ? * \" # %% \\ ^ | ~ ` $ & , ; : / or a control character); the create call fails with \"InvalidName: Invalid Name: '%s'\"", [n, n]),
	_pf_sfnname_fix, _pf_sfnname_url) if {
	some [rt, prop] in _pf_sfnname_prop
	some name in resources_of_type(rt)
	n := resolve(name, prop)
	is_string(n)
	regex.match(_pf_sfnname_bad, n)
}
