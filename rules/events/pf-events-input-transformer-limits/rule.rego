package cdk_preflight

import rego.v1

# InputPathsMap is capped at 100 entries and its keys may not collide with a
# reserved aws.events.* variable; both are refused by the PutTargets request
# model, so the stack never reaches the service check. Measured 2026-09-07,
# events:PutTargets, us-east-1: 101 entries and a key of
# "aws.events.rule-name" each give "1 validation error detected", while 100
# entries and ordinary keys are accepted. A key merely starting with "AWS" is
# accepted, so that is deliberately not reported.
_pf_evitl_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-rule-inputtransformer.html"

_pf_evitl_maps(name) := [t |
	some t in flatten_list(name, "Properties.Targets")
	is_object(t.value)
	it := object.get(t.value, "InputTransformer", null)
	is_object(it)
	is_object(object.get(it, "InputPathsMap", null))
]

_pf_evitl_map(t) := t.value.InputTransformer.InputPathsMap

_pf_evitl_plain(pm) if {
	every k, v in pm {
		not startswith(k, "__")
	}
}

violation contains make_diag_full("pf-events-input-transformer-limits", "ERROR", name,
	sprintf("Properties.Targets.%d.InputTransformer.InputPathsMap", [t.index]),
	sprintf("InputPathsMap holds %d entries; PutTargets accepts at most 100", [count(pm)]),
	"Fold the extra paths into fewer placeholders",
	_pf_evitl_url) if {
	some name in resources_of_type("AWS::Events::Rule")
	some t in _pf_evitl_maps(name)
	pm := _pf_evitl_map(t)
	_pf_evitl_plain(pm)
	count(pm) > 100
}

violation contains make_diag_full("pf-events-input-transformer-limits", "ERROR", name,
	sprintf("Properties.Targets.%d.InputTransformer.InputPathsMap", [t.index]),
	sprintf("'%s' is a reserved EventBridge variable and cannot be an InputPathsMap key; PutTargets rejects the request", [k]),
	"Name the placeholder something outside the aws.events. namespace",
	_pf_evitl_url) if {
	some name in resources_of_type("AWS::Events::Rule")
	some t in _pf_evitl_maps(name)
	some k, v in _pf_evitl_map(t)
	startswith(k, "aws.events.")
}
