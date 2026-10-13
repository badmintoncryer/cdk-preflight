package cdk_preflight

import rego.v1

# A rate-controlled Automation association (one with AutomationTargetParameterName)
# hands its Targets to StartAutomationExecution, which takes at most one Target and,
# inside it, a single tag or a single resource group. CreateAssociation accepts more,
# so the stack deploys and every run then fails with
# "Only one resource group or tag can be specified at a time"
# (association Status Failed, DetailedStatus InvalidAutomationParameters, no child
# executions). The deploy itself fails only when WaitForSuccessTimeoutSeconds is set,
# which is why both fixtures carry it; the rule fires without it, because the
# association can never run. Command associations take any number of tag values and
# are left alone, as are InstanceIds values (no documented limit here) and tag-key
# values (how several keys behave is neither documented nor observed).
# Values that are not a literal list (Ref, Fn::Split) or that hold an Fn::If are skipped:
# the template does not show how many values deploy (_pf_countable_items).
_pf_ssmaas_url := "https://docs.aws.amazon.com/systems-manager/latest/userguide/running-automations-map-targets.html"

_pf_ssmaas_fix := "Select the targets with one tag key and one value (for example a tag every target shares), or with one resource group"

_pf_ssmaas_rate_controlled(name) if {
	object.get(input.resources[name].properties, "AutomationTargetParameterName", "__pf_absent") != "__pf_absent"
}

violation contains make_diag_full("pf-ssm-association-automation-single-target", "ERROR", name,
	"Properties.Targets",
	sprintf("a rate-controlled Automation association takes one target, but Targets has %d; every run fails with \"Only one resource group or tag can be specified at a time\"", [n]),
	_pf_ssmaas_fix, _pf_ssmaas_url) if {
	some name in resources_of_type("AWS::SSM::Association")
	_pf_ssmaas_rate_controlled(name)
	_pf_countable_list(name, "Properties.Targets")
	n := count(flatten_list(name, "Properties.Targets"))
	n >= 2
}

_pf_ssmaas_single_key(k) if startswith(k, "tag:")

_pf_ssmaas_single_key(k) if lower(k) == "resource-groups:name"

violation contains make_diag_full("pf-ssm-association-automation-single-target", "ERROR", name,
	sprintf("Properties.Targets.%d.Values", [i]),
	sprintf("a rate-controlled Automation association takes one value for '%s', but it has %d; every run fails with \"Only one resource group or tag can be specified at a time\"", [k, n]),
	_pf_ssmaas_fix, _pf_ssmaas_url) if {
	some name in resources_of_type("AWS::SSM::Association")
	_pf_ssmaas_rate_controlled(name)
	targets := object.get(input.resources[name].properties, "Targets", [])
	is_array(targets)
	some i, t in targets
	k := resolve(name, sprintf("Properties.Targets.%d.Key", [i]))
	is_string(k)
	_pf_ssmaas_single_key(k)
	is_object(t)
	_pf_countable_items(object.get(t, "Values", null))
	n := count(flatten_list(name, sprintf("Properties.Targets.%d.Values", [i])))
	n >= 2
}
