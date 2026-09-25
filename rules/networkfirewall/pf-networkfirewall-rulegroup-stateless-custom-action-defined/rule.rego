package cdk_preflight

import rego.v1

# Actions and CustomActions are two independent lists in the schema. Only names
# that do not start with "aws:" are checked here - an unknown "aws:" name is the
# standard-action rule's business, and claiming it twice would double-report.
_pf_nfwcad_defined(name) := names if {
	cas := object.get(_pf_nfwlib_props(name), ["RuleGroup", "RulesSource", "StatelessRulesAndCustomActions", "CustomActions"], [])
	_pf_countable_items(cas)
	names := {n |
		some c in cas
		n := object.get(c, "ActionName", null)
		is_string(n)
	}
	count(names) == count(cas)
}

violation contains make_diag_full("pf-networkfirewall-rulegroup-stateless-custom-action-defined", "ERROR", name,
	sprintf("Properties.RuleGroup.RulesSource.StatelessRulesAndCustomActions.StatelessRules[%d].RuleDefinition.Actions", [i]),
	sprintf("this stateless rule names the custom action %s, which CustomActions does not define; CreateRuleGroup answers \"Actions is invalid, parameter: [%s], context: StatelessRulesAndCustomActions.StatelessRules[...].RuleDefinition.Actions\"", [u, u]),
	"Define the custom action under the same StatelessRulesAndCustomActions.CustomActions, or use a standard action",
	"https://docs.aws.amazon.com/network-firewall/latest/developerguide/rule-action.html") if {
	some [name, i, r] in _pf_nfwlib_stateless_rules
	acts := object.get(r, ["RuleDefinition", "Actions"], null)
	_pf_countable_items(acts)

	# bound here on purpose: inlining the call would put it under a `not`, and
	# `not <undefined>` is true - an unreadable CustomActions list would then
	# report every custom action as undeclared.
	defined := _pf_nfwcad_defined(name)
	undef := {a |
		some a in acts
		is_string(a)
		not startswith(a, "aws:")
		not a in defined
	}
	count(undef) > 0
	u := concat(", ", sort(undef))
}
