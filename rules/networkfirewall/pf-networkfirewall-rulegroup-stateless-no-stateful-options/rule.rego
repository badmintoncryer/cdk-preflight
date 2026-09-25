package cdk_preflight

import rego.v1

# Measured one key at a time (CreateRuleGroup DryRun, us-east-1, 2026-09-25):
# RuleVariables and StatefulRuleOptions are rejected on a STATELESS group, while
# ReferenceSets is accepted - so the doc's "stateful rule group options" heading
# covers one key more than the service does, and this rule claims only the two.
_pf_nfwsno_keys := {"RuleVariables", "StatefulRuleOptions"}

violation contains make_diag_full("pf-networkfirewall-rulegroup-stateless-no-stateful-options", "ERROR", name,
	sprintf("Properties.RuleGroup.%s", [k]),
	sprintf("a STATELESS rule group cannot carry %s; CreateRuleGroup answers \"%s cannot be provided, context: %s\"", [k, k, k]),
	sprintf("Drop %s, or make the rule group STATEFUL", [k]),
	"https://docs.aws.amazon.com/network-firewall/latest/developerguide/stateful-rule-group-options.html") if {
	some name in resources_of_type("AWS::NetworkFirewall::RuleGroup")
	_pf_nfwlib_lit(name, "Properties.Type") == "STATELESS"
	rg := object.get(_pf_nfwlib_props(name), "RuleGroup", null)
	_pf_countable_entries(rg)
	some k in object.keys(rg) & _pf_nfwsno_keys
}
