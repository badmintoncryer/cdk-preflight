package cdk_preflight

import rego.v1

# Masks says which flags are inspected and Flags says which of those must be
# set, so a flag outside the mask can never match. The schema holds the two
# arrays side by side with no relation between them.
_pf_nfwtfm contains [name, i, ti, extra] if {
	some [name, i, r] in _pf_nfwlib_stateless_rules
	tfs := object.get(r, ["RuleDefinition", "MatchAttributes", "TCPFlags"], null)
	_pf_countable_items(tfs)
	some ti, tf in tfs
	masks := object.get(tf, "Masks", null)
	_pf_countable_items(masks)
	count(masks) > 0
	flags := object.get(tf, "Flags", null)
	_pf_countable_items(flags)
	extra := {f | some f in flags; is_string(f)} - {m | some m in masks; is_string(m)}
	count(extra) > 0
}

violation contains make_diag_full("pf-networkfirewall-rulegroup-tcpflags-subset-of-masks", "ERROR", name,
	sprintf("Properties.RuleGroup.RulesSource.StatelessRulesAndCustomActions.StatelessRules[%d].RuleDefinition.MatchAttributes.TCPFlags[%d].Flags", [i, ti]),
	sprintf("%s is in Flags but not in Masks, so the rule can never match; CreateRuleGroup answers \"Flags is unmasked, parameter: [%s], context: ...MatchAttributes.TCPFlags[%d].Flags\"", [e, e, ti]),
	"Add the flag to Masks as well, or drop it from Flags",
	"https://docs.aws.amazon.com/network-firewall/latest/developerguide/stateless-rule-groups-standard.html") if {
	some [name, i, ti, extra] in _pf_nfwtfm
	e := concat(", ", sort(extra))
}
