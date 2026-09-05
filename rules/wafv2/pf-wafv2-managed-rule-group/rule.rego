package cdk_preflight

import rego.v1

_pf_wafmrg_url := "https://docs.aws.amazon.com/waf/latest/APIReference/API_ManagedRuleGroupStatement.html"

_pf_wafmrg_fix := "Use an existing AWS managed rule group name, give AWSManagedRulesATPRuleSet / ACFPRuleSet their own config object (and no config meant for another group), do not list a rule in both ExcludedRules and RuleActionOverrides, give Anti-DDoS 1-5 exempt regexes when the challenge is enabled, and inspect exactly one response component with disjoint success / failure codes"

_pf_wafmrg contains [name, pp, m] if {
	some [name, i, p, kind, m] in _pf_waflib_leaves
	kind == "ManagedRuleGroupStatement"
	pp := _pf_waflib_path(i, array.concat(p, ["ManagedRuleGroupStatement"]))
}

_pf_wafmrg_cfgs(m) := c if {
	c := m.ManagedRuleGroupConfigs
	is_array(c)
}

_pf_wafmrg_cfgs(m) := [] if not is_array(object.get(m, "ManagedRuleGroupConfigs", null))

_pf_wafmrg_special := {"AWSManagedRulesATPRuleSet", "AWSManagedRulesACFPRuleSet", "AWSManagedRulesBotControlRuleSet", "AWSManagedRulesAntiDDoSRuleSet"}

violation contains make_diag_full("pf-wafv2-managed-rule-group", "ERROR", name, sprintf("%s.Name", [pp]),
	sprintf("AWS has no managed rule group named '%s'; the create call fails with WAFNonexistentItemException", [n]),
	_pf_wafmrg_fix, _pf_wafmrg_url) if {
	some [name, pp, m] in _pf_wafmrg
	m.VendorName == "AWS"
	n := m.Name
	is_string(n)
	not _pf_waflib_managed[n]
}

_pf_wafmrg_has_cfg(m, g) if {
	some c in _pf_wafmrg_cfgs(m)
	c[g]
}

violation contains make_diag_full("pf-wafv2-managed-rule-group", "ERROR", name, sprintf("%s.ManagedRuleGroupConfigs", [pp]),
	"AWSManagedRulesATPRuleSet needs a ManagedRuleGroupConfigs entry with AWSManagedRulesATPRuleSet (LoginPath, RequestInspection); the create call fails with \"REQUIRED_FIELD_MISSING\"",
	_pf_wafmrg_fix, _pf_wafmrg_url) if {
	some [name, pp, m] in _pf_wafmrg
	m.VendorName == "AWS"
	m.Name == "AWSManagedRulesATPRuleSet"
	not _pf_wafmrg_has_cfg(m, "AWSManagedRulesATPRuleSet")
}

violation contains make_diag_full("pf-wafv2-managed-rule-group", "ERROR", name, sprintf("%s.ManagedRuleGroupConfigs", [pp]),
	"AWSManagedRulesACFPRuleSet needs a ManagedRuleGroupConfigs entry with AWSManagedRulesACFPRuleSet (CreationPath, RegistrationPagePath, RequestInspection); the create call fails with \"ACP Managed Rule group config is not found\"",
	_pf_wafmrg_fix, _pf_wafmrg_url) if {
	some [name, pp, m] in _pf_wafmrg
	m.VendorName == "AWS"
	m.Name == "AWSManagedRulesACFPRuleSet"
	not _pf_wafmrg_has_cfg(m, "AWSManagedRulesACFPRuleSet")
}

violation contains make_diag_full("pf-wafv2-managed-rule-group", "ERROR", name, sprintf("%s.ManagedRuleGroupConfigs[%d].%s", [pp, c, g]),
	sprintf("%s configuration is only accepted on the %s rule group, not on %s; the create call fails with \"UNSUPPORTED_PARAMETER_VALUE\"", [g, g, m.Name]),
	_pf_wafmrg_fix, _pf_wafmrg_url) if {
	some [name, pp, m] in _pf_wafmrg
	cfgs := _pf_wafmrg_cfgs(m)
	some c
	some g in _pf_wafmrg_special
	cfgs[c][g]
	m.Name != g
}

violation contains make_diag_full("pf-wafv2-managed-rule-group", "ERROR", name, sprintf("%s.ManagedRuleGroupConfigs[%d].%s", [pp, d, g]),
	sprintf("%s configuration is already given at ManagedRuleGroupConfigs[%d]; the create call fails with \"DUPLICATE_PARAMETER_ITEM\"", [g, c]),
	_pf_wafmrg_fix, _pf_wafmrg_url) if {
	some [name, pp, m] in _pf_wafmrg
	cfgs := _pf_wafmrg_cfgs(m)
	some c, d
	c < d
	some g in _pf_wafmrg_special
	cfgs[c][g]
	cfgs[d][g]
}

violation contains make_diag_full("pf-wafv2-managed-rule-group", "ERROR", name, sprintf("%s.RuleActionOverrides[%d]", [pp, o]),
	sprintf("rule '%s' is listed in both ExcludedRules and RuleActionOverrides; the create call fails with \"EXCLUDED_RULES_COEXIST_RULE_ACTION_OVERRIDES\"", [n]),
	_pf_wafmrg_fix, _pf_wafmrg_url) if {
	some [name, pp, m] in _pf_wafmrg
	some o, e
	n := m.RuleActionOverrides[o].Name
	m.ExcludedRules[e].Name == n
}

violation contains make_diag_full("pf-wafv2-managed-rule-group", "ERROR", name, sprintf("%s.RuleActionOverrides[%d].Name", [pp, q]),
	sprintf("rule '%s' is already overridden at RuleActionOverrides[%d]; the create call fails with \"You have duplicated some of the information in the parameter.\"", [n, o]),
	_pf_wafmrg_fix, _pf_wafmrg_url) if {
	some [name, pp, m] in _pf_wafmrg
	some o, q
	o < q
	n := m.RuleActionOverrides[o].Name
	m.RuleActionOverrides[q].Name == n
}

_pf_wafmrg_exempt(ch) := l if {
	l := ch.ExemptUriRegularExpressions
	is_array(l)
}

_pf_wafmrg_exempt(ch) := [] if not is_array(object.get(ch, "ExemptUriRegularExpressions", null))

violation contains make_diag_full("pf-wafv2-managed-rule-group", "ERROR", name, sprintf("%s.ManagedRuleGroupConfigs[%d].AWSManagedRulesAntiDDoSRuleSet.ClientSideActionConfig.Challenge", [pp, c]),
	sprintf("UsageOfAction ENABLED needs 1 to 5 ExemptUriRegularExpressions (found %d); the create call fails with \"AWSManagedRulesAntiDDoSRuleSet managed rule group config must have at least one RegularExpression in ExemptUriRegularExpressions\"", [count(l)]),
	_pf_wafmrg_fix, _pf_wafmrg_url) if {
	some [name, pp, m] in _pf_wafmrg
	cfgs := _pf_wafmrg_cfgs(m)
	some c
	ch := cfgs[c].AWSManagedRulesAntiDDoSRuleSet.ClientSideActionConfig.Challenge
	ch.UsageOfAction == "ENABLED"
	l := _pf_wafmrg_exempt(ch)
	_pf_wafmrg_bad_count(count(l))
}

_pf_wafmrg_bad_count(n) if n < 1

_pf_wafmrg_bad_count(n) if n > 5

_pf_wafmrg_ri contains [name, sprintf("%s.ManagedRuleGroupConfigs[%d].%s.ResponseInspection", [pp, c, g]), ri] if {
	some [name, pp, m] in _pf_wafmrg
	cfgs := _pf_wafmrg_cfgs(m)
	some c
	some g in {"AWSManagedRulesATPRuleSet", "AWSManagedRulesACFPRuleSet"}
	ri := cfgs[c][g].ResponseInspection
	is_object(ri)
}

violation contains make_diag_full("pf-wafv2-managed-rule-group", "ERROR", name, rp,
	sprintf("ResponseInspection names %d components; exactly one of StatusCode / Header / BodyContains / Json is required (the create call fails with \"EXACTLY_ONE_CONDITION_REQUIRED\")", [count(object.keys(ri))]),
	_pf_wafmrg_fix, _pf_wafmrg_url) if {
	some [name, rp, ri] in _pf_wafmrg_ri
	count(object.keys(ri)) != 1
}

violation contains make_diag_full("pf-wafv2-managed-rule-group", "ERROR", name, sprintf("%s.StatusCode", [rp]),
	sprintf("status code %d appears in both SuccessCodes and FailureCodes; the create call fails with \"MUTUALLY_EXCLUSIVE_LISTS\"", [code]),
	_pf_wafmrg_fix, _pf_wafmrg_url) if {
	some [name, rp, ri] in _pf_wafmrg_ri
	some code in ri.StatusCode.SuccessCodes
	code in ri.StatusCode.FailureCodes
}
