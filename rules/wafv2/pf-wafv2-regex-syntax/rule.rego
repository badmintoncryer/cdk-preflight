package cdk_preflight

import rego.v1

_pf_wafrx_url := "https://docs.aws.amazon.com/waf/latest/developerguide/waf-regex-pattern-support.html"

_pf_wafrx_fix := "Rewrite the pattern without backreferences, lookahead / lookbehind, possessive quantifiers, atomic groups, conditionals, recursion, \\K, \\R or (*VERB)s, keep it syntactically valid, and keep a regex pattern set to 10 patterns"

# every regex: [resource, path, pattern]
_pf_wafrx contains [name, sprintf("%s.RegexString", [_pf_waflib_path(i, array.concat(p, ["RegexMatchStatement"]))]), re] if {
	some [name, i, p, kind, body] in _pf_waflib_leaves
	kind == "RegexMatchStatement"
	re := body.RegexString
	is_string(re)
}

_pf_wafrx contains [name, sprintf("Properties.RegularExpressionList[%d]", [k]), re] if {
	some name in resources_of_type("AWS::WAFv2::RegexPatternSet")
	l := input.resources[name].properties.RegularExpressionList
	some k
	re := l[k]
	is_string(re)
}

_pf_wafrx contains [name, sprintf("%s.ManagedRuleGroupConfigs[%d].AWSManagedRulesAntiDDoSRuleSet.ClientSideActionConfig.Challenge.ExemptUriRegularExpressions[%d].RegexString", [_pf_waflib_path(i, array.concat(p, ["ManagedRuleGroupStatement"])), c, k]), re] if {
	some [name, i, p, kind, body] in _pf_waflib_leaves
	kind == "ManagedRuleGroupStatement"
	some c, k
	re := body.ManagedRuleGroupConfigs[c].AWSManagedRulesAntiDDoSRuleSet.ClientSideActionConfig.Challenge.ExemptUriRegularExpressions[k].RegexString
	is_string(re)
}

# [description, detector]; the detectors skip a backslash-escaped quantifier such as \++
_pf_wafrx_bad := {
	["a backreference (\\1)", "\\\\[1-9]"],
	["lookahead / lookbehind ((?=, (?!, (?<=, (?<!)", "\\(\\?<?[=!]"],
	["a possessive quantifier (++, *+, ?+, }+)", "(^|[^\\\\])[+*?}]\\+"],
	["an atomic group ((?>)", "\\(\\?>"],
	["a conditional pattern ((?()", "\\(\\?\\("],
	["recursion ((?R) / (?1))", "\\(\\?(R|[+-]?[0-9]+)\\)"],
	["\\K", "(^|[^\\\\])\\\\K"],
	["\\R", "(^|[^\\\\])\\\\R"],
	["a backtracking control verb ((*VERB))", "\\(\\*[A-Z]"],
}

violation contains make_diag_full("pf-wafv2-regex-syntax", "ERROR", name, pp,
	sprintf("pattern '%s' uses %s, which AWS WAF does not support; the create call fails with \"The parameter contains formatting that is not valid.\"", [re, what]),
	_pf_wafrx_fix, _pf_wafrx_url) if {
	some [name, pp, re] in _pf_wafrx
	some [what, det] in _pf_wafrx_bad
	regex.match(det, re)
}

# ponytail: the engine's regex parser (RE2-like) stands in for the WAF parser for everything the
# detectors above do not name; PCRE-only escapes it rejects but WAF accepts would show up here.
violation contains make_diag_full("pf-wafv2-regex-syntax", "ERROR", name, pp,
	sprintf("pattern '%s' is not a valid regular expression (unbalanced group or bracket, or unsupported syntax); the create call fails with \"The parameter contains formatting that is not valid.\"", [re]),
	_pf_wafrx_fix, _pf_wafrx_url) if {
	some [name, pp, re] in _pf_wafrx
	not regex.is_valid(re)
	count({what | some [what, det] in _pf_wafrx_bad; regex.match(det, re)}) == 0
}

violation contains make_diag_full("pf-wafv2-regex-syntax", "ERROR", name, "Properties.RegularExpressionList",
	sprintf("%d patterns; a regex pattern set holds at most 10 (the create call fails with WAFLimitsExceededException NUM_PATTERNS_IN_REGEX_PATTERN_SET)", [count(l)]),
	_pf_wafrx_fix, _pf_wafrx_url) if {
	some name in resources_of_type("AWS::WAFv2::RegexPatternSet")
	l := input.resources[name].properties.RegularExpressionList
	is_array(l)
	count(l) > 10
}

# ATP / ACFP paths evaluated as regexes must not turn case sensitivity off
violation contains make_diag_full("pf-wafv2-regex-syntax", "ERROR", name, sprintf("%s.ManagedRuleGroupConfigs[%d].%s.%s", [_pf_waflib_path(i, array.concat(p, ["ManagedRuleGroupStatement"])), c, g, f]),
	sprintf("path regex '%s' uses (?-i); the create call fails with \"Case-sensitive mode flag (?-i) is not supported in Regex patterns for paths\"", [v]),
	_pf_wafrx_fix, _pf_wafrx_url) if {
	some [name, i, p, kind, body] in _pf_waflib_leaves
	kind == "ManagedRuleGroupStatement"
	some c
	some g in {"AWSManagedRulesATPRuleSet", "AWSManagedRulesACFPRuleSet"}
	cfg := body.ManagedRuleGroupConfigs[c][g]
	cfg.EnableRegexInPath == true
	some f in {"LoginPath", "CreationPath", "RegistrationPagePath"}
	v := cfg[f]
	is_string(v)
	contains(v, "(?-i)")
}
