package cdk_preflight

import rego.v1

# Shared helpers for the WAFv2 rules (rules/wafv2/pf-wafv2-*).
# Loaded ahead of every rule (BUNDLED_LIBS); never emits diagnostics.
#
# The engine has no walk() and Rego has no recursion, so the statement tree of
# every rule is unrolled level by level (And / Or / Not / ScopeDown) six levels
# deep. ponytail: deeper nesting is not inspected; the console allows one level
# and hand-written JSON rarely exceeds three.

_pf_waflib_containers contains name if some name in resources_of_type("AWS::WAFv2::WebACL")

_pf_waflib_containers contains name if some name in resources_of_type("AWS::WAFv2::RuleGroup")

_pf_waflib_is_webacl(name) if name in resources_of_type("AWS::WAFv2::WebACL")

_pf_waflib_is_rulegroup(name) if name in resources_of_type("AWS::WAFv2::RuleGroup")

_pf_waflib_rules(name) := rules if {
	rules := input.resources[name].properties.Rules
	is_array(rules)
}

_pf_waflib_scope(name) := s if {
	s := resolve(name, "Properties.Scope")
	is_string(s)
}

# Region a container's entities live in: CLOUDFRONT scope pins us-east-1.
_pf_waflib_region(name) := "us-east-1" if _pf_waflib_scope(name) == "CLOUDFRONT"

_pf_waflib_region(name) := data.cdk_preflight.deploy_region if _pf_waflib_scope(name) != "CLOUDFRONT"

# ---- statement tree: [container, rule index, path segments, statement object] ----

_pf_waflib_root contains [name, i, [], s] if {
	some name in _pf_waflib_containers
	rules := _pf_waflib_rules(name)
	some i
	s := rules[i].Statement
	is_object(s)
}

_pf_waflib_kids(s) := kids if {
	a := {[["AndStatement", "Statements", j], c] | some j; c := s.AndStatement.Statements[j]; is_object(c)}
	o := {[["OrStatement", "Statements", j], c] | some j; c := s.OrStatement.Statements[j]; is_object(c)}
	n := {[["NotStatement", "Statement"], c] | c := s.NotStatement.Statement; is_object(c)}
	r := {[["RateBasedStatement", "ScopeDownStatement"], c] | c := s.RateBasedStatement.ScopeDownStatement; is_object(c)}
	m := {[["ManagedRuleGroupStatement", "ScopeDownStatement"], c] | c := s.ManagedRuleGroupStatement.ScopeDownStatement; is_object(c)}
	kids := ((a | o) | (n | r)) | m
}

_pf_waflib_l1 contains [name, i, p, c] if {
	some [name, i, p0, s] in _pf_waflib_root
	some [p, c] in _pf_waflib_kids(s)
}

_pf_waflib_l2 contains [name, i, array.concat(p1, p2), c] if {
	some [name, i, p1, s] in _pf_waflib_l1
	some [p2, c] in _pf_waflib_kids(s)
}

_pf_waflib_l3 contains [name, i, array.concat(p1, p2), c] if {
	some [name, i, p1, s] in _pf_waflib_l2
	some [p2, c] in _pf_waflib_kids(s)
}

_pf_waflib_l4 contains [name, i, array.concat(p1, p2), c] if {
	some [name, i, p1, s] in _pf_waflib_l3
	some [p2, c] in _pf_waflib_kids(s)
}

_pf_waflib_l5 contains [name, i, array.concat(p1, p2), c] if {
	some [name, i, p1, s] in _pf_waflib_l4
	some [p2, c] in _pf_waflib_kids(s)
}

_pf_waflib_l6 contains [name, i, array.concat(p1, p2), c] if {
	some [name, i, p1, s] in _pf_waflib_l5
	some [p2, c] in _pf_waflib_kids(s)
}

_pf_waflib_stmts := ((_pf_waflib_root | _pf_waflib_l1) | (_pf_waflib_l2 | _pf_waflib_l3)) | ((_pf_waflib_l4 | _pf_waflib_l5) | _pf_waflib_l6)

_pf_waflib_stmt_keys := {"AndStatement", "AsnMatchStatement", "ByteMatchStatement", "GeoMatchStatement", "IPSetReferenceStatement", "LabelMatchStatement", "ManagedRuleGroupStatement", "NotStatement", "OrStatement", "RateBasedStatement", "RegexMatchStatement", "RegexPatternSetReferenceStatement", "RuleGroupReferenceStatement", "SizeConstraintStatement", "SqliMatchStatement", "XssMatchStatement"}

# Statements that inspect a request component (carry FieldToMatch / TextTransformations).
_pf_waflib_match_keys := {"ByteMatchStatement", "RegexMatchStatement", "RegexPatternSetReferenceStatement", "SizeConstraintStatement", "SqliMatchStatement", "XssMatchStatement"}

# Every statement body: [container, rule index, path to the statement object, kind, body].
_pf_waflib_leaves contains [name, i, p, kind, body] if {
	some [name, i, p, s] in _pf_waflib_stmts
	some kind in object.keys(s)
	kind in _pf_waflib_stmt_keys
	body := s[kind]
}

# Top-level statement kind(s) of rule i.
_pf_waflib_tops contains [name, i, kind] if {
	some [name, i, p, s] in _pf_waflib_root
	some kind in object.keys(s)
}

_pf_waflib_seg(x) := sprintf("[%d]", [x]) if is_number(x)

_pf_waflib_seg(x) := sprintf(".%s", [x]) if is_string(x)

_pf_waflib_path(i, p) := out if {
	segs := [seg | some j; x := p[j]; seg := _pf_waflib_seg(x)]
	out := sprintf("Properties.Rules[%d].Statement%s", [i, concat("", segs)])
}

# resolve() turns {"Fn::GetAtt": ["X", "Arn"]} into the logical id "X"; a literal is a
# resolved string that is not a resource name of this template.
_pf_waflib_lit(name, path) := s if {
	s := resolve(name, path)
	is_string(s)
	not input.resources[s]
}

# [partition, service, region, account, resource...] of a literal ARN; undefined otherwise
_pf_waflib_arn(s) := parts if {
	is_string(s)
	startswith(s, "arn:")
	parts := split(s, ":")
	count(parts) >= 6
}

# The engine hands intrinsics to Rego as markers: {"Fn::GetAtt": ["X", "Arn"]} is
# {"__kind": "getatt:Arn", "__ref": "X"}, {"Ref": "X"} is {"__kind": "resource", "__ref": "X"},
# and resolve() turns both into the logical id "X".
_pf_waflib_getatt(v) := x if {
	is_object(v)
	startswith(v["__kind"], "getatt:")
	x := v["__ref"]
	is_string(x)
}

_pf_waflib_ref(v) := x if {
	is_object(v)
	v["__kind"] == "resource"
	x := v["__ref"]
	is_string(x)
}

_pf_waflib_ref_kinds := {"IPSetReferenceStatement": "ipset", "RegexPatternSetReferenceStatement": "regexpatternset", "RuleGroupReferenceStatement": "rulegroup"}

_pf_waflib_ref_types := {"IPSetReferenceStatement": "AWS::WAFv2::IPSet", "RegexPatternSetReferenceStatement": "AWS::WAFv2::RegexPatternSet", "RuleGroupReferenceStatement": "AWS::WAFv2::RuleGroup"}

# AWS Managed Rules rule groups and their capacities (describe-managed-rule-group, 2026-09-05).
# ponytail: static table; a new AWS group shows up here as a false "unknown group" until refreshed.
_pf_waflib_managed := {
	"AWSManagedRulesACFPRuleSet": 50,
	"AWSManagedRulesATPRuleSet": 50,
	"AWSManagedRulesAdminProtectionRuleSet": 100,
	"AWSManagedRulesAmazonIpReputationList": 25,
	"AWSManagedRulesAnonymousIpList": 50,
	"AWSManagedRulesAntiDDoSRuleSet": 50,
	"AWSManagedRulesBotControlRuleSet": 50,
	"AWSManagedRulesCommonRuleSet": 700,
	"AWSManagedRulesKnownBadInputsRuleSet": 200,
	"AWSManagedRulesLinuxRuleSet": 200,
	"AWSManagedRulesPHPRuleSet": 100,
	"AWSManagedRulesSQLiRuleSet": 200,
	"AWSManagedRulesUnixRuleSet": 100,
	"AWSManagedRulesWindowsRuleSet": 200,
	"AWSManagedRulesWordPressRuleSet": 100,
}
