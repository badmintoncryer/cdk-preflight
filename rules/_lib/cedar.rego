package cdk_preflight

import rego.v1

# Shared helpers for the Amazon Verified Permissions Cedar rules
# (rules/verifiedpermissions/pf-avp-policy-* and pf-avp-template-*).
# Loaded ahead of every rule (BUNDLED_LIBS); never emits diagnostics.
#
# Rego cannot host a Cedar parser here (no walk, no recursion, no `every`
# inside a comprehension), so every helper is regex over a normalized text.
# The Fn::If / token hazard (AGENTS.md #258 / #272) is handled once, at the
# resolve() boundary in the three sets below: an intrinsic statement never
# reaches a helper, because resolve() either collapses it to a literal string
# or is undefined and the set entry disappears. Everything past that point is
# a single-bodied function of the statement *string*, so no helper can ever
# produce two outputs for one input ("functions must not produce multiple
# outputs", which would silence the whole pack).

# Static policy statements: [logical id, property path, statement].
_pf_cedarlib_static contains [name, "Properties.Definition.Static.Statement", s] if {
	some name in resources_of_type("AWS::VerifiedPermissions::Policy")
	s := resolve(name, "Properties.Definition.Static.Statement")
	is_string(s)
}

# Policy template statements. Verified Permissions runs the same Cedar parser
# over both, so the syntax rules read this set and the one above together
# (probe 2026-09-25: a malformed PolicyTemplate.Statement is rejected with the
# same "Failed to validate policy body" as a malformed static policy).
_pf_cedarlib_template contains [name, "Properties.Statement", s] if {
	some name in resources_of_type("AWS::VerifiedPermissions::PolicyTemplate")
	s := resolve(name, "Properties.Statement")
	is_string(s)
}

_pf_cedarlib_all := _pf_cedarlib_static | _pf_cedarlib_template

# Comments removed, string literals kept. One left-to-right pass over an
# alternation: the leftmost alternative wins, so a `//` inside a string does
# not start a comment and a `"` inside a comment does not open a string.
_pf_cedarlib_nocomment(s) := regex.replace(s, `("(?:\\.|[^"\\])*")|//[^\n]*`, "$1")

# The working text: comments gone, every string literal collapsed to "", every
# @annotation("...") dropped (whitespace around the name and the parentheses is
# legal Cedar and must not survive as a stray "(" that reads like the scope).
# Declines when an `@` still survives - a value-less Cedar annotation - so the
# rules go quiet on a policy this normalization does not model.
_pf_cedarlib_code(s) := c if {
	collapsed := regex.replace(_pf_cedarlib_nocomment(s), `"(?:\\.|[^"\\])*"`, `""`)
	c := regex.replace(collapsed, `@\s*[A-Za-z_][A-Za-z_0-9]*\s*\(\s*""\s*\)`, "")
	not contains(c, "@")
}

# Text before the scope's opening parenthesis (the effect keyword lives here).
_pf_cedarlib_head(s) := substring(c, 0, i) if {
	c := _pf_cedarlib_code(s)
	i := indexof(c, "(")
	i >= 0
}

# The scope text between the first ( and the first ). A Cedar scope carries no
# parentheses of its own, so the first ) closes it; if one turns up inside, the
# text is not a scope this normalization understands and every scope rule
# declines rather than guessing. indexof returns -1 for a missing character,
# which is why both ends are checked before substring sees them.
_pf_cedarlib_scope(s) := sc if {
	c := _pf_cedarlib_code(s)
	i := indexof(c, "(")
	i >= 0
	j := indexof(c, ")")
	j > i
	sc := substring(c, i + 1, j - i - 1)
	not contains(sc, "(")
}

# Everything after the scope: the when / unless clauses and the terminator.
_pf_cedarlib_body(s) := b if {
	sc := _pf_cedarlib_scope(s)
	is_string(sc)
	c := _pf_cedarlib_code(s)
	j := indexof(c, ")")
	b := substring(c, j + 1, count(c) - j - 1)
}

# The depth-0 elements of the scope. `action in [A::"x", A::"y"]` carries commas
# of its own, so the bracket groups collapse to [] before the split - counting
# those commas is what would make scope-three-elements misfire.
_pf_cedarlib_parts(s) := split(regex.replace(sc, `\[[^\]]*\]`, "[]"), ",") if {
	sc := _pf_cedarlib_scope(s)
}

# Leading identifier of a scope element ("principal" / "action" / "resource").
_pf_cedarlib_word(part) := w[0] if {
	w := regex.find_n(`^[A-Za-z_][A-Za-z_0-9]*`, trim_space(part), 1)
	count(w) == 1
}

# Path tokens, e.g. MyApp::User::"" (string literals are already collapsed).
# A token with no "::" is a keyword, an operator or a bare identifier.
_pf_cedarlib_paths(part) := regex.find_n(`[A-Za-z_][A-Za-z_0-9]*(?:::(?:[A-Za-z_][A-Za-z_0-9]*|""))*`, part, -1)

# Whether the text uses the `is` operator, where the grammar wants a bare type
# name rather than an entity UID. Returns a boolean rather than declining: a
# predicate that goes undefined would invert under `not` and fire on
# everything (AGENTS.md, #268 / #280).
_pf_cedarlib_is_op(part) := regex.match(`(^|[^A-Za-z_0-9])is($|[^A-Za-z_0-9])`, part)

# Template placeholders (`?principal`, `?resource`, and anything else spelled
# like one) occurring in a piece of normalized text.
_pf_cedarlib_slots(part) := regex.find_n(`\?[A-Za-z_][A-Za-z_0-9]*`, part, -1)

# Number of statement terminators. Cedar has no `;` inside a policy body, and
# string literals and comments are gone, so this counts whole policies.
_pf_cedarlib_semicolons(s) := count(split(c, ";")) - 1 if {
	c := _pf_cedarlib_code(s)
}

# Template-linked policies: [policy logical id, template logical id, the
# placeholders the linked template actually declares]. A template-linked policy
# has to supply exactly those placeholders - Verified Permissions rejects both
# a missing one and a spare one (probe 2026-09-25) - so the four
# pf-avp-template-linked-* rules compare this list against what
# Definition.TemplateLinked spells out. `slots` is bound here, not called
# inline from the rules: a helper that declines would invert under `not` and
# make the two "unexpected" rules fire on everything (AGENTS.md, #268 / #280).
_pf_cedarlib_links contains [name, tname, slots] if {
	some name in resources_of_type("AWS::VerifiedPermissions::Policy")
	tname := resolve(name, "Properties.Definition.TemplateLinked.PolicyTemplateId")
	is_string(tname)
	tname in resources_of_type("AWS::VerifiedPermissions::PolicyTemplate")
	some [tname2, _, st] in _pf_cedarlib_template
	tname2 == tname
	slots := _pf_cedarlib_slots(_pf_cedarlib_code(st))
}

# The raw Definition.TemplateLinked object, for the absence proofs the link
# rules need (resolve() cannot tell an absent Principal from an unresolvable
# one). PolicyTemplateId is mandatory there and no intrinsic marker object
# carries that key, so an Fn::If wrapped around Definition or TemplateLinked
# declines here instead of reading as "Principal is absent" - which is what
# resolve() collapsing the same Fn::If to its true branch would otherwise turn
# into a false positive on every conditional template-linked policy.
_pf_cedarlib_tl(name) := tl if {
	props := input.resources[name].properties
	is_object(props)
	tl := object.get(props, ["Definition", "TemplateLinked"], null)
	is_object(tl)
	object.get(tl, "PolicyTemplateId", "__pf_absent") != "__pf_absent"
}
