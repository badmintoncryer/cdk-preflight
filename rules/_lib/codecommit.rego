package cdk_preflight

import rego.v1

# Shared helpers for the CodeCommit rules.
#
# AWS::CodeCommit::Repository.Triggers is applied by the CloudFormation handler
# with PutRepositoryTriggers after the repository exists, so every trigger
# constraint surfaces as a CREATE_FAILED on the repository itself. Triggers are
# read off the raw document: resolve() cannot prove a key absent, and the list
# has to keep its index so a diagnostic can point at one trigger.
# Loaded ahead of every rule (BUNDLED_LIBS); never emits diagnostics.

_pf_cclib_props(name) := p if {
	p := input.resources[name].properties
	is_object(p)
}

_pf_cclib_triggers(name) := t if {
	t := object.get(_pf_cclib_props(name), "Triggers", [])
	is_array(t)
}

# A user-written literal string. Ref/GetAtt resolve to a logical id in the
# template, and an unresolved intrinsic stays a marker object.
_pf_cclib_lit(v) if {
	is_string(v)
	not input.resources[v]
}

# The parts of a literal ARN, guarded so a token never reaches a rule.
_pf_cclib_arn(v) := parts if {
	_pf_cclib_lit(v)
	startswith(v, "arn:")
	parts := split(v, ":")
	count(parts) >= 6
}

# Git ref names CodeCommit rejects. Measured against PutRepositoryTriggers
# (2026-09-14, us-east-1): a space or a tab, "..", "//", "@{", any of ~^:?*[\,
# a leading "/" or ".", a trailing "/" or ".", and a ".lock" suffix all raise
# InvalidRepositoryTriggerBranchNameException. Accepted in the same run, so
# deliberately not encoded: ; , ' ( ) & % # ! + = < | " ` , a leading "-", a
# bare "@", non-ASCII, and a 255-character name.
_pf_cclib_bad_ref(b) if {
	_pf_cclib_lit(b)
	regex.match(`[ \t~^:?*\[\\]|\.\.|//|@\{|^[./]|[/.]$|\.lock$`, b)
}
