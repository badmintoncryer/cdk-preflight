package cdk_preflight

import rego.v1

_pf_kmslock_url := "https://docs.aws.amazon.com/kms/latest/developerguide/key-policy-default.html"

_pf_kmslock_fix := "Keep the default statement (Principal arn:aws:iam::<account>:root, Action kms:*, Resource *) or another Allow that covers kms:PutKeyPolicy for a principal in this account"

# KeyPolicy arrives as a JSON object or as a JSON string (both are valid CloudFormation).
_pf_kmslock_pol(name) := v if {
	v := object.get(input.resources[name].properties, "KeyPolicy", null)
	is_object(v)
}

_pf_kmslock_pol(name) := v if {
	raw := object.get(input.resources[name].properties, "KeyPolicy", null)
	is_string(raw)
	v := json.unmarshal(raw)
	is_object(v)
}

# Statement may be a single object or an array of objects.
_pf_kmslock_stmts(pol) := [s] if {
	s := object.get(pol, "Statement", null)
	is_object(s)
}

_pf_kmslock_stmts(pol) := arr if {
	arr := object.get(pol, "Statement", null)
	is_array(arr)
}

_pf_kmslock_list(v) := [v] if not is_array(v)

_pf_kmslock_list(v) := v if is_array(v)

_pf_kmslock_types := ["AWS::KMS::Key", "AWS::KMS::ReplicaKey"]

# The account check uses data.cdk_preflight.deploy_account (enforce mode); without it any account counts as ours.
_pf_kmslock_acct(a) if a == data.cdk_preflight.deploy_account

_pf_kmslock_acct(_) if not data.cdk_preflight.deploy_account

_pf_kmslock_ours(p) if p == "*"

_pf_kmslock_ours(p) if {
	regex.match("^[0-9]{12}$", p)
	_pf_kmslock_acct(p)
}

_pf_kmslock_ours(p) if {
	parts := split(p, ":")
	count(parts) >= 6
	parts[0] == "arn"
	parts[2] in ["iam", "sts"]
	_pf_kmslock_acct(parts[4])
}

# unresolved principals (intrinsics) may well be ours
_pf_kmslock_ours(p) if not is_string(p)

_pf_kmslock_covers(a) if not is_string(a)

_pf_kmslock_covers(a) if {
	is_string(a)
	pat := replace(lower(a), "*", ".*")
	regex.match(sprintf("^%s$", [pat]), "kms:putkeypolicy")
}

_pf_kmslock_grants(s) if {
	is_object(s)
	object.get(s, "Effect", "Allow") == "Allow"
	pr := object.get(s, "Principal", null)
	_pf_kmslock_principal_ours(pr)
	_pf_kmslock_action_covers(s)
}

# NotPrincipal / NotAction statements are treated as granting (never a false positive)
_pf_kmslock_grants(s) if {
	is_object(s)
	object.get(s, "Effect", "Allow") == "Allow"
	object.get(s, "NotPrincipal", "__pf_absent") != "__pf_absent"
}

_pf_kmslock_principal_ours(pr) if pr == "*"

_pf_kmslock_principal_ours(pr) if {
	is_object(pr)
	some p in _pf_kmslock_list(object.get(pr, "AWS", []))
	_pf_kmslock_ours(p)
}

_pf_kmslock_action_covers(s) if {
	some a in _pf_kmslock_list(object.get(s, "Action", []))
	_pf_kmslock_covers(a)
}

_pf_kmslock_action_covers(s) if object.get(s, "NotAction", "__pf_absent") != "__pf_absent"

_pf_kmslock_action_covers(s) if {
	a := object.get(s, "Action", null)
	not is_string(a)
	not is_array(a)
	a != null
}

violation contains make_diag_full("pf-kms-key-policy-lockout", "ERROR", name,
	"Properties.KeyPolicy",
	"no Allow statement grants kms:PutKeyPolicy to a principal of this account, so the key would become unmanageable; CreateKey fails with \"The new key policy will not allow you to update the key policy in the future.\"",
	_pf_kmslock_fix, _pf_kmslock_url) if {
	some t in _pf_kmslock_types
	some name in resources_of_type(t)
	pol := _pf_kmslock_pol(name)
	not resolve(name, "Properties.BypassPolicyLockoutSafetyCheck") in {true, "true"}
	stmts := _pf_kmslock_stmts(pol)
	count(stmts) > 0
	not _pf_kmslock_any(stmts)
}

_pf_kmslock_any(stmts) if {
	some s in stmts
	_pf_kmslock_grants(s)
}
