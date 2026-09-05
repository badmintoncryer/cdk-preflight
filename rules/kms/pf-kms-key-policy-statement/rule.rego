package cdk_preflight

import rego.v1

_pf_kmskps_url := "https://docs.aws.amazon.com/kms/latest/APIReference/API_CreateKey.html"

_pf_kmskps_fix := "Give each statement a Principal (or NotPrincipal), an Action and a Resource (\"*\" for the key itself), and write AWS principals as account ids or arn:...:iam::<account>:... ARNs"

# KeyPolicy arrives as a JSON object or as a JSON string (both are valid CloudFormation).
_pf_kmskps_pol(name) := v if {
	v := object.get(input.resources[name].properties, "KeyPolicy", null)
	is_object(v)
}

_pf_kmskps_pol(name) := v if {
	raw := object.get(input.resources[name].properties, "KeyPolicy", null)
	is_string(raw)
	v := json.unmarshal(raw)
	is_object(v)
}

# Statement may be a single object or an array of objects.
_pf_kmskps_stmts(pol) := [s] if {
	s := object.get(pol, "Statement", null)
	is_object(s)
}

_pf_kmskps_stmts(pol) := arr if {
	arr := object.get(pol, "Statement", null)
	is_array(arr)
}

_pf_kmskps_list(v) := [v] if not is_array(v)

_pf_kmskps_list(v) := v if is_array(v)

_pf_kmskps_types := ["AWS::KMS::Key", "AWS::KMS::ReplicaKey"]

violation contains make_diag_full("pf-kms-key-policy-statement", "ERROR", name,
	"Properties.KeyPolicy.Statement",
	"KeyPolicy has no statements; CreateKey fails with MalformedPolicyDocumentException",
	_pf_kmskps_fix, _pf_kmskps_url) if {
	some t in _pf_kmskps_types
	some name in resources_of_type(t)
	pol := _pf_kmskps_pol(name)
	count(_pf_kmskps_stmts(pol)) == 0
}

violation contains make_diag_full("pf-kms-key-policy-statement", "ERROR", name,
	"Properties.KeyPolicy.Statement",
	"KeyPolicy.Statement is missing or not a list/object; CreateKey fails with MalformedPolicyDocumentException",
	_pf_kmskps_fix, _pf_kmskps_url) if {
	some t in _pf_kmskps_types
	some name in resources_of_type(t)
	pol := _pf_kmskps_pol(name)
	not _pf_kmskps_stmts(pol)
}

_pf_kmskps_missing := {
	"Principal": ["Principal", "NotPrincipal", "Policy contains a statement with no principal."],
	"Action": ["Action", "NotAction", "Missing required field Action"],
	"Resource": ["Resource", "NotResource", "Missing required field Resource"],
}

violation contains make_diag_full("pf-kms-key-policy-statement", "ERROR", name,
	sprintf("Properties.KeyPolicy.Statement.%d", [i]),
	sprintf("statement %d has no %s; CreateKey fails with \"%s\"", [i, field, spec[2]]),
	_pf_kmskps_fix, _pf_kmskps_url) if {
	some t in _pf_kmskps_types
	some name in resources_of_type(t)
	some i, s in _pf_kmskps_stmts(_pf_kmskps_pol(name))
	is_object(s)
	some field, spec in _pf_kmskps_missing
	object.get(s, spec[0], "__pf_absent") == "__pf_absent"
	object.get(s, spec[1], "__pf_absent") == "__pf_absent"
}

_pf_kmskps_principal_ok(p) if p == "*"

_pf_kmskps_principal_ok(p) if regex.match("^[0-9]{12}$", p)

_pf_kmskps_principal_ok(p) if regex.match("^arn:[a-z-]+:(iam|sts)::", p)

violation contains make_diag_full("pf-kms-key-policy-statement", "ERROR", name,
	sprintf("Properties.KeyPolicy.Statement.%d.Principal.AWS", [i]),
	sprintf("AWS principal '%s' is neither *, a 12-digit account id nor an IAM/STS ARN; CreateKey fails with \"Policy contains a statement with one or more invalid principals.\"", [p]),
	_pf_kmskps_fix, _pf_kmskps_url) if {
	some t in _pf_kmskps_types
	some name in resources_of_type(t)
	some i, s in _pf_kmskps_stmts(_pf_kmskps_pol(name))
	is_object(s)
	pr := object.get(s, "Principal", null)
	is_object(pr)
	some p in _pf_kmskps_list(object.get(pr, "AWS", null))
	is_string(p)
	not _pf_kmskps_principal_ok(p)
}
