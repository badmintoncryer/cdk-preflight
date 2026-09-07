package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-iam-permissions-boundary-policy-arn", "ERROR", name,
	"Properties.PermissionsBoundary",
	sprintf("PermissionsBoundary '%s' does not name a policy; IAM rejects the entity with \"ARN ... is not valid.\"", [v]),
	"Point PermissionsBoundary at a managed policy ARN (arn:aws:iam::<account>:policy/<name> or arn:aws:iam::aws:policy/<name>) — a role or user ARN is not a boundary",
	"https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html") if {
	some t in {"AWS::IAM::Role", "AWS::IAM::User"}
	some name in resources_of_type(t)
	v := resolve(name, "Properties.PermissionsBoundary")
	is_string(v)
	startswith(v, "arn:")
	parts := split(v, ":")
	count(parts) >= 6
	not startswith(parts[5], "policy/")
}
