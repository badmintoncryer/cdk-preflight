package cdk_preflight

import rego.v1

_pf_iampap_arns contains [name, path, v] if {
	some t in {"AWS::IAM::Role", "AWS::IAM::User", "AWS::IAM::Group"}
	some name in resources_of_type(t)
	some p in flatten_list(name, "Properties.ManagedPolicyArns")
	v := p.value
	path := sprintf("Properties.ManagedPolicyArns.%d", [p.index])
}

_pf_iampap_arns contains [name, "Properties.PermissionsBoundary", v] if {
	some t in {"AWS::IAM::Role", "AWS::IAM::User"}
	some name in resources_of_type(t)
	v := resolve(name, "Properties.PermissionsBoundary")
}

violation contains make_diag_full("pf-iam-policy-arn-partition", "ERROR", name,
	path,
	sprintf("Policy ARN '%s' names partition '%s' but the stack deploys into '%s'; IAM rejects the attachment with \"Invalid ARN partition\"", [v, parts[1], _pf_iamlib_partition]),
	sprintf("Use the deploy partition (arn:%s:iam::aws:policy/...) or build the ARN from the AWS::Partition pseudo parameter", [_pf_iamlib_partition]),
	"https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html") if {
	some [name, path, v] in _pf_iampap_arns
	is_string(v)
	startswith(v, "arn:")
	parts := split(v, ":")
	count(parts) >= 6
	parts[1] != _pf_iamlib_partition
}
