package cdk_preflight

import rego.v1

# An object-level action whose statement lists only bucket-level ARNs applies
# to nothing, and S3 rejects the policy. A bucket-level ARN is provable two
# ways: a literal arn:...:s3:::name with no "/" in the name part, or a value
# that resolve() turns into the logical ID of an in-template bucket (Ref and
# Fn::GetAtt Arn both do — the GetAtt of a bucket is its bucket ARN). Fires
# only when every resource in the statement is provably bucket-level, so
# unresolvable entries (e.g. Fn::Sub "${B.Arn}/*") mute the statement.

_pf_s3bpar_object_action(a) if startswith(lower(a), "s3:getobject")

_pf_s3bpar_object_action(a) if startswith(lower(a), "s3:putobject")

_pf_s3bpar_object_action(a) if startswith(lower(a), "s3:deleteobject")

_pf_s3bpar_object_action(a) if lower(a) in {"s3:abortmultipartupload", "s3:restoreobject", "s3:listmultipartuploadparts"}

_pf_s3bpar_bucket_level(r) if r in resources_of_type("AWS::S3::Bucket")

_pf_s3bpar_bucket_level(r) if {
	startswith(r, "arn:")
	contains(r, ":s3:::")
	parts := split(r, ":::")
	count(parts) == 2
	not contains(parts[1], "/")
}

_pf_s3bpar_actions(name, i) := [a] if {
	a := resolve(name, sprintf("Properties.PolicyDocument.Statement.%d.Action", [i]))
	is_string(a)
}

_pf_s3bpar_actions(name, i) := acts if {
	items := [it | some it in flatten_list(name, sprintf("Properties.PolicyDocument.Statement.%d.Action", [i]))]
	count(items) > 0
	acts := [v | some it in items; v := it.value; is_string(v)]
}

_pf_s3bpar_resources(name, i) := [r] if {
	r := resolve(name, sprintf("Properties.PolicyDocument.Statement.%d.Resource", [i]))
	is_string(r)
}

_pf_s3bpar_resources(name, i) := rs if {
	items := [it | some it in flatten_list(name, sprintf("Properties.PolicyDocument.Statement.%d.Resource", [i]))]
	count(items) > 0
	rs := [v | some it in items; v := resolve(name, sprintf("Properties.PolicyDocument.Statement.%d.Resource.%d", [i, it.index])); is_string(v)]
	count(rs) == count(items)
}

violation contains make_diag_full("pf-s3-bucket-policy-action-resource", "ERROR", name,
	sprintf("Properties.PolicyDocument.Statement.%d.Resource", [st.index]),
	sprintf("Action '%s' targets objects but the statement's resources are all bucket-level ARNs; S3 rejects the policy with \"Action does not apply to any resource(s) in statement\"", [a]),
	"Add the object form of the ARN (append /* or a key pattern) to Resource, or drop the object-level action",
	"https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-policies.html") if {
	some name in resources_of_type("AWS::S3::BucketPolicy")
	some st in flatten_list(name, "Properties.PolicyDocument.Statement")
	is_object(st.value)
	some a in _pf_s3bpar_actions(name, st.index)
	_pf_s3bpar_object_action(a)
	rs := _pf_s3bpar_resources(name, st.index)
	count(rs) > 0
	every r in rs {
		_pf_s3bpar_bucket_level(r)
	}
}
