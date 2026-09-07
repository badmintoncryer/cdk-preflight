package cdk_preflight

import rego.v1

# iam and route53 ARNs are region-less whatever the resource type. s3 is only
# region- and account-less for *bucket* ARNs: an access point ARN
# (arn:aws:s3:us-east-1:111122223333:accesspoint/ap) carries both and is valid,
# so the s3 half only judges the bare-name form (no "/" in the resource part).
_pf_iamgsa_noregion := {"iam", "route53"}

_pf_iamgsa_set(v) if {
	v != ""
	not regex.match(`^[*?]+$`, v)
}

_pf_iamgsa_bads(parts) := out if {
	out := [[seg, v] |
		some [seg, idx] in [["region", 3], ["account id", 4]]
		_pf_iamgsa_applies(parts, idx)
		v := parts[idx]
		_pf_iamgsa_set(v)
	]
}

_pf_iamgsa_applies(parts, idx) if {
	parts[2] in _pf_iamgsa_noregion
	idx == 3
}

_pf_iamgsa_applies(parts, _) if {
	parts[2] == "s3"
	not contains(concat(":", array.slice(parts, 5, count(parts))), "/")
}

_pf_iamgsa_label(svc) := "an S3 bucket ARN" if svc == "s3"

_pf_iamgsa_label(svc) := sprintf("a %s ARN", [svc]) if svc != "s3"

violation contains make_diag_full("pf-iam-policy-resource-global-service-arn", "ERROR", name,
	sprintf("%s.Statement.%d", [path, i]),
	sprintf("Resource ARN '%s' carries a %s ('%s'), but %s leaves that segment empty and IAM rejects the document with \"can not contain region information\" / \"cannot contain an account id\"", [v, bad[0], bad[1], _pf_iamgsa_label(parts[2])]),
	"Drop the segment: a bucket is arn:aws:s3:::bucket and a role is arn:aws:iam::123456789012:role/name",
	"https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_resource.html") if {
	some [name, path, d] in _pf_iamlib_all
	some [i, s] in _pf_iamlib_stmts(d)
	is_object(s)
	some v in _pf_iamlib_resources(s)
	is_string(v)
	startswith(v, "arn:")
	parts := split(v, ":")
	count(parts) >= 6
	some bad in _pf_iamgsa_bads(parts)
}
