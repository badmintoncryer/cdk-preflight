package cdk_preflight

import rego.v1

_pf_s3pbp_fix := "Scope the statement to a concrete principal, or set BlockPublicPolicy to false"

_pf_s3pbp_url := "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html"

_pf_s3pbp_anyone(pr) if pr == "*"

_pf_s3pbp_anyone(pr) if {
	is_object(pr)
	object.get(pr, "AWS", "") == "*"
}

_pf_s3pbp_anyone(pr) if {
	is_object(pr)
	l := object.get(pr, "AWS", [])
	is_array(l)
	some a in l
	a == "*"
}

violation contains make_diag_full("pf-s3-policy-public-with-block-public-policy", "ERROR", p,
	sprintf("Properties.PolicyDocument.Statement.%d.Principal", [st.index]),
	"the statement allows every principal while the bucket sets BlockPublicPolicy: true; PutBucketPolicy rejects it",
	_pf_s3pbp_fix, _pf_s3pbp_url) if {
	some p in resources_of_type("AWS::S3::BucketPolicy")
	b := resolve(p, "Properties.Bucket")
	b in resources_of_type("AWS::S3::Bucket")
	resolve(b, "Properties.PublicAccessBlockConfiguration.BlockPublicPolicy") == true
	some st in flatten_list(p, "Properties.PolicyDocument.Statement")
	is_object(st.value)
	object.get(st.value, "Effect", "") == "Allow"
	object.get(st.value, "Condition", "__pf_absent") == "__pf_absent"
	_pf_s3pbp_anyone(object.get(st.value, "Principal", null))
}
