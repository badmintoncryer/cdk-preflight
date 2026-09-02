package cdk_preflight

import rego.v1

# Resource-based policies require Principal (or NotPrincipal) in every
# statement — unlike identity policies, where cfn-lint-grade checks are
# tuned. An unresolvable Principal value still counts as present.
violation contains make_diag_full("pf-s3-bucket-policy-principal", "ERROR", name,
	sprintf("Properties.PolicyDocument.Statement.%d", [st.index]),
	"The statement has neither Principal nor NotPrincipal; S3 rejects the policy with \"Missing required field Principal\"",
	"Add a Principal (or NotPrincipal) to the statement — bucket policies always name who they apply to",
	"https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-policies.html") if {
	some name in resources_of_type("AWS::S3::BucketPolicy")
	some st in flatten_list(name, "Properties.PolicyDocument.Statement")
	is_object(st.value)
	object.get(st.value, "Principal", "__pf_absent") == "__pf_absent"
	object.get(st.value, "NotPrincipal", "__pf_absent") == "__pf_absent"
}
