package cdk_preflight

import rego.v1

# PutClusterPolicy refuses a policy whose statements name a different cluster: "The cluster policy
# is not valid. Invalid cluster arn: \"<arn>\" ... InvalidParameter: policy". The realistic mistake
# is copying a policy between two clusters and forgetting the Resource.
# Only fully literal kafka ARNs are compared -- a Ref/GetAtt is a marker object (is_string is
# false) and a wildcard is left alone.
_pf_mskcprm_res(name) := rs if {
	rs := [r |
		some st in flatten_list(name, "Properties.Policy.Statement")
		r := _pf_mskcprm_one(st.value)
	]
}

_pf_mskcprm_one(st) := r if {
	is_string(st.Resource)
	r := st.Resource
}

violation contains make_diag_full("pf-msk-clusterpolicy-resource-matches-cluster", "ERROR", name,
	"Properties.Policy.Statement",
	sprintf("the policy grants access to '%s' but is attached to '%s'; PutClusterPolicy fails with \"The cluster policy is not valid. Invalid cluster arn\"", [r, carn]),
	"Point every statement's Resource at the same cluster the policy is attached to",
	"https://docs.aws.amazon.com/msk/latest/developerguide/aws-access-mult-vpc.html") if {
	some name in resources_of_type("AWS::MSK::ClusterPolicy")
	carn := resolve(name, "Properties.ClusterArn")
	startswith(carn, "arn:")
	some r in _pf_mskcprm_res(name)
	startswith(r, "arn:")
	startswith(r, "arn:aws")
	contains(r, ":kafka:")
	not contains(r, "*")
	r != carn
}
