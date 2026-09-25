package cdk_preflight

import rego.v1

# _pf_aoss_doc is bound with := before the negation: `not is_array(f(x))`
# reads true when f is undefined, and f is undefined for exactly the policy a
# CDK app usually emits (Fn::Join over a collection Ref). Binding first turns
# that case into "no match" instead of a false ERROR.

violation contains make_diag_full("pf-aoss-access-policy-top-level-array", "ERROR", name,
	"Properties.Policy",
	"the data access policy document is a JSON object; CreateAccessPolicy answers \"Policy json is invalid, error: [$: object found, array expected]\"",
	"Wrap the rule block in an array: [{\"Rules\": [...], \"Principal\": [...]}]",
	"https://docs.aws.amazon.com/opensearch-service/latest/developerguide/serverless-data-access.html") if {
	some name in _pf_aoss_data
	d := _pf_aoss_doc(name)
	not is_array(d)
}
