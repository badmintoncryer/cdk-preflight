package cdk_preflight

import rego.v1

# The CFN schema caps Policy at 20,480 characters, so 10,241-20,480 passes
# every schema layer and is rejected by the service. The service measures the
# MINIFIED document: a pretty-printed 16,078-character body whose minified
# length is 10,000 is accepted (api 2026-09-25), so the raw string length is
# the wrong thing to count. json.marshal re-minifies what json.unmarshal read.

violation contains make_diag_full("pf-aoss-policy-document-size", "ERROR", name,
	"Properties.Policy",
	sprintf("the policy document is %v bytes once minified; Create*Policy answers \"Your request exceeds the %v-policy-max-size-bytes limit of 10240 bytes per %v policy\"", [n, t, upper(t)]),
	"Split the rules across several policies, or widen the resource patterns so fewer are needed",
	"https://docs.aws.amazon.com/general/latest/gr/opensearch-service.html#opensearch-limits-serverless") if {
	some name in _pf_aoss_policy_names
	t := resolve(name, "Properties.Type")
	d := _pf_aoss_doc(name)
	n := count(json.marshal(d))
	n > 10240
}
