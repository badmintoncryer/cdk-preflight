package cdk_preflight

import rego.v1

_pf_waflu_url := "https://docs.aws.amazon.com/waf/latest/APIReference/API_PutLoggingConfiguration.html"

_pf_waflu_fix := "Keep a single LoggingConfiguration per web ACL (filters and redactions go in that one resource)"

_pf_waflu_key(name) := json.marshal(input.resources[name].properties.ResourceArn)

violation contains make_diag_full("pf-wafv2-logging-unique", "ERROR", n2, "Properties.ResourceArn",
	sprintf("%s already configures logging for this web ACL; the second one fails with \"already exists\" (a web ACL has one logging configuration)", [n1]),
	_pf_waflu_fix, _pf_waflu_url) if {
	some n1 in resources_of_type("AWS::WAFv2::LoggingConfiguration")
	some n2 in resources_of_type("AWS::WAFv2::LoggingConfiguration")
	n1 < n2
	_pf_waflu_key(n1) == _pf_waflu_key(n2)
}
