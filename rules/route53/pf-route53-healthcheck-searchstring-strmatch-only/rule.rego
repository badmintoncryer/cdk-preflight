package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53-healthcheck-searchstring-strmatch-only", "ERROR", name,
	"Properties.HealthCheckConfig.SearchString",
	sprintf("SearchString is set on a %s health check; only HTTP_STR_MATCH and HTTPS_STR_MATCH read the response body", [t]),
	"Drop SearchString, or switch the type to HTTP_STR_MATCH / HTTPS_STR_MATCH",
	"https://docs.aws.amazon.com/Route53/latest/APIReference/API_HealthCheckConfig.html") if {
	some name in resources_of_type("AWS::Route53::HealthCheck")
	cfg := _pf_r53z_hcc(name)
	_pf_r53z_has(cfg, "SearchString")
	t := _pf_r53z_str(cfg, "Type")
	not t in _pf_r53z_strmatch_types
}
