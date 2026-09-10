package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53-healthcheck-searchstring-required-strmatch", "ERROR", name,
	"Properties.HealthCheckConfig",
	sprintf("a %s health check has no SearchString, so there is nothing to look for in the response body", [t]),
	"Add SearchString, or drop _STR_MATCH from the health check type",
	"https://docs.aws.amazon.com/Route53/latest/APIReference/API_HealthCheckConfig.html") if {
	some name in resources_of_type("AWS::Route53::HealthCheck")
	cfg := _pf_r53z_hcc(name)
	t := _pf_r53z_str(cfg, "Type")
	t in _pf_r53z_strmatch_types
	not _pf_r53z_has(cfg, "SearchString")
}
