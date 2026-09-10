package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53-healthcheck-requestinterval-discrete", "ERROR", name,
	"Properties.HealthCheckConfig.RequestInterval",
	sprintf("RequestInterval %v is not one of the two intervals Route 53 offers (10 or 30 seconds)", [v]),
	"Set RequestInterval to 10 (fast) or 30 (standard)",
	"https://docs.aws.amazon.com/Route53/latest/APIReference/API_HealthCheckConfig.html") if {
	some name in resources_of_type("AWS::Route53::HealthCheck")
	cfg := _pf_r53z_hcc(name)
	v := to_number(_pf_r53z_get(cfg, "RequestInterval"))
	not v in {10, 30}
}
