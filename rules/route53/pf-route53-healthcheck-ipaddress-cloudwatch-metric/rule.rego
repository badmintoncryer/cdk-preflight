package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53-healthcheck-ipaddress-cloudwatch-metric", "ERROR", name,
	"Properties.HealthCheckConfig.IPAddress",
	"IPAddress is set on a CLOUDWATCH_METRIC health check, which watches an alarm instead of an endpoint",
	"Drop IPAddress from the CloudWatch alarm health check",
	"https://docs.aws.amazon.com/Route53/latest/APIReference/API_HealthCheckConfig.html") if {
	some name in resources_of_type("AWS::Route53::HealthCheck")
	cfg := _pf_r53z_hcc(name)
	_pf_r53z_str(cfg, "Type") == "CLOUDWATCH_METRIC"
	_pf_r53z_has(cfg, "IPAddress")
}
