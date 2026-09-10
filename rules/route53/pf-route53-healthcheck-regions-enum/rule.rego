package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53-healthcheck-regions-enum", "ERROR", name,
	"Properties.HealthCheckConfig.Regions",
	sprintf("region %s cannot host Route 53 health checkers; pick from us-east-1, us-west-1, us-west-2, eu-west-1, ap-southeast-1, ap-southeast-2, ap-northeast-1, sa-east-1", [v]),
	"Use only the eight regions Route 53 places health checkers in",
	"https://docs.aws.amazon.com/Route53/latest/APIReference/API_HealthCheckConfig.html") if {
	some name in resources_of_type("AWS::Route53::HealthCheck")
	cfg := _pf_r53z_hcc(name)
	some v in object.get(cfg, "Regions", [])
	is_string(v)
	not v in _pf_r53z_checker_regions
}
