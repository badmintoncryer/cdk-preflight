package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53-healthcheck-childhealthchecks-quota-255", "WARN", name,
	"Properties.HealthCheckConfig.ChildHealthChecks",
	sprintf("%d child health checks exceed the 255 a calculated health check can monitor", [n]),
	"Split the children across a tree of calculated health checks",
	"https://docs.aws.amazon.com/general/latest/gr/r53.html") if {
	some name in resources_of_type("AWS::Route53::HealthCheck")
	cfg := _pf_r53z_hcc(name)
	_pf_r53z_str(cfg, "Type") == "CALCULATED"
	n := count(object.get(cfg, "ChildHealthChecks", []))
	n > 255
}
