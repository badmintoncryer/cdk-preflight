package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53-healthcheck-alarm-metric-math", "ERROR", name,
	"Properties.HealthCheckConfig.AlarmIdentifier",
	sprintf("the CloudWatch alarm health check watches %s, which is a metric math alarm; Route 53 can only monitor an alarm on a single metric", [al]),
	"Point the health check at an alarm on one metric",
	"https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/health-checks-creating-values.html") if {
	some name in resources_of_type("AWS::Route53::HealthCheck")
	cfg := _pf_r53z_hcc(name)
	_pf_r53z_str(cfg, "Type") == "CLOUDWATCH_METRIC"
	al := _pf_r53z_alarm_of(cfg)
	some m in flatten_list(al, "Properties.Metrics")
	is_object(m.value)
	is_string(object.get(m.value, "Expression", null))
}
