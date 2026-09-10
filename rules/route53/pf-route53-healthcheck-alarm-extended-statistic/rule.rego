package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53-healthcheck-alarm-extended-statistic", "ERROR", name,
	"Properties.HealthCheckConfig.AlarmIdentifier",
	sprintf("the CloudWatch alarm health check watches %s, which uses ExtendedStatistic; Route 53 only supports Average, Minimum, Maximum, Sum and SampleCount", [al]),
	"Use one of Average, Minimum, Maximum, Sum or SampleCount for the watched alarm",
	"https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/health-checks-creating-values.html") if {
	some name in resources_of_type("AWS::Route53::HealthCheck")
	cfg := _pf_r53z_hcc(name)
	_pf_r53z_str(cfg, "Type") == "CLOUDWATCH_METRIC"
	al := _pf_r53z_alarm_of(cfg)
	_pf_r53z_has(_pf_r53z_props(al), "ExtendedStatistic")
}
