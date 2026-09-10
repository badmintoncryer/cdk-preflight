package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53-healthcheck-alarm-high-resolution", "ERROR", name,
	"Properties.HealthCheckConfig.AlarmIdentifier",
	sprintf("the CloudWatch alarm health check watches %s, whose Period is %v seconds; Route 53 can only monitor standard-resolution alarms (Period 60 or more)", [al, p]),
	"Raise the watched alarm's Period to 60 seconds or more",
	"https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/health-checks-creating-values.html") if {
	some name in resources_of_type("AWS::Route53::HealthCheck")
	cfg := _pf_r53z_hcc(name)
	_pf_r53z_str(cfg, "Type") == "CLOUDWATCH_METRIC"
	al := _pf_r53z_alarm_of(cfg)
	p := to_number(object.get(_pf_r53z_props(al), "Period", "x"))
	p < 60
}
