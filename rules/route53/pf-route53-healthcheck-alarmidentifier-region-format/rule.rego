package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53-healthcheck-alarmidentifier-region-format", "ERROR", name,
	"Properties.HealthCheckConfig.AlarmIdentifier.Region",
	sprintf("AlarmIdentifier.Region %s is not a region name; Route 53 takes the region the CloudWatch alarm lives in", [rg]),
	"Use the alarm's region, for example us-east-1",
	"https://docs.aws.amazon.com/Route53/latest/APIReference/API_HealthCheckConfig.html") if {
	some name in resources_of_type("AWS::Route53::HealthCheck")
	cfg := _pf_r53z_hcc(name)
	ai := _pf_r53z_get(cfg, "AlarmIdentifier")
	is_object(ai)
	rg := object.get(ai, "Region", null)
	is_string(rg)
	not _pf_r53z_region_shape(rg)
}
