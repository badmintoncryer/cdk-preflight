package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53-keysigningkey-max-2-per-zone", "ERROR", name,
	"Properties.HostedZoneId",
	sprintf("%d key signing keys are attached to hosted zone %s; Route 53 answers TooManyKeySigningKeys above two", [count(_pf_r53z_ksks_of(z)), z]),
	"Keep at most two key signing keys per hosted zone",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-route53-keysigningkey.html") if {
	some name in resources_of_type("AWS::Route53::KeySigningKey")
	z := _pf_r53z_zone_of(name)
	count(_pf_r53z_ksks_of(z)) > 2
}
