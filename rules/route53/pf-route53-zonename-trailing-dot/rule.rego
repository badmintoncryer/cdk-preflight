package cdk_preflight

import rego.v1

# CloudFormation looks the zone up by the literal HostedZoneName and does not
# normalize the trailing dot: the same stack deployed clean with
# "zone.example." and failed with NotFound for "zone.example" (2026-09-02).
violation contains make_diag_full("pf-route53-zonename-trailing-dot", "ERROR", name,
	"Properties.HostedZoneName",
	sprintf("HostedZoneName '%s' is missing the trailing dot, so CloudFormation fails the lookup with \"No hosted zone with name ... found\"", [zn]),
	sprintf("Use '%s.' (with the trailing dot)", [zn]),
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-route53-recordset.html") if {
	some name in resources_of_type("AWS::Route53::RecordSet")
	zn := resolve(name, "Properties.HostedZoneName")
	is_string(zn)
	zn != ""
	not endswith(zn, ".")
}
