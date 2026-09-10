package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53-hostedzone-vpc-region-format", "ERROR", name,
	"Properties.VPCs",
	sprintf("VPCRegion %s is not a region name; give the region the VPC lives in", [rg]),
	"Use the VPC's region, for example us-east-1",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-route53-hostedzone.html") if {
	some name in resources_of_type("AWS::Route53::HostedZone")
	some v in _pf_r53z_vpcs(name)
	is_object(v)
	rg := object.get(v, "VPCRegion", null)
	is_string(rg)
	not _pf_r53z_region_shape(rg)
}
