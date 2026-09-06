package cdk_preflight

import rego.v1

_pf_tgwasn_ok(n) if {
	n >= 64512
	n <= 65534
}

_pf_tgwasn_ok(n) if {
	n >= 4200000000
	n <= 4294967294
}

violation contains make_diag_full("pf-ec2-tgw-amazon-side-asn", "ERROR", name,
	"Properties.AmazonSideAsn",
	sprintf("AmazonSideAsn %v is outside the private ASN ranges 64512-65534 and 4200000000-4294967294", [n]),
	"Use a private ASN such as 64512",
	"https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_TransitGatewayRequestOptions.html") if {
	some name in resources_of_type("AWS::EC2::TransitGateway")
	n := to_number(resolve(name, "Properties.AmazonSideAsn"))
	not _pf_tgwasn_ok(n)
}
