package cdk_preflight

import rego.v1

_pf_r53_typol_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-route53-recordset.html"

_pf_r53_typol_props := ["Weight", "Region", "Failover", "GeoLocation", "CidrRoutingConfig"]

_pf_r53_typol_has_policy(name) if {
	some p in _pf_r53_typol_props
	resolve(name, sprintf("Properties.%s", [p])) != null
}

_pf_r53_typol_has_policy(name) if {
	resolve(name, "Properties.MultiValueAnswer") == true
}

# Only combinations that failed on a real deploy are flagged. DS with a routing
# policy is documented as unsupported but the API accepted it (2026-09-08), so
# it is deliberately left out.
violation contains make_diag_full("pf-route53-record-type-routing-policy", "ERROR", name,
	"Properties.Type",
	"An NS record cannot use a routing policy; the service rejects it with \"this type of RRSet is not supported\"",
	"Use a simple record set for NS records (no Weight/Region/Failover/GeoLocation/MultiValueAnswer/CidrRoutingConfig)",
	_pf_r53_typol_url) if {
	some name in resources_of_type("AWS::Route53::RecordSet")
	resolve(name, "Properties.Type") == "NS"
	_pf_r53_typol_has_policy(name)
}

violation contains make_diag_full("pf-route53-record-type-routing-policy", "ERROR", name,
	"Properties.Type",
	"An SOA record cannot use a routing policy; the service rejects it with \"this type of RRSet is not supported\"",
	"Use a simple record set for the SOA record",
	_pf_r53_typol_url) if {
	some name in resources_of_type("AWS::Route53::RecordSet")
	resolve(name, "Properties.Type") == "SOA"
	_pf_r53_typol_has_policy(name)
}

violation contains make_diag_full("pf-route53-record-type-routing-policy", "ERROR", name,
	"Properties.Type",
	"A CNAME record cannot use the multivalue answer routing policy; the service rejects it with \"this type of RRSet is not supported\"",
	"Point the multivalue records at A/AAAA (or another supported type), or drop MultiValueAnswer",
	_pf_r53_typol_url) if {
	some name in resources_of_type("AWS::Route53::RecordSet")
	resolve(name, "Properties.Type") == "CNAME"
	resolve(name, "Properties.MultiValueAnswer") == true
}
