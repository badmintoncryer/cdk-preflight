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

# Only combinations that failed on a real deploy are flagged. SOA/DS with a
# routing policy are also documented as unsupported but were not measured, so
# they are deliberately left out (see the discovery issue).
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
	"A CNAME record cannot use the multivalue answer routing policy; the service rejects it with \"this type of RRSet is not supported\"",
	"Point the multivalue records at A/AAAA (or another supported type), or drop MultiValueAnswer",
	_pf_r53_typol_url) if {
	some name in resources_of_type("AWS::Route53::RecordSet")
	resolve(name, "Properties.Type") == "CNAME"
	resolve(name, "Properties.MultiValueAnswer") == true
}
