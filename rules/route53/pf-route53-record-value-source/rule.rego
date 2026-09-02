package cdk_preflight

import rego.v1

_pf_r53_valsrc_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-route53-recordset.html"

# The service expects "exactly one of [AliasTarget, all of [TTL, and
# ResourceRecords]]" (TrafficPolicyInstanceId has no CloudFormation property).
# The TTL+AliasTarget combination is already the engine's E3029, so this rule
# covers the remaining shapes: alias plus records, and an incomplete non-alias
# group (records without TTL, TTL without records, or neither).
_pf_r53_valsrc_has_alias(name) if is_object(resolve(name, "Properties.AliasTarget"))

_pf_r53_valsrc_has_rr(name) if {
	some _ in flatten_list(name, "Properties.ResourceRecords")
}

_pf_r53_valsrc_has_ttl(name) if resolve(name, "Properties.TTL") != null

violation contains make_diag_full("pf-route53-record-value-source", "ERROR", name,
	"Properties.ResourceRecords",
	"AliasTarget and ResourceRecords are mutually exclusive; the service expects exactly one of AliasTarget or TTL-plus-ResourceRecords",
	"Keep the AliasTarget and drop ResourceRecords, or make it a plain record with TTL and ResourceRecords",
	_pf_r53_valsrc_url) if {
	some name in resources_of_type("AWS::Route53::RecordSet")
	_pf_r53_valsrc_has_alias(name)
	_pf_r53_valsrc_has_rr(name)
}

violation contains make_diag_full("pf-route53-record-value-source", "ERROR", name,
	"Properties",
	"A non-alias record set needs both TTL and ResourceRecords; the service rejects an incomplete pair with \"Expected exactly one of [AliasTarget, all of [TTL, and ResourceRecords]] ... found none\"",
	"Specify TTL and ResourceRecords together, or use AliasTarget instead",
	_pf_r53_valsrc_url) if {
	some name in resources_of_type("AWS::Route53::RecordSet")
	not _pf_r53_valsrc_has_alias(name)
	not _pf_r53_valsrc_complete(name)
}

_pf_r53_valsrc_complete(name) if {
	_pf_r53_valsrc_has_rr(name)
	_pf_r53_valsrc_has_ttl(name)
}
