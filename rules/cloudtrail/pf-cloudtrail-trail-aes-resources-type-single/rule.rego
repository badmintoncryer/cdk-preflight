package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-cloudtrail-trail-aes-resources-type-single", "ERROR", name,
	"Properties.AdvancedEventSelectors.FieldSelectors",
	sprintf("advanced event selector %v has %v resources.type field selectors; CloudTrail allows one per selector", [i, n]),
	"Split the resource types across separate advanced event selectors",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-cloudtrail-trail-advancedfieldselector.html") if {
	some name in resources_of_type("AWS::CloudTrail::Trail")
	some i, s in _pf_ctlib_aes(name)
	n := count(_pf_ctlib_fields_named(s, "resources.type"))
	n > 1
}
