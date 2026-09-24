package cdk_preflight

import rego.v1

_pf_ctequals_fields := {"eventCategory", "readOnly", "resources.type"}

violation contains make_diag_full("pf-cloudtrail-trail-aes-event-category-equals-only", "ERROR", name,
	"Properties.AdvancedEventSelectors.FieldSelectors",
	sprintf("field selector '%v' uses %v; Equals is the only operator CloudTrail accepts for eventCategory, readOnly and resources.type", [fld, op]),
	"Rewrite the condition with Equals",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-cloudtrail-trail-advancedfieldselector.html") if {
	some name in resources_of_type("AWS::CloudTrail::Trail")
	some s in _pf_ctlib_aes(name)
	some fs in _pf_ctlib_field_selectors(s)
	fld := object.get(fs, "Field", null)
	fld in _pf_ctequals_fields
	some op in _pf_ctlib_operators(fs)
	op != "Equals"
}
