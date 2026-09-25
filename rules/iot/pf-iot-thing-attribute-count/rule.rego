package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-iot-thing-attribute-count", "ERROR", name,
	"Properties.AttributePayload.Attributes",
	sprintf("the thing carries %d attributes; more than 3 needs a thing type, which AWS::IoT::Thing cannot set, and CreateThing answers \"To use more than 3 attributes, a thing must have a type specified.\"", [count(attrs)]),
	"Keep the thing to 3 attributes",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-iot-thing.html") if {
	some name in resources_of_type("AWS::IoT::Thing")
	attrs := object.get(_pf_iotlib_props(name), ["AttributePayload", "Attributes"], null)
	_pf_iotlib_plain_obj(attrs)
	count(attrs) > 3
}
