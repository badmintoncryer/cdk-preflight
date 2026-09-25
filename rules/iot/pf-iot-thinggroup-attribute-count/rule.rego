package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-iot-thinggroup-attribute-count", "ERROR", name,
	"Properties.ThingGroupProperties.AttributePayload.Attributes",
	sprintf("the thing group carries %d attributes; CreateThingGroup answers \"Too many attributes specified. The maximum number of attributes allowed for a thing group is 50\"", [count(attrs)]),
	"Keep the thing group to 50 attributes",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-iot-thinggroup.html") if {
	some name in resources_of_type("AWS::IoT::ThingGroup")
	attrs := object.get(_pf_iotlib_props(name), ["ThingGroupProperties", "AttributePayload", "Attributes"], null)
	_pf_iotlib_plain_obj(attrs)
	count(attrs) > 50
}
