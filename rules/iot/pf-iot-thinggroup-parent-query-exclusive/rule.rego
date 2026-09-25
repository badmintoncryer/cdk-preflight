package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-iot-thinggroup-parent-query-exclusive", "ERROR", name,
	"Properties.QueryString",
	"the thing group sets both ParentGroupName and QueryString; the CloudFormation handler answers \"Thing group cannot have a QueryString and a ParentGroup\" (the service API cannot express the combination at all - CreateDynamicThingGroup has no parentGroupName argument)",
	"Drop ParentGroupName from the dynamic group, or drop QueryString and make it a static child group",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-iot-thinggroup.html") if {
	some name in resources_of_type("AWS::IoT::ThingGroup")
	_pf_iotlib_has(name, "ParentGroupName")
	_pf_iotlib_has(name, "QueryString")
}
