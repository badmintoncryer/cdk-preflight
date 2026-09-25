package cdk_preflight

import rego.v1

# "You can specify only one type of parameter" - and none is the same error as
# two. The count only means something once the object is free of intrinsics,
# because count() over a marker object returns its marker keys.
violation contains make_diag_full("pf-iot-mitigationaction-params-exactly-one", "ERROR", name,
	"Properties.ActionParams",
	sprintf("ActionParams carries %d parameter types; CreateMitigationAction answers \"Expected only one action parameter to be set\"", [count(ap)]),
	"Leave exactly one of the ActionParams members in place",
	"https://docs.aws.amazon.com/iot/latest/apireference/API_MitigationActionParams.html") if {
	some name in resources_of_type("AWS::IoT::MitigationAction")
	ap := object.get(_pf_iotlib_props(name), "ActionParams", null)
	_pf_iotlib_plain_obj(ap)
	count(ap) != 1
}
