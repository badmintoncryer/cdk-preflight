package cdk_preflight

import rego.v1

_pf_glueudfru_valid := {"JAR", "FILE", "ARCHIVE"}

violation contains make_diag_full("pf-glue-user-defined-function-resource-uri-type", "ERROR", name,
	sprintf("Properties.ResourceUris.%d.ResourceType", [i]),
	sprintf("ResourceType \"%s\" is not one of JAR, FILE or ARCHIVE; CreateUserDefinedFunction fails with \"Resource Type is not valid\"", [rt]),
	"Set ResourceType to JAR, FILE or ARCHIVE",
	"https://docs.aws.amazon.com/glue/latest/webapi/API_UserDefinedFunctionInput.html") if {
	some name in resources_of_type("AWS::Glue::UserDefinedFunction")
	arr := _pf_gluelib_get(name, "ResourceUris")
	is_array(arr)
	some i, u in arr
	is_object(u)
	rt := object.get(u, "ResourceType", null)
	_pf_gluelib_lit(rt)
	not rt in _pf_glueudfru_valid
}
