package cdk_preflight

import rego.v1

# The service answers two different sentences - one for a value outside the set
# and one for the property being left out - and neither is a schema error, so
# both directions are here.
_pf_glueudfot_valid := {"USER", "ROLE", "GROUP"}

violation contains make_diag_full("pf-glue-user-defined-function-owner-type", "ERROR", name,
	"Properties.OwnerType",
	sprintf("OwnerType \"%s\" is not one of USER, ROLE or GROUP; CreateUserDefinedFunction fails with \"Owner Type is not valid\"", [ot]),
	"Set OwnerType to USER, ROLE or GROUP",
	"https://docs.aws.amazon.com/glue/latest/webapi/API_UserDefinedFunctionInput.html") if {
	some name in resources_of_type("AWS::Glue::UserDefinedFunction")
	ot := _pf_gluelib_str(name, "Properties.OwnerType")
	not ot in _pf_glueudfot_valid
}

violation contains make_diag_full("pf-glue-user-defined-function-owner-type", "ERROR", name,
	"Properties.OwnerType",
	"The function has no OwnerType; CreateUserDefinedFunction fails with \"Owner type for function can not be null\"",
	"Set OwnerType to USER, ROLE or GROUP",
	"https://docs.aws.amazon.com/glue/latest/webapi/API_UserDefinedFunctionInput.html") if {
	some name in resources_of_type("AWS::Glue::UserDefinedFunction")
	_pf_gluelib_absent(name, "OwnerType")
}
