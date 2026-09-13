package cdk_preflight

import rego.v1

# The CloudFormation reference documents RegexString as optional, but there is
# nothing to detect without it and CreateCustomEntityType rejects a null value.
violation contains make_diag_full("pf-glue-custom-entity-type-regex-string-required", "ERROR", name,
	"Properties.RegexString",
	"The custom entity type has no RegexString; CreateCustomEntityType fails with \"Value null at 'regexString' failed to satisfy constraint: Member must not be null\"",
	"Add RegexString with the pattern the entity type matches",
	"https://docs.aws.amazon.com/glue/latest/webapi/API_CreateCustomEntityType.html") if {
	some name in resources_of_type("AWS::Glue::CustomEntityType")
	_pf_gluelib_absent(name, "RegexString")
}
