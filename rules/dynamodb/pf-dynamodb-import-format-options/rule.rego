package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-dynamodb-import-format-options", "ERROR", name,
	"Properties.ImportSourceSpecification.InputFormatOptions",
	sprintf("InputFormatOptions is set but InputFormat is %s; ImportTable fails with \"Unsupported InputFormatOptions for the given input format: %s\"", [fmt, fmt]),
	"Drop InputFormatOptions for DYNAMODB_JSON and ION imports; it only carries CSV options",
	"https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/S3DataImport.Requesting.html") if {
	some name in resources_of_type("AWS::DynamoDB::Table")
	imp := resolve(name, "Properties.ImportSourceSpecification")
	is_object(imp)
	fmt := object.get(imp, "InputFormat", null)
	is_string(fmt)
	fmt != "CSV"
	object.get(imp, "InputFormatOptions", "__pf_absent") != "__pf_absent"
}
