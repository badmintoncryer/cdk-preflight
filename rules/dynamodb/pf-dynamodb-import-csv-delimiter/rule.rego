package cdk_preflight

import rego.v1

# The CFN schema carries the pattern and Maximum 1, but the bundled engine
# does not evaluate them (measured 2026-09-08, 1.7.0-beta).
violation contains make_diag_full("pf-dynamodb-import-csv-delimiter", "ERROR", name,
	"Properties.ImportSourceSpecification.InputFormatOptions.Csv.Delimiter",
	sprintf("CSV Delimiter '%s' is not one of , ; : | tab space; ImportTable fails with \"Member must have length less than or equal to 1\" / a constraint violation", [d]),
	"Use a single delimiter character out of comma, semicolon, colon, pipe, tab or space",
	"https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/S3DataImport.Requesting.html") if {
	some name in resources_of_type("AWS::DynamoDB::Table")
	d := resolve(name, "Properties.ImportSourceSpecification.InputFormatOptions.Csv.Delimiter")
	is_string(d)
	not regex.match("^[,;:|\t ]$", d)
}
