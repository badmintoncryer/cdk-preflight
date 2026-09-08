package cdk_preflight

import rego.v1

# ponytail: a denylist of the mutation processors rather than an allowlist of
# parsers - the service's parser list grows, and an incomplete allowlist would
# reject valid configs.
_pf_lgtp_mutators := {
	"AddKeys",
	"CopyValue",
	"DateTimeConverter",
	"DeleteKeys",
	"ListToMap",
	"LowerCaseString",
	"MoveKeys",
	"RenameKeys",
	"SplitString",
	"SubstituteString",
	"TrimString",
	"TypeConverter",
	"UpperCaseString",
}

violation contains make_diag_full("pf-logs-transformer-parser-first", "ERROR", name,
	"Properties.TransformerConfig",
	sprintf("The transformer starts with the '%s' processor; PutTransformer fails with \"Transformer config should begin with parser.\"", [key]),
	"Put a parser first (ParseJSON, ParseKeyValue, Csv, Grok or one of the AWS service parsers)",
	"https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/CloudWatch-Logs-Transformation-Configurable.html") if {
	some name in resources_of_type("AWS::Logs::Transformer")
	some item in flatten_list(name, "Properties.TransformerConfig")
	item.index == 0
	first := item.value
	is_object(first)
	some key in object.keys(first)
	key in _pf_lgtp_mutators
}
