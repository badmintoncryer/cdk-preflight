package cdk_preflight

import rego.v1

# The service takes the eleven Glue datatypes in any case; SQL spellings such as
# BIGINT, INTEGER, CHAR and VARCHAR are all rejected by name.
_pf_gluecdt_types := {"BINARY", "BOOLEAN", "DATE", "DECIMAL", "DOUBLE", "FLOAT", "INT", "LONG", "SHORT", "STRING", "TIMESTAMP"}

violation contains make_diag_full("pf-glue-classifier-csv-custom-datatype", "ERROR", name,
	sprintf("Properties.CsvClassifier.ContainsCustomDatatype.%d", [i]),
	sprintf("\"%s\" is not a Glue datatype; CreateClassifier fails with \"The following types are invalid: %s\"", [t, t]),
	"Use one of BINARY BOOLEAN DATE DECIMAL DOUBLE FLOAT INT LONG SHORT STRING TIMESTAMP",
	"https://docs.aws.amazon.com/glue/latest/dg/custom-classifier.html") if {
	some name in resources_of_type("AWS::Glue::Classifier")
	csv := _pf_gluelib_classifier(name, "CsvClassifier")
	arr := csv.ContainsCustomDatatype
	is_array(arr)
	some i, t in arr
	_pf_gluelib_lit(t)
	u := upper(t)
	not u in _pf_gluecdt_types
}
