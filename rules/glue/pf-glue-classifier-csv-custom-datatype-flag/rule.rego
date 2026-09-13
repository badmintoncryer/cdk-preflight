package cdk_preflight

import rego.v1

# The service checks the pair in both directions and answers the same sentence:
# a list without the flag, the flag without a list, and the flag set to false
# next to a list are all rejected.
_pf_gluecdtflag_on(csv) if csv.CustomDatatypeConfigured == true

_pf_gluecdtflag_on(csv) if csv.CustomDatatypeConfigured == "true"

violation contains make_diag_full("pf-glue-classifier-csv-custom-datatype-flag", "ERROR", name,
	"Properties.CsvClassifier.CustomDatatypeConfigured",
	"ContainsCustomDatatype is listed without CustomDatatypeConfigured set to true; CreateClassifier fails with \"Must enable using custom datatypes and pass in the list of datatypes\"",
	"Set CustomDatatypeConfigured to true alongside ContainsCustomDatatype",
	"https://docs.aws.amazon.com/glue/latest/dg/custom-classifier.html") if {
	some name in resources_of_type("AWS::Glue::Classifier")
	csv := _pf_gluelib_classifier(name, "CsvClassifier")
	arr := csv.ContainsCustomDatatype
	is_array(arr)
	count(arr) > 0
	not _pf_gluecdtflag_on(csv)
}

violation contains make_diag_full("pf-glue-classifier-csv-custom-datatype-flag", "ERROR", name,
	"Properties.CsvClassifier.ContainsCustomDatatype",
	"CustomDatatypeConfigured is true but no ContainsCustomDatatype list is given; CreateClassifier fails with \"Must enable using custom datatypes and pass in the list of datatypes\"",
	"List the datatypes in ContainsCustomDatatype, or drop CustomDatatypeConfigured",
	"https://docs.aws.amazon.com/glue/latest/dg/custom-classifier.html") if {
	some name in resources_of_type("AWS::Glue::Classifier")
	csv := _pf_gluelib_classifier(name, "CsvClassifier")
	_pf_gluecdtflag_on(csv)
	object.get(csv, "ContainsCustomDatatype", "__pf_absent") == "__pf_absent"
}
