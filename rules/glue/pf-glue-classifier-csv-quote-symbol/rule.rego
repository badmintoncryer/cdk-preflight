package cdk_preflight

import rego.v1

# Both are single characters, so equality is the whole check.
violation contains make_diag_full("pf-glue-classifier-csv-quote-symbol", "ERROR", name,
	"Properties.CsvClassifier.QuoteSymbol",
	sprintf("QuoteSymbol and Delimiter are both \"%s\"; CreateClassifier fails with \"Parameters Delimiter and QuoteSymbol cannot be equal.\"", [q]),
	"Give QuoteSymbol a character the Delimiter does not use",
	"https://docs.aws.amazon.com/glue/latest/dg/custom-classifier.html") if {
	some name in resources_of_type("AWS::Glue::Classifier")
	csv := _pf_gluelib_classifier(name, "CsvClassifier")
	d := object.get(csv, "Delimiter", "__pf_absent")
	q := object.get(csv, "QuoteSymbol", "__pf_absent")
	d != "__pf_absent"
	_pf_gluelib_lit(d)
	_pf_gluelib_lit(q)
	d == q
}
