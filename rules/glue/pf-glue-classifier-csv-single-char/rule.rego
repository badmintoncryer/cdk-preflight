package cdk_preflight

import rego.v1

# csvClassifier.delimiter and .quoteSymbol both carry maxLength 1 on the wire.
violation contains make_diag_full("pf-glue-classifier-csv-single-char", "ERROR", name,
	sprintf("Properties.CsvClassifier.%s", [k]),
	sprintf("CsvClassifier.%s is %d characters; CreateClassifier fails with \"Member must have length less than or equal to 1\"", [k, count(v)]),
	sprintf("Give %s a single character", [k]),
	"https://docs.aws.amazon.com/glue/latest/dg/custom-classifier.html") if {
	some name in resources_of_type("AWS::Glue::Classifier")
	csv := _pf_gluelib_classifier(name, "CsvClassifier")
	some k in ["Delimiter", "QuoteSymbol"]
	v := csv[k]
	_pf_gluelib_lit(v)
	count(v) > 1
}
