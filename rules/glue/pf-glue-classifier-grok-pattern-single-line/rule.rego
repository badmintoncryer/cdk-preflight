package cdk_preflight

import rego.v1

# grokClassifier.grokPattern accepts \r and \t but not \n; CustomPatterns is the
# multi-line field and is deliberately left alone.
violation contains make_diag_full("pf-glue-classifier-grok-pattern-single-line", "ERROR", name,
	"Properties.GrokClassifier.GrokPattern",
	"GrokPattern spans more than one line; CreateClassifier fails with \"failed to satisfy constraint: Member must satisfy regular expression pattern\"",
	"Keep the pattern on one line and move reusable pieces into CustomPatterns",
	"https://docs.aws.amazon.com/glue/latest/dg/custom-classifier.html") if {
	some name in resources_of_type("AWS::Glue::Classifier")
	grok := _pf_gluelib_classifier(name, "GrokClassifier")
	gp := grok.GrokPattern
	_pf_gluelib_lit(gp)
	contains(gp, "\n")
}
