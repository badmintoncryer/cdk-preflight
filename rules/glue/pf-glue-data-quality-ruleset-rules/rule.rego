package cdk_preflight

import rego.v1

# CreateDataQualityRuleset answers "DataQuality rules cannot be parsed" for
# everything DQDL cannot read; the two shapes checked here were measured. The
# keyword is case sensitive ("rules = [...]" is rejected). A ruleset that has a
# non-empty Rules list but a broken rule inside it is not judged, and a ruleset
# carrying an Analyzers block is left alone entirely - "Analyzers = [ RowCount ]"
# on its own and next to an empty Rules list are both accepted.
_pf_gluedqrules_analyzers(rs) if {
	regex.match(`Analyzers\s*=\s*\[`, rs)
}

violation contains make_diag_full("pf-glue-data-quality-ruleset-rules", "ERROR", name,
	"Properties.Ruleset",
	"The ruleset does not declare a Rules list; CreateDataQualityRuleset fails with \"DataQuality rules cannot be parsed\"",
	"Write the ruleset as DQDL, e.g. Rules = [ RowCount > 0 ]",
	"https://docs.aws.amazon.com/glue/latest/dg/dqdl.html") if {
	some name in resources_of_type("AWS::Glue::DataQualityRuleset")
	rs := _pf_gluelib_str(name, "Properties.Ruleset")
	not _pf_gluedqrules_analyzers(rs)
	not regex.match(`Rules\s*=\s*\[`, rs)
}

violation contains make_diag_full("pf-glue-data-quality-ruleset-rules", "ERROR", name,
	"Properties.Ruleset",
	"The ruleset declares an empty Rules list; CreateDataQualityRuleset fails with \"DataQuality rules cannot be parsed\"",
	"Put at least one rule in the list, e.g. Rules = [ RowCount > 0 ]",
	"https://docs.aws.amazon.com/glue/latest/dg/dqdl.html") if {
	some name in resources_of_type("AWS::Glue::DataQualityRuleset")
	rs := _pf_gluelib_str(name, "Properties.Ruleset")
	not _pf_gluedqrules_analyzers(rs)
	regex.match(`Rules\s*=\s*\[\s*\]`, rs)
}
