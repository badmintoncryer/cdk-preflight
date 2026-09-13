package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-athena-wg-engine-version-enum", "ERROR", name,
	"Properties.WorkGroupConfiguration.EngineVersion.SelectedEngineVersion",
	sprintf("SelectedEngineVersion '%v' is not a published engine version; CreateWorkGroup fails with \"The selected engine version is not valid.\"", [ev]),
	"Use AUTO, \"Athena engine version 3\" or \"PySpark engine version 3\"",
	"https://docs.aws.amazon.com/athena/latest/ug/engine-versions-reference.html") if {
	some name in resources_of_type("AWS::Athena::WorkGroup")
	ev := resolve(name, "Properties.WorkGroupConfiguration.EngineVersion.SelectedEngineVersion")
	_pf_athlib_lit(ev)
	not ev in {"AUTO", "Athena engine version 2", "Athena engine version 3", "PySpark engine version 3"}
}
