package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-firehose-processor-duplicate-type", "ERROR", name,
	sprintf("%s.ProcessingConfiguration.Processors", [path]),
	sprintf("%d Lambda processors are configured; the stream create fails with \"Cannot have more than 1 Lambda processor.\"", [n]),
	"Keep a single Lambda processor",
	"https://docs.aws.amazon.com/firehose/latest/APIReference/API_ProcessingConfiguration.html") if {
	some [name, path, _, t, _] in _pf_fhlib_procs
	t == "Lambda"
	n := count([j | some [nm, p, j, tt, _] in _pf_fhlib_procs; nm == name; p == path; tt == "Lambda"])
	n > 1
}
