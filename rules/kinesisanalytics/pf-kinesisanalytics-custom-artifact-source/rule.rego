package cdk_preflight

import rego.v1

_pf_kinart_source(a) if {
	some k in ["S3ContentLocation", "MavenReference"]
	_pf_kinlib_has(a, k)
}

violation contains make_diag_full("pf-kinesisanalytics-custom-artifact-source", "ERROR", name,
	sprintf("Properties.ApplicationConfiguration.ZeppelinApplicationConfiguration.CustomArtifactsConfiguration.%v", [i]),
	sprintf("custom artifact %v names neither S3ContentLocation nor MavenReference; CreateApplication fails with \"Must define S3ContentLocation or MavenReference for CustomArtifact.\"", [i]),
	"Give the artifact an S3ContentLocation, or a MavenReference for a dependency JAR",
	"https://docs.aws.amazon.com/managed-flink/latest/apiv2/API_CustomArtifactConfiguration.html") if {
	some [name, i, a] in _pf_kinlib_artifacts
	not _pf_kinart_source(a)
}
