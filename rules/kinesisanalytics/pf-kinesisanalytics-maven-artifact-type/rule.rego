package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-kinesisanalytics-maven-artifact-type", "ERROR", name,
	sprintf("Properties.ApplicationConfiguration.ZeppelinApplicationConfiguration.CustomArtifactsConfiguration.%v.MavenReference", [i]),
	sprintf("artifact %v is a %v but carries a MavenReference; CreateApplication fails with \"MavenReference can only be used for ArtifactType: DEPENDENCY_JAR\"", [i, at]),
	"Upload UDF artifacts to Amazon S3 and reference them with S3ContentLocation",
	"https://docs.aws.amazon.com/managed-flink/latest/apiv2/API_CustomArtifactConfiguration.html") if {
	some [name, i, a] in _pf_kinlib_artifacts
	_pf_kinlib_has(a, "MavenReference")
	at := object.get(a, "ArtifactType", null)
	is_string(at)
	at != "DEPENDENCY_JAR"
}
