package main

import "fmt"

const (
	// ref. https://github.com/opencontainers/image-spec/blob/dd7fd714f5406d39db5fd0602a0e6090929dc85e/annotations.md#pre-defined-annotation-keys
	annotationKeyCreated     = "org.opencontainers.artifact.created"
	annotationKeyDescription = "org.opencontainers.artifact.description"

	// Use a Media Type registered with IANA.
	// ref. https://github.com/opencontainers/image-spec/blob/dd7fd714f5406d39db5fd0602a0e6090929dc85e/artifact.md#artifact-manifest-property-descriptions
	// ref. https://www.iana.org/assignments/media-types/media-types.xhtml
	mediaKeyCycloneDX = "application/vnd.cyclonedx+json"
	mediaKeySPDX      = "application/spdx+json"
	mediaKeySARIF     = "application/sarif+json"
	// 2023/4/4: Since there is no MediaType specialized for vulnerability information registered with IANA, we use the json type.
	mediaKeyCosignVuln = "application/json"
)

func getArtifactType(mediaType string) (string, error) {
	switch mediaType {
	case "cyclonedx":
		return mediaKeyCycloneDX, nil
	case "spdx-json":
		return mediaKeySPDX, nil
	case "sarif":
		return mediaKeySARIF, nil
	case "cosign-vuln":
		return mediaKeyCosignVuln, nil
	default:
		return "", fmt.Errorf("unknown media type: %s", mediaType)
	}
}
