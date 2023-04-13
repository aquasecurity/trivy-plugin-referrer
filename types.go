package main

import "fmt"

const (
	// ref. https://github.com/opencontainers/image-spec/blob/dd7fd714f5406d39db5fd0602a0e6090929dc85e/annotations.md#pre-defined-annotation-keys
	annotationKeyCreated     = "org.opencontainers.artifact.created"
	annotationKeyDescription = "org.opencontainers.artifact.description"

	customAnnotationKeyDescription = "created-by"

	// Use a Media Type registered with IANA.
	// ref. https://github.com/opencontainers/image-spec/blob/dd7fd714f5406d39db5fd0602a0e6090929dc85e/artifact.md#artifact-manifest-property-descriptions
	// ref. https://www.iana.org/assignments/media-types/media-types.xhtml
	mediaKeyCycloneDX = "application/vnd.cyclonedx+json"
	mediaKeySPDX      = "application/spdx+json"
	mediaKeySARIF     = "application/sarif+json"
	// 2023/4/4: Since there is no MediaType specialized for vulnerability information registered with IANA, we use the json type.
	mediaKeyCosignVuln = "application/json"
)

type ArtifactType string

const (
	CycloneDX  ArtifactType = "cyclonedx"
	SPDXJSON   ArtifactType = "spdx-json"
	SARIF      ArtifactType = "sarif"
	CosignVuln ArtifactType = "cosign-vuln"
)

func (at ArtifactType) String() string {
	return string(at)
}

func (at ArtifactType) MediaType() string {
	switch at {
	case CycloneDX:
		return mediaKeyCycloneDX
	case SPDXJSON:
		return mediaKeySPDX
	case SARIF:
		return mediaKeySARIF
	case CosignVuln:
		return mediaKeyCosignVuln
	default:
		return ""
	}
}

func artifactTypeFromName(name string) (ArtifactType, error) {
	switch name {
	case CycloneDX.String():
		return CycloneDX, nil
	case SPDXJSON.String():
		return SPDXJSON, nil
	case SARIF.String():
		return SARIF, nil
	case CosignVuln.String():
		return CosignVuln, nil
	default:
		return "", fmt.Errorf("unknown artifact name: " + name)
	}
}

func artifactTypeFromMediaType(mediaType string) (ArtifactType, error) {
	switch mediaType {
	case mediaKeyCycloneDX:
		return CycloneDX, nil
	case mediaKeySPDX:
		return SPDXJSON, nil
	case mediaKeySARIF:
		return SARIF, nil
	case mediaKeyCosignVuln:
		return CosignVuln, nil
	default:
		return "", fmt.Errorf("unknown media type: " + mediaType)
	}
}
