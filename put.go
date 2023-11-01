package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/purl"
	"github.com/aquasecurity/trivy/pkg/report/predicate"
	"github.com/aquasecurity/trivy/pkg/sbom"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"
	ctypes "github.com/google/go-containerregistry/pkg/v1/types"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/owenrumney/go-sarif/sarif"
	"github.com/samber/lo"
	"github.com/spdx/tools-golang/spdx"
)

var errFailedSBOMDetection = fmt.Errorf("failed to detect SBOM")
var errFailedSARIFDetection = fmt.Errorf("failed to detect SARIF")
var errFailedVulnDetection = fmt.Errorf("failed to detect Cosign Vulnerability")
var errFailedToWriteReferrer = fmt.Errorf("failed to write referrer")

type referrer struct {
	Insecure
	annotations     map[string]string
	mediaType       ctypes.MediaType
	bytes           []byte
	targetReference name.Reference
}

func (r *referrer) Image(useRemoteMediaType bool) (v1.Image, error) {
	img, err := mutate.Append(empty.Image, mutate.Addendum{
		Layer: static.NewLayer(r.bytes, r.mediaType),
	})
	if err != nil {
		return nil, fmt.Errorf("error appending layer: %w", err)
	}

	remoteOpts := append(r.Insecure.RemoteOptions(), remote.WithAuthFromKeychain(authn.DefaultKeychain))
	targetDesc, err := remote.Head(r.targetReference, remoteOpts...)
	if err != nil {
		return nil, fmt.Errorf("error getting descriptor: %w", err)
	}

	if useRemoteMediaType {
		img = mutate.MediaType(img, targetDesc.MediaType)
	} else {
		img = mutate.MediaType(img, ocispec.MediaTypeImageManifest)
	}

	img = mutate.ConfigMediaType(img, r.mediaType)
	img = mutate.Annotations(img, r.annotations).(v1.Image)
	img = mutate.Subject(img, *targetDesc).(v1.Image)

	return img, nil
}

func (r *referrer) Tag(img v1.Image) (name.Reference, error) {
	digest, err := img.Digest()
	if err != nil {
		return name.Digest{}, fmt.Errorf("error getting image digest: %w", err)
	}

	tag, err := name.NewDigest(
		fmt.Sprintf("%s/%s@%s", r.targetReference.Context().RegistryStr(), r.targetReference.Context().RepositoryStr(), digest.String()),
		r.NameOptions()...,
	)
	if err != nil {
		return name.Digest{}, fmt.Errorf("error creating new digest: %w", err)
	}
	return tag, nil
}

func newAnnotations(description string) map[string]string {
	return map[string]string{
		annotationKeyDescription:       description,
		annotationKeyCreated:           time.Now().Format(time.RFC3339),
		customAnnotationKeyDescription: "trivy",
	}
}

func writeImage(tag name.Reference, img v1.Image, remoteOpts []remote.Option) error {
	if err := remote.Write(tag, img, remoteOpts...); err != nil {
		var terr *transport.Error
		if errors.As(err, &terr) {
			// There is no standardized status code for when the media type is rejected by OCI,
			// but DockerHub returns a 404 in such cases.
			// e.g. https://github.com/opencontainers/distribution-spec/blob/3940529fe6c0a068290b27fb3cd797cf0528bed6/spec.md#pushing-manifests
			if terr.StatusCode == http.StatusNotFound {
				return errFailedToWriteReferrer
			}
		}
		return fmt.Errorf("error pushing referrer: %w", err)
	}
	return nil
}

func tryPutReferrer(ref referrer, retryWithRemoteMediaType bool) error {
	img, err := ref.Image(retryWithRemoteMediaType)
	if err != nil {
		return fmt.Errorf("error getting image: %w", err)
	}

	tag, err := ref.Tag(img)
	if err != nil {
		return fmt.Errorf("error getting tag: %w", err)
	}

	log.Logger.Infof("Pushing referrer to %s", tag.String())

	remoteOpts := append(ref.RemoteOptions(), remote.WithAuthFromKeychain(authn.DefaultKeychain))
	return writeImage(tag, img, remoteOpts)

}

func putReferrer(r io.Reader, opts putOptions) error {
	ref, err := referrerFromReader(r, opts)
	if err != nil {
		return fmt.Errorf("error getting referrer: %w", err)
	}

	if err := tryPutReferrer(ref, false); err != nil {
		if !errors.Is(err, errFailedToWriteReferrer) {
			return fmt.Errorf("error pushing referrer: %w", err)
		}

		log.Logger.Infof("Retrying with remote media type")
		if err := tryPutReferrer(ref, true); err != nil {
			return fmt.Errorf("error pushing referrer: %w", err)
		}
	}

	log.Logger.Infof("Successfully pushed referrer")
	return nil
}

func referrerFromReader(r io.Reader, opts putOptions) (referrer, error) {
	b, err := io.ReadAll(r)
	if err != nil {
		return referrer{}, fmt.Errorf("error reading: %w", err)
	}

	var ref referrer
	ref, err = tryReferrerFromSBOM(bytes.NewReader(b), opts)
	if err == nil {
		return ref, nil
	} else if err != nil && err != errFailedSBOMDetection {
		return referrer{}, fmt.Errorf("error processing SBOM: %w", err)
	}

	log.Logger.Infof("Failed to detect a valid SBOM: ensure the provided SBOM is generated by Trivy, as only Trivy-generated SBOMs are currently supported")

	ref, err = tryReferrerFromSarif(bytes.NewReader(b), opts)
	if err == nil {
		return ref, nil
	} else if err != nil && err != errFailedSARIFDetection {
		return referrer{}, fmt.Errorf("error processing SARIF: %w", err)
	}

	ref, err = tryReferrerFromVulnerability(bytes.NewReader(b), opts)
	if err == nil {
		return ref, nil
	} else if err != nil && err != errFailedVulnDetection {
		return referrer{}, fmt.Errorf("error processing vulnerability: %w", err)
	}

	log.Logger.Infof("Failed to detect Cosign vulnerability format")

	return referrer{}, fmt.Errorf("failed to detect referrer type")
}

func tryReferrerFromSBOM(r io.Reader, opts putOptions) (referrer, error) {
	b, err := io.ReadAll(r)
	if err != nil {
		return referrer{}, fmt.Errorf("error reading: %w", err)
	}

	format, err := sbom.DetectFormat(bytes.NewReader(b))
	if format == sbom.FormatUnknown {
		return referrer{}, errFailedSBOMDetection
	} else if err != nil {
		return referrer{}, fmt.Errorf("error detecting SBOM format: %w", err)
	}
	decoded, err := sbom.Decode(bytes.NewReader(b), format)
	if err != nil {
		return referrer{}, fmt.Errorf("error decoding SBOM: %w", err)
	}

	var mediaType types.MediaType
	var anns map[string]string
	var ref name.Reference

	switch format {
	case sbom.FormatCycloneDXJSON:
		if opts.Subject != "" {
			ref, err = name.ParseReference(opts.Subject, opts.NameOptions()...)
			if err != nil {
				return referrer{}, fmt.Errorf("error parsing subject: %w", err)
			}
		} else {
			ref, err = repoFromPURL(decoded.CycloneDX.Metadata.Component.BOMRef, opts)
			if err != nil {
				return referrer{}, fmt.Errorf("error getting repository from CycloneDX: %w", err)
			}
		}

		anns = newAnnotations("CycloneDX JSON SBOM")
		mediaType = mediaKeyCycloneDX

	case sbom.FormatSPDXJSON:
		if opts.Subject != "" {
			ref, err = name.ParseReference(opts.Subject, opts.NameOptions()...)
			if err != nil {
				return referrer{}, fmt.Errorf("error parsing subject: %w", err)
			}
		} else {
			ref, err = repoFromSPDX(*decoded.SPDX, opts)
			if err != nil {
				return referrer{}, fmt.Errorf("error getting repository from SPDX: %w", err)
			}
		}

		anns = newAnnotations("SPDX JSON SBOM")
		mediaType = mediaKeySPDX

	default:
		return referrer{}, fmt.Errorf("unsupported format: %s", format)
	}

	log.Logger.Infof("SBOM detected: %s", format)

	anns = lo.Assign(anns, opts.Annotations)

	return referrer{
		Insecure:        opts.Insecure,
		annotations:     anns,
		mediaType:       mediaType,
		bytes:           b,
		targetReference: ref,
	}, nil
}

func digestFromSarif(report *sarif.Report, opts putOptions) (name.Reference, error) {
	if len(report.Runs) == 0 {
		return nil, fmt.Errorf("no runs found in sarif report")
	}

	// SARIF reports generated by Trivy contain a repoDigests property
	// ref. https://github.com/aquasecurity/trivy/pull/4020
	if v, ok := report.Runs[0].Properties["repoDigests"].([]interface{}); ok {
		if len(v) == 0 {
			return nil, fmt.Errorf("no repoDigests found in sarif report")
		}
		s := v[0].(string)
		ref, err := name.NewDigest(s, opts.NameOptions()...)
		if err != nil {
			return nil, fmt.Errorf("error parsing digest: %w", err)
		}
		return ref, nil
	}
	return nil, fmt.Errorf("no repoDigests found in sarif report")
}

func tryReferrerFromSarif(r io.Reader, opts putOptions) (referrer, error) {
	b, err := io.ReadAll(r)
	if err != nil {
		return referrer{}, fmt.Errorf("error reading: %w", err)

	}
	sa, err := sarif.FromBytes(b)
	if err != nil {
		return referrer{}, err
	}

	// A naive detection would be to check whether the $schema contains ‘sarif.’
	// Trivy generates the following schema:
	//   https://json.schemastore.org/sarif-2.1.0-rtm.5.json
	if !strings.Contains(sa.Schema, "sarif") {
		return referrer{}, errFailedSARIFDetection
	}

	var ref name.Reference
	if opts.Subject != "" {
		ref, err = name.ParseReference(opts.Subject, opts.NameOptions()...)
		if err != nil {
			return referrer{}, fmt.Errorf("error parsing subject: %w", err)
		}
	} else {
		ref, err = digestFromSarif(sa, opts)
		if err != nil {
			return referrer{}, fmt.Errorf("error getting repository from SARIF: %w", err)
		}
	}
	log.Logger.Infof("SARIF detected")

	anns := newAnnotations("SARIF")
	anns = lo.Assign(anns, opts.Annotations)

	return referrer{
		annotations:     anns,
		mediaType:       types.MediaType(mediaKeySARIF),
		bytes:           b,
		targetReference: ref,
	}, nil
}

func tryReferrerFromVulnerability(r io.Reader, opts putOptions) (referrer, error) {
	b, err := io.ReadAll(r)
	if err != nil {
		return referrer{}, fmt.Errorf("error reading: %w", err)

	}

	var d predicate.CosignVulnPredicate
	if err := json.Unmarshal(b, &d); err != nil {
		return referrer{}, fmt.Errorf("failed to unmarshal vulnerability data: %w", errFailedVulnDetection)
	}

	if len(d.Scanner.Result.Metadata.RepoDigests) == 0 {
		return referrer{}, fmt.Errorf("no RepoDigests found in vulnerability data: %w", errFailedVulnDetection)
	}

	var ref name.Reference
	if opts.Subject != "" {
		ref, err = name.ParseReference(opts.Subject, opts.NameOptions()...)
		if err != nil {
			return referrer{}, fmt.Errorf("error parsing subject: %w", err)
		}
	} else {
		ref, err = name.NewDigest(d.Scanner.Result.Metadata.RepoDigests[0], opts.NameOptions()...)
		if err != nil {
			return referrer{}, fmt.Errorf("error creating new digest: %w", err)
		}
	}

	log.Logger.Infof("Cosign vulnerability data detected")

	anns := newAnnotations("Cosign Vulnerability Data")
	anns = lo.Assign(anns, opts.Annotations)

	return referrer{
		annotations:     anns,
		mediaType:       types.MediaType(mediaKeyCosignVuln),
		bytes:           b,
		targetReference: ref,
	}, nil
}

func repoFromPURL(purlStr string, opts putOptions) (name.Reference, error) {
	p, err := purl.FromString(purlStr)
	if err != nil {
		return nil, fmt.Errorf("error parsing purl: %w", err)
	}

	url := p.Qualifiers.Map()["repository_url"]
	if url == "" {
		return nil, fmt.Errorf("repository_url not found")
	}

	digest, err := name.NewDigest(fmt.Sprintf("%s@%s", url, p.Version), opts.NameOptions()...)
	if err != nil {
		return nil, fmt.Errorf("error creating new digest: %w", err)
	}

	return digest, nil
}

func repoFromSPDX(spdx spdx.Document, opts putOptions) (name.Reference, error) {
	for _, pkg := range spdx.Packages {
		if pkg.PackageName == spdx.DocumentName {
			for _, ref := range pkg.PackageExternalReferences {
				if ref.Category == "PACKAGE-MANAGER" {
					return repoFromPURL(ref.Locator, opts)
				}
			}
		}
	}

	return nil, fmt.Errorf("error getting repository from SPDX")
}
