package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
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
	"github.com/google/go-containerregistry/pkg/v1/static"
	ctypes "github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/owenrumney/go-sarif/sarif"
	"github.com/samber/lo"
	"github.com/spdx/tools-golang/spdx"
	"github.com/spf13/cobra"
)

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

var errFailedSBOMDetection = fmt.Errorf("failed to detect SBOM")
var errFailedSARIFDetection = fmt.Errorf("failed to detect SARIF")
var errFailedVulnDetection = fmt.Errorf("failed to detect Cosign Vulnerability")

type options struct {
	Annotations map[string]string
	Subject     string
}

type referrer struct {
	annotations     map[string]string
	mediaType       ctypes.MediaType
	bytes           []byte
	targetReference name.Reference
	targetDesc      v1.Descriptor
}

func (r *referrer) Image() (v1.Image, error) {
	img, err := mutate.Append(empty.Image, mutate.Addendum{
		Layer: static.NewLayer(r.bytes, r.mediaType),
	})
	if err != nil {
		return nil, fmt.Errorf("error appending layer: %w", err)
	}

	img = mutate.MediaType(img, r.targetDesc.MediaType)
	img = mutate.ConfigMediaType(img, r.mediaType)
	img = mutate.Annotations(img, r.annotations).(v1.Image)
	img = mutate.Subject(img, r.targetDesc).(v1.Image)

	return img, nil
}

func (r *referrer) Tag(img v1.Image) (name.Reference, error) {
	digest, err := img.Digest()
	if err != nil {
		return name.Digest{}, fmt.Errorf("error getting image digest: %w", err)
	}

	tag, err := name.NewDigest(
		fmt.Sprintf("%s/%s@%s", r.targetReference.Context().RegistryStr(), r.targetReference.Context().RepositoryStr(), digest.String()),
	)
	if err != nil {
		return name.Digest{}, fmt.Errorf("error creating new digest: %w", err)
	}
	return tag, nil
}

func repoFromPurl(purlStr string) (name.Digest, error) {
	p, err := purl.FromString(purlStr)
	if err != nil {
		return name.Digest{}, fmt.Errorf("error parsing purl: %w", err)
	}

	url := p.Qualifiers.Map()["repository_url"]
	if url == "" {
		return name.Digest{}, fmt.Errorf("repository_url not found")
	}

	digest, err := name.NewDigest(fmt.Sprintf("%s@%s", url, p.Version))
	if err != nil {
		return name.Digest{}, fmt.Errorf("error creating new digest: %w", err)
	}

	return digest, nil
}

func repoFromSpdx(spdx spdx.Document2_2) (name.Digest, error) {
	for _, pkg := range spdx.Packages {
		if pkg.PackageName == spdx.CreationInfo.DocumentName {
			for _, ref := range pkg.PackageExternalReferences {
				if ref.Category == "PACKAGE-MANAGER" {
					return repoFromPurl(ref.Locator)
				}
			}
		}
	}

	return name.Digest{}, fmt.Errorf("error getting repository from SPDX")
}

func tryReferrerFromSBOM(r io.Reader, opts options) (referrer, error) {
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

	var mediaType ctypes.MediaType
	var anns map[string]string
	var ref name.Reference

	switch format {
	case sbom.FormatCycloneDXJSON:
		if opts.Subject != "" {
			ref, err = name.ParseReference(opts.Subject)
			if err != nil {
				return referrer{}, fmt.Errorf("error parsing subject: %w", err)
			}
		} else {
			ref, err = repoFromPurl(decoded.CycloneDX.Metadata.Component.BOMRef)
			if err != nil {
				return referrer{}, fmt.Errorf("error getting repository from CycloneDX: %w", err)
			}
		}

		anns = map[string]string{
			annotationKeyDescription: "CycloneDX JSON SBOM",
			annotationKeyCreated:     time.Now().Format(time.RFC3339),
		}
		mediaType = mediaKeyCycloneDX

	case sbom.FormatSPDXJSON:
		if opts.Subject != "" {
			ref, err = name.ParseReference(opts.Subject)
			if err != nil {
				return referrer{}, fmt.Errorf("error parsing subject: %w", err)
			}
		} else {
			ref, err = repoFromSpdx(*decoded.SPDX)
			if err != nil {
				return referrer{}, fmt.Errorf("error getting repository from SPDX: %w", err)
			}
		}

		anns = map[string]string{
			annotationKeyDescription: "SPDX JSON SBOM",
			annotationKeyCreated:     time.Now().Format(time.RFC3339),
		}
		mediaType = mediaKeySPDX

	default:
		return referrer{}, fmt.Errorf("unsupported format: %s", format)
	}

	log.Logger.Infof("SBOM detected: %s", format)

	targetDesc, err := remote.Head(ref, remote.WithAuthFromKeychain(authn.DefaultKeychain))
	if err != nil {
		return referrer{}, fmt.Errorf("error getting descriptor: %w", err)
	}

	anns = lo.Assign(anns, opts.Annotations)

	return referrer{
		annotations:     anns,
		mediaType:       mediaType,
		bytes:           b,
		targetReference: ref,
		targetDesc:      *targetDesc,
	}, nil
}

func tryReferrerFromSarif(r io.Reader, opts options) (referrer, error) {
	b, err := io.ReadAll(r)
	if err != nil {
		return referrer{}, fmt.Errorf("error reading: %w", err)

	}
	fromBytes, err := sarif.FromBytes(b)
	if err != nil {
		return referrer{}, err
	}

	// A naive detection would be to check whether the $schema contains ‘sarif.’
	// Trivy v0.38.3 generate the following schema:
	//   https://json.schemastore.org/sarif-2.1.0-rtm.5.json
	if !strings.Contains(fromBytes.Schema, "sarif") {
		return referrer{}, errFailedSARIFDetection
	}

	// After Trivy supports for the artifact location, we can detect the subject automatically.
	//   https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html#_Toc34317499
	if opts.Subject == "" {
		return referrer{}, fmt.Errorf("subject is required for SARIF")
	}

	ref, err := name.ParseReference(opts.Subject)
	if err != nil {
		return referrer{}, fmt.Errorf("error parsing subject: %w", err)
	}

	targetDesc, err := remote.Head(ref, remote.WithAuthFromKeychain(authn.DefaultKeychain))
	if err != nil {
		return referrer{}, fmt.Errorf("error getting descriptor: %w", err)
	}

	anns := map[string]string{
		annotationKeyDescription: "SARIF",
		annotationKeyCreated:     time.Now().Format(time.RFC3339),
	}
	anns = lo.Assign(anns, opts.Annotations)

	return referrer{
		annotations:     anns,
		mediaType:       ctypes.MediaType(mediaKeySARIF),
		bytes:           b,
		targetReference: ref,
		targetDesc:      *targetDesc,
	}, nil
}

func tryReferrerFromVulnerability(r io.Reader, opts options) (referrer, error) {
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
		ref, err = name.ParseReference(opts.Subject)
		if err != nil {
			return referrer{}, fmt.Errorf("error parsing subject: %w", err)
		}
	} else {
		ref, err = name.NewDigest(d.Scanner.Result.Metadata.RepoDigests[0])
		if err != nil {
			return referrer{}, fmt.Errorf("error creating new digest: %w", err)
		}
	}

	targetDesc, err := remote.Head(ref, remote.WithAuthFromKeychain(authn.DefaultKeychain))
	if err != nil {
		return referrer{}, fmt.Errorf("error fetching target descriptor: %w", err)
	}

	log.Logger.Infof("Cosign vulnerability data detected")

	anns := map[string]string{
		annotationKeyDescription: "Vulnerability Scan Report",
		annotationKeyCreated:     time.Now().Format(time.RFC3339),
	}
	anns = lo.Assign(anns, opts.Annotations)

	return referrer{
		annotations:     anns,
		mediaType:       ctypes.MediaType(mediaKeyCosignVuln),
		bytes:           b,
		targetReference: ref,
		targetDesc:      *targetDesc,
	}, nil
}

func referrerFromReader(r io.Reader, opts options) (referrer, error) {
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

func putReferrer(r io.Reader, opts options) error {
	ref, err := referrerFromReader(r, opts)
	if err != nil {
		return fmt.Errorf("error getting referrer: %w", err)
	}

	img, err := ref.Image()
	if err != nil {
		return fmt.Errorf("error getting image: %w", err)
	}

	tag, err := ref.Tag(img)
	if err != nil {
		return fmt.Errorf("error getting tag: %w", err)
	}

	log.Logger.Infof("Pushing referrer to %s", tag.String())

	err = remote.Write(tag, img, remote.WithAuthFromKeychain(authn.DefaultKeychain))
	if err != nil {
		return fmt.Errorf("error pushing referrer: %w", err)
	}

	return nil
}

func main() {
	rootCmd := &cobra.Command{
		Short: "A Trivy plugin for oci referrers",
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			debug, err := cmd.Flags().GetBool("debug")
			if err != nil {
				return fmt.Errorf("error getting debug flag: %w", err)
			}

			quiet, err := cmd.Flags().GetBool("quiet")
			if err != nil {
				return fmt.Errorf("error getting quiet flag: %w", err)
			}

			if err := log.InitLogger(debug, quiet); err != nil {
				return err
			}

			return nil
		},
	}
	rootCmd.PersistentFlags().BoolP("debug", "d", false, "debug mode")
	rootCmd.PersistentFlags().BoolP("quiet", "q", false, "suppress log output")

	putCmd := &cobra.Command{
		Use:   "put",
		Short: "put a referrer to the oci registry",
		Example: `  trivy image -q -f cyclonedx YOUR_IMAGE | trivy referrer put
  # Put SBOM attestation
  trivy referrer put -f sbom.json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			path, err := cmd.Flags().GetString("file")
			if err != nil {
				return fmt.Errorf("error getting file path: %w", err)
			}

			var reader io.Reader
			if path != "" {
				fp, err := os.Open(path)
				if err != nil {
					return fmt.Errorf("error opening file: %w", err)
				}
				defer fp.Close()

				reader = fp
			} else {
				reader = os.Stdin
			}

			subject, err := cmd.Flags().GetString("subject")
			if err != nil {
				return fmt.Errorf("error getting subject: %w", err)
			}

			annList, err := cmd.Flags().GetStringSlice("annotation")
			if err != nil {
				return fmt.Errorf("error getting annotations: %w", err)
			}

			ann := make(map[string]string, len(annList))
			for _, a := range annList {
				kv := strings.Split(a, "=")
				if len(kv) != 2 {
					return fmt.Errorf("invalid annotation: %s", a)
				}
				ann[kv[0]] = kv[1]
			}

			err = putReferrer(reader, options{Annotations: ann, Subject: subject})
			if err != nil {
				return fmt.Errorf("error putting referrer: %w", err)
			}

			return nil
		},
	}
	putCmd.Flags().StringP("file", "f", "", "file path. If a file path is not specified, it will accept input from the standard input.")
	putCmd.Flags().StringSliceP("annotation", "", nil, "annotations associated with the artifact (can specify multiple or separate values with commas: key1=path1,key2=path2)")
	putCmd.Flags().StringP("subject", "", "", "set the subject to a reference (If the value is not set, it will attempt to detect it automatically from the input)")

	rootCmd.AddCommand(putCmd)

	if err := putCmd.Execute(); err != nil {
		log.Logger.Fatal(err)
	}
}
