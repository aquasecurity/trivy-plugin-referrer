package main

import (
	"encoding/json"
	"fmt"
	"io"
	"text/tabwriter"
	"text/template"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/samber/lo"
)

func fetchTargetDigest(subject string) (name.Digest, error) {
	ref, err := name.ParseReference(subject)
	if err != nil {
		return name.Digest{}, fmt.Errorf("error parsing reference: %w", err)
	}

	desc, err := remote.Head(ref, remote.WithAuthFromKeychain(authn.DefaultKeychain))
	if err != nil {
		return name.Digest{}, fmt.Errorf("error getting descriptor: %w", err)
	}

	digest, err := name.NewDigest(
		fmt.Sprintf("%s/%s@%s", ref.Context().RegistryStr(), ref.Context().RepositoryStr(), desc.Digest.String()),
	)
	if err != nil {
		return name.Digest{}, fmt.Errorf("error creating digest: %w", err)
	}

	return digest, nil
}

func listReferrers(writer io.Writer, opts listOptions) error {
	targetDigest, err := fetchTargetDigest(opts.Subject)
	if err != nil {
		return fmt.Errorf("error getting digest: %w", err)
	}

	index, err := remote.Referrers(targetDigest, remote.WithAuthFromKeychain(authn.DefaultKeychain))
	if err != nil {
		return fmt.Errorf("error fetching referrers: %w", err)
	}

	filtered := index.DeepCopy()
	manifests, err := filterManifests(index.Manifests, opts)
	if err != nil {
		return fmt.Errorf("error filtering manifests: %w", err)
	}
	filtered.Manifests = manifests

	if opts.Format == "json" {
		marshal, err := json.Marshal(filtered)
		if err != nil {
			return fmt.Errorf("error marshaling index: %w", err)
		}
		writer.Write(marshal)
	} else {
		w := tabwriter.NewWriter(writer, 0, 0, 1, ' ', 0)
		defer w.Flush()

		tmpl := `Subject:	{{ .Subject }}
{{- $registry := .Registry }}
{{- $repository := .Repository }}
Referrers:	 {{ range $index, $descriptor := .Index.Manifests }}
  Digest:	{{ $descriptor.Digest }}
  Reference:	{{ $registry }}/{{ $repository }}@{{ $descriptor.Digest }}
  MediaType:	{{ $descriptor.MediaType }}
  ArtifactType:	{{ $descriptor.ArtifactType }}
  {{- if $descriptor.Annotations }}
  Annotations:	{{ range $key, $value := $descriptor.Annotations }}
    {{ $key }}:	{{ $value }}{{ end }}
  {{- end }}
{{ end }}`

		t := template.Must(template.New("descriptorsTemplate").Parse(tmpl))
		err := t.Execute(w, struct {
			Index      v1.IndexManifest
			Subject    string
			Registry   string
			Repository string
		}{
			Index:      *filtered,
			Subject:    opts.Subject,
			Registry:   targetDigest.RegistryStr(),
			Repository: targetDigest.RepositoryStr(),
		})

		if err != nil {
			return fmt.Errorf("error executing template: %w", err)
		}
	}

	return nil
}

func filterManifests(manifests []v1.Descriptor, opts listOptions) ([]v1.Descriptor, error) {
	if opts.Type != "" {
		artifactType, err := getArtifactType(opts.Type)
		if err != nil {
			return nil, fmt.Errorf("error getting artifact type: %w", err)
		}

		manifests = lo.Filter(manifests, func(item v1.Descriptor, index int) bool {
			return item.ArtifactType == artifactType
		})
	}

	for annKey, annValue := range opts.FilterAnnotations {
		manifests = lo.Filter(manifests, func(item v1.Descriptor, index int) bool {
			return item.Annotations[annKey] == annValue
		})
	}
	return manifests, nil
}
