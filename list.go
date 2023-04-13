package main

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"text/template"
	"time"

	"github.com/fatih/color"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/samber/lo"
)

const tableTemplate = `DIGEST	TYPE	ANNOTATIONS	DESCRIPTION	CREATED
{{- range $index, $descriptor := .Manifests }}
{{ $descriptor.Digest }}	{{ $descriptor.ArtifactType }}	{{ $descriptor.ShortAnnotations }}	{{ $descriptor.Description }}	{{ $descriptor.Created }}
{{- end }}`

const onelineTemplate = `{{- range $index, $descriptor := .Manifests }}
{{ color $descriptor.Digest "yellow" }}	{{ color $descriptor.ArtifactType "cyan" }}	{{ $descriptor.ShortAnnotations }}
{{- end }}`

const detailsTemplate = `Subject:	{{ .Subject }}
Referrers:	 {{ range $index, $descriptor := .Manifests }}
  Digest:	{{ $descriptor.Descriptor.Digest }}
  Reference:	{{ $descriptor.Reference }}
  MediaType:	{{ $descriptor.Descriptor.MediaType }}
  ArtifactType:	{{ $descriptor.Descriptor.ArtifactType }}
  {{- if $descriptor.Descriptor.Annotations }}
  Annotations:	{{ range $key, $value := $descriptor.Descriptor.Annotations }}
    {{ $key }}:	{{ $value }}{{ end }}
  {{- end }}
{{ end }}`

type customDescriptor struct {
	v1.Descriptor
	registry   string
	repository string
}

func (d *customDescriptor) Digest() string {
	s := d.Descriptor.Digest.String()
	s = strings.TrimPrefix(s, "sha256:")
	return s[:7]
}

func (d *customDescriptor) ArtifactType() string {
	a, err := artifactTypeFromMediaType(d.Descriptor.ArtifactType)
	if err != nil {
		return d.Descriptor.ArtifactType
	}
	return a.String()
}

func (d *customDescriptor) ShortAnnotations() string {
	s := ""
	for k, v := range d.Descriptor.Annotations {
		if k != annotationKeyCreated && k != annotationKeyDescription {
			s += fmt.Sprintf("%s=%s ", k, v)
		}
	}
	return s
}

func (d *customDescriptor) Description() string {
	for k, v := range d.Descriptor.Annotations {
		if k == annotationKeyDescription {
			return v
		}
	}
	return ""
}

func (d *customDescriptor) Created() string {
	for k, v := range d.Descriptor.Annotations {
		if k == annotationKeyCreated {
			t, err := time.Parse(time.RFC3339, v)
			if err != nil {
				return ""
			}
			return readableDuration(time.Since(t)) + " ago"
		}
	}
	return ""
}

func (d *customDescriptor) Reference() string {
	return fmt.Sprintf("%s/%s@%s", d.registry, d.repository, d.Descriptor.Digest.String())
}

type data struct {
	Index     *v1.IndexManifest
	Manifests []customDescriptor
	Subject   string
}

func NewData(im *v1.IndexManifest, subject string) data {
	ref, err := name.ParseReference(subject)
	if err != nil {
		return data{}
	}
	myManifests := make([]customDescriptor, len(im.Manifests))
	for i, m := range im.Manifests {
		myManifests[i] = customDescriptor{
			Descriptor: m,
			registry:   ref.Context().RegistryStr(),
			repository: ref.Context().RepositoryStr(),
		}
	}
	return data{
		Index:     im,
		Manifests: myManifests,
		Subject:   subject,
	}
}

func readableDuration(d time.Duration) string {
	if seconds := int(d.Seconds()); seconds < 1 {
		return "Less than a second"
	} else if seconds == 1 {
		return "1 second"
	} else if seconds < 60 {
		return fmt.Sprintf("%d seconds", seconds)
	} else if minutes := int(d.Minutes()); minutes == 1 {
		return "About a minute"
	} else if minutes < 60 {
		return fmt.Sprintf("%d minutes", minutes)
	} else if hours := int(d.Hours()); hours == 1 {
		return "About an hour"
	} else if hours < 48 {
		return fmt.Sprintf("%d hours", hours)
	} else if hours < 24*7*2 {
		return fmt.Sprintf("%d days", hours/24)
	} else if hours < 24*30*2 {
		return fmt.Sprintf("%d weeks", hours/24/7)
	} else if hours < 24*365*2 {
		return fmt.Sprintf("%d months", hours/24/30)
	}
	return fmt.Sprintf("%d years", int(d.Hours())/24/365)
}

type reporter interface {
	Report(w io.Writer, data data) error
}

type jsonReporter struct{}

func (jr jsonReporter) Report(w io.Writer, data data) error {
	marshal, err := json.Marshal(data.Index)
	if err != nil {
		return fmt.Errorf("error marshaling index: %w", err)
	}
	_, err = w.Write(marshal)
	if err != nil {
		return fmt.Errorf("error writing json: %w", err)
	}
	return nil
}

type templateReporter struct {
	template string
}

func (tr templateReporter) Report(w io.Writer, data data) error {
	funcMap := template.FuncMap{
		"color": func(s string, c string) string {
			switch c {
			case "yellow":
				return color.YellowString(s)
			case "cyan":
				return color.CyanString(s)
			}
			return s
		},
	}
	t := template.Must(template.New("listTemplate").Funcs(funcMap).Parse(tr.template))
	tw := tabwriter.NewWriter(w, 0, 0, 1, ' ', 0)
	defer tw.Flush()

	if err := t.Execute(tw, data); err != nil {
		return fmt.Errorf("error executing template: %w", t.Execute(w, data))
	}
	return nil
}

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
		if e, ok := err.(*transport.Error); ok && e.StatusCode == 404 {
			// If the OCI registry returns 404, process it as an index with no referrer. This happens when the OCI registry does not support
			// the referrers API.
			index = &v1.IndexManifest{}
		} else {
			return fmt.Errorf("error fetching referrers: %w", err)
		}
	}

	filtered := index.DeepCopy()
	manifests, err := filterManifests(index.Manifests, opts)
	if err != nil {
		return fmt.Errorf("error filtering manifests: %w", err)
	}
	filtered.Manifests = manifests

	var re reporter
	if opts.Format == "json" {
		re = jsonReporter{}
	} else if opts.Format == "table" {
		re = templateReporter{template: tableTemplate}
	} else if opts.Format == "oneline" {
		re = templateReporter{template: onelineTemplate}
	} else {
		re = templateReporter{template: detailsTemplate}
	}

	if err := re.Report(writer, NewData(filtered, opts.Subject)); err != nil {
		return fmt.Errorf("error reporting: %w", err)
	}

	return nil
}

func filterManifests(manifests []v1.Descriptor, opts listOptions) ([]v1.Descriptor, error) {
	if opts.Type != "" {
		artifactType, err := artifactTypeFromName(opts.Type)
		if err != nil {
			return nil, fmt.Errorf("error getting artifact type: %w", err)
		}

		manifests = lo.Filter(manifests, func(item v1.Descriptor, index int) bool {
			return item.ArtifactType == artifactType.MediaType()
		})
	}

	for annKey, annValue := range opts.FilterAnnotations {
		manifests = lo.Filter(manifests, func(item v1.Descriptor, index int) bool {
			return item.Annotations[annKey] == annValue
		})
	}
	return manifests, nil
}
