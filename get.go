package main

import (
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/samber/lo"
)

var errNoReferrerFound = fmt.Errorf("no referrer found")

func getReferrer(writer io.Writer, opts getOptions) error {
	var err error
	var artifactDigest name.Digest

	ref, err := name.ParseReference(opts.Reference)
	if err != nil {
		return fmt.Errorf("error parsing reference: %w", err)
	}

	desc, err := remote.Head(ref, remote.WithAuthFromKeychain(authn.DefaultKeychain))
	if err != nil {
		return fmt.Errorf("error getting descriptor: %w", err)
	}

	digest, err := name.NewDigest(
		fmt.Sprintf("%s/%s@%s", ref.Context().RegistryStr(), ref.Context().RepositoryStr(), desc.Digest.String()),
	)
	if err != nil {
		return fmt.Errorf("error creating digest: %w", err)
	}

	artifactDigest, err = findArtifactDigest(digest, opts)
	if errors.Is(err, errNoReferrerFound) {
		log.Logger.Infof("no referrer found(%s)", opts.Type)
		return nil
	}
	if err != nil {
		return fmt.Errorf("error getting artifact digest: %w", err)
	}

	image, err := remote.Image(artifactDigest, remote.WithAuthFromKeychain(authn.DefaultKeychain))
	if err != nil {
		return fmt.Errorf("error fetching image: %w", err)
	}

	layers, err := image.Layers()
	if err != nil {
		return fmt.Errorf("error getting layers: %w", err)
	}

	artifact, err := layers[0].Compressed()
	if err != nil {
		return fmt.Errorf("error getting artifact: %w", err)
	}

	io.Copy(writer, artifact)

	return nil
}

func findArtifactDigest(digest name.Digest, opts getOptions) (name.Digest, error) {
	index, err := remote.Referrers(digest, remote.WithAuthFromKeychain(authn.DefaultKeychain))
	if err != nil {
		return name.Digest{}, fmt.Errorf("error fetching referrers: %w", err)
	}

	var manifest v1.Descriptor
	if opts.Digest != "" {
		manifest, err = findReferrerByDigest(index, opts)
		if err != nil {
			return name.Digest{}, fmt.Errorf("error finding referrers: %w", err)
		}
	} else if opts.Type != "" {
		manifest, err = findLatestReferrerByType(index, opts)
		if err != nil {
			return name.Digest{}, fmt.Errorf("error fetching referrers: %w", err)
		}
	} else {
		return name.Digest{}, fmt.Errorf("either digest or type must be specified")
	}

	artifactDigest, err := name.NewDigest(
		fmt.Sprintf("%s/%s@%s", digest.Context().RegistryStr(), digest.Context().RepositoryStr(), manifest.Digest.String()),
	)
	if err != nil {
		return name.Digest{}, fmt.Errorf("error parsing artifact tag: %w", err)
	}
	return artifactDigest, nil
}

func findReferrerByDigest(index *v1.IndexManifest, opts getOptions) (v1.Descriptor, error) {
	m, found := lo.Find(index.Manifests, func(item v1.Descriptor) bool {
		return item.Digest.String() == opts.Digest
	})
	if !found {
		return v1.Descriptor{}, errNoReferrerFound
	}
	return m, nil
}

func findLatestReferrerByType(index *v1.IndexManifest, opts getOptions) (v1.Descriptor, error) {

	artifactType, err := getArtifactType(opts.Type)
	if err != nil {
		return v1.Descriptor{}, fmt.Errorf("error getting artifact type: %w", err)
	}

	filtered := lo.Filter(index.Manifests, func(item v1.Descriptor, index int) bool {
		return item.ArtifactType == artifactType
	})

	if len(filtered) == 0 {
		return v1.Descriptor{}, errNoReferrerFound
	}

	if len(filtered) > 1 {
		log.Logger.Infof("%d referrers found(%s)", len(filtered), opts.Type)
	}

	latest := lo.MaxBy(filtered, func(item v1.Descriptor, max v1.Descriptor) bool {
		var t1, t2 time.Time
		if v, ok := item.Annotations[annotationKeyCreated]; ok {
			t1, _ = time.Parse(time.RFC3339, v)
		} else {
			t1 = time.Time{}
		}

		if v, ok := max.Annotations[annotationKeyCreated]; ok {
			t2, _ = time.Parse(time.RFC3339, v)
		} else {
			t2 = time.Time{}
		}

		// In case both values are not set, take the latter one.
		return t1.Compare(t2) >= 0
	})
	return latest, nil
}
