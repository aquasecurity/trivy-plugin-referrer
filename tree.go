package main

import (
	"bufio"
	"fmt"
	"io"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/xlab/treeprint"
)

var digestFull = false

func FormatDigest(digest string) string {
	if digestFull {
		return digest
	}
	return strings.TrimPrefix(digest, "sha256:")[:7]
}

func treeReferrers(w io.Writer, opts treeOptions) error {

	if opts.Full {
		digestFull = true
	}

	targetDigest, err := fetchTargetDigest(opts.Subject)
	if err != nil {
		return fmt.Errorf("error getting digest: %w", err)
	}

	writer := bufio.NewWriter(w)
	defer writer.Flush()

	writer.Write([]byte(fmt.Sprintf("Subject: %s\n\n", opts.Subject)))

	tree := treeprint.NewWithRoot(FormatDigest(targetDigest.DigestStr()))
	if err := recurseReferrers(tree, targetDigest); err != nil {
		return fmt.Errorf("error writing referrers: %w", err)
	}

	writer.Write([]byte(tree.String()))

	return nil
}

func recurseReferrers(root treeprint.Tree, digest name.Digest) error {
	index, err := remote.Referrers(digest, remote.WithAuthFromKeychain(authn.DefaultKeychain))
	if err != nil {
		return fmt.Errorf("error fetching referrers: %w", err)
	}

	if len(index.Manifests) == 0 {
		return nil
	}

	for _, manifest := range index.Manifests {
		node := root.AddBranch(fmt.Sprintf("%s: %s", FormatDigest(manifest.Digest.String()), manifest.ArtifactType))

		d, err := name.NewDigest(
			fmt.Sprintf("%s/%s@%s", digest.RegistryStr(), digest.RepositoryStr(), manifest.Digest.String()),
		)
		if err != nil {
			return fmt.Errorf("error creating digest: %w", err)
		}

		if err := recurseReferrers(node, d); err != nil {
			return fmt.Errorf("error writing referrers: %w", err)
		}
	}
	return nil
}
