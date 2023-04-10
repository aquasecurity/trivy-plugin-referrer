package main

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/spf13/cobra"
)

type putOptions struct {
	Annotations map[string]string
	Subject     string
}

type getOptions struct {
	Type    string
	Subject string
	Digest  string
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

			err = putReferrer(reader, putOptions{Annotations: ann, Subject: subject})
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

	getCmd := &cobra.Command{
		Use:   "get",
		Short: "get a referrer",
		Example: `  $ trivy referrer get --type cyclonedx --subject YOUR_IMAGE
  $ trivy referrer get --digest ARTIFACT_DIGEST`,
		RunE: func(cmd *cobra.Command, args []string) error {
			output := cmd.Flags().Lookup("output").Value.String()
			var writer io.Writer
			if output == "" {
				writer = os.Stdout
			} else {
				fp, err := os.Create(output)
				if err != nil {
					return fmt.Errorf("error creating file: %w", err)
				}
				defer fp.Close()

				writer = fp
			}

			digest, err := cmd.Flags().GetString("digest")
			if err != nil {
				return fmt.Errorf("error getting digest: %w", err)
			}

			subject, err := cmd.Flags().GetString("subject")
			if err != nil {
				return fmt.Errorf("error getting subject: %w", err)
			}

			t, err := cmd.Flags().GetString("type")
			if err != nil {
				return fmt.Errorf("error getting file path: %w", err)
			}

			err = getReferrer(writer, getOptions{
				Type:    t,
				Subject: subject,
				Digest:  digest,
			})
			if err != nil {
				return fmt.Errorf("error getting referrer: %w", err)
			}

			return nil
		},
	}
	getCmd.Flags().StringP("type", "", "", "artifact type (cyclonedx, spdx-json, sarif, cosign-vuln)")
	getCmd.Flags().StringP("subject", "", "", "get a referrer for the subject reference.")
	getCmd.Flags().StringP("digest", "", "", "artifact digest")
	getCmd.Flags().StringP("output", "o", "", "output file name")

	rootCmd.AddCommand(getCmd)

	if err := rootCmd.Execute(); err != nil {
		log.Logger.Fatal(err)
	}
}
