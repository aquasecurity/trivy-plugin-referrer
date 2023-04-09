# trivy-plugin-referrer

Trivy plugin for the OCI referrer

## Install

```
$ trivy plugin install github.com/aquasecurity/trivy-plugin-referrer
```

## Usage

### Putting the SBOM into the OCI registry

Put the SBOM into the OCI registry as a referrer.
You need the write permission for the target repository.
```
# CycloneDX
$ trivy image -q -f cyclonedx YOUR_IMAGE | trivy referrer put

# SPDX
$ trivy image -q -f spdx-json YOUR_IMAGE | trivy referrer put
```

You can also upload by specifying a file.
```
$ trivy image -q -f cyclonedx YOUR_IMAGE > sbom.cdx.json
$ trivy referrer put -f sbom.cdx.json
```

### Putting the SARIF into the OCI registry
```
# NOTICE: Since Trivy v0.38.3 doesn’t write subject identification in SARIF, you need to explicitly state the subject.
$ trivy image -q -f sarif YOUR_IMAGE | trivy referrer put --subject YOUR_IMAGE
```

### Putting the Vulnerability info into the OCI registry
```
$ trivy image -q -f cosign-vuln YOUR_IMAGE | trivy referrer put
```
