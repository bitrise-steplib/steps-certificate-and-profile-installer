package certificateutil

import (
	"fmt"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/bitrise-io/go-utils/command"
	"github.com/bitrise-io/go-utils/fileutil"
	"github.com/bitrise-io/go-utils/pathutil"
)

const appleCACertificateChain = `-----BEGIN CERTIFICATE-----
MIIEIjCCAwqgAwIBAgIIAd68xDltoBAwDQYJKoZIhvcNAQEFBQAwYjELMAkGA1UE
BhMCVVMxEzARBgNVBAoTCkFwcGxlIEluYy4xJjAkBgNVBAsTHUFwcGxlIENlcnRp
ZmljYXRpb24gQXV0aG9yaXR5MRYwFAYDVQQDEw1BcHBsZSBSb290IENBMB4XDTEz
MDIwNzIxNDg0N1oXDTIzMDIwNzIxNDg0N1owgZYxCzAJBgNVBAYTAlVTMRMwEQYD
VQQKDApBcHBsZSBJbmMuMSwwKgYDVQQLDCNBcHBsZSBXb3JsZHdpZGUgRGV2ZWxv
cGVyIFJlbGF0aW9uczFEMEIGA1UEAww7QXBwbGUgV29ybGR3aWRlIERldmVsb3Bl
ciBSZWxhdGlvbnMgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkwggEiMA0GCSqGSIb3
DQEBAQUAA4IBDwAwggEKAoIBAQDKOFSmy1aqyCQ5SOmM7uxfuH8mkbw0U3rOfGOA
YXdkXqUHI7Y5/lAtFVZYcC1+xG7BSoU+L/DehBqhV8mvexj/avoVEkkVCBmsqtsq
Mu2WY2hSFT2Miuy/axiV4AOsAX2XBWfODoWVN2rtCbauZ81RZJ/GXNG8V25nNYB2
NqSHgW44j9grFU57Jdhav06DwY3Sk9UacbVgnJ0zTlX5ElgMhrgWDcHld0WNUEi6
Ky3klIXh6MSdxmilsKP8Z35wugJZS3dCkTm59c3hTO/AO0iMpuUhXf1qarunFjVg
0uat80YpyejDi+l5wGphZxWy8P3laLxiX27Pmd3vG2P+kmWrAgMBAAGjgaYwgaMw
HQYDVR0OBBYEFIgnFwmpthhgi+zruvZHWcVSVKO3MA8GA1UdEwEB/wQFMAMBAf8w
HwYDVR0jBBgwFoAUK9BpR5R2Cf70a40uQKb3R01/CF4wLgYDVR0fBCcwJTAjoCGg
H4YdaHR0cDovL2NybC5hcHBsZS5jb20vcm9vdC5jcmwwDgYDVR0PAQH/BAQDAgGG
MBAGCiqGSIb3Y2QGAgEEAgUAMA0GCSqGSIb3DQEBBQUAA4IBAQBPz+9Zviz1smwv
j+4ThzLoBTWobot9yWkMudkXvHcs1Gfi/ZptOllc34MBvbKuKmFysa/Nw0Uwj6OD
Dc4dR7Txk4qjdJukw5hyhzs+r0ULklS5MruQGFNrCk4QttkdUGwhgAqJTleMa1s8
Pab93vcNIx0LSiaHP7qRkkykGRIZbVf1eliHe2iK5IaMSuviSRSqpd1VAKmuu0sw
ruGgsbwpgOYJd+W+NKIByn/c4grmO7i77LpilfMFY0GCzQ87HUyVpNur+cmV6U/k
TecmmYHpvPm0KdIBembhLoz2IYrF+Hjhga6/05Cdqa3zr/04GpZnMBxRpVzscYqC
tGwPDBUf
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIEuzCCA6OgAwIBAgIBAjANBgkqhkiG9w0BAQUFADBiMQswCQYDVQQGEwJVUzET
MBEGA1UEChMKQXBwbGUgSW5jLjEmMCQGA1UECxMdQXBwbGUgQ2VydGlmaWNhdGlv
biBBdXRob3JpdHkxFjAUBgNVBAMTDUFwcGxlIFJvb3QgQ0EwHhcNMDYwNDI1MjE0
MDM2WhcNMzUwMjA5MjE0MDM2WjBiMQswCQYDVQQGEwJVUzETMBEGA1UEChMKQXBw
bGUgSW5jLjEmMCQGA1UECxMdQXBwbGUgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkx
FjAUBgNVBAMTDUFwcGxlIFJvb3QgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw
ggEKAoIBAQDkkakJH5HbHkdQ6wXtXnmELes2oldMVeyLGYne+Uts9QerIjAC6Bg+
+FAJ039BqJj50cpmnCRrEdCju+QbKsMflZ56DKRHi1vUFjczy8QPTc4UadHJGXL1
XQ7Vf1+b8iUDulWPTV0N8WQ1IxVLFVkds5T39pyez1C6wVhQZ48ItCD3y6wsIG9w
tj8BMIy3Q88PnT3zK0koGsj+zrW5DtleHNbLPbU6rfQPDgCSC7EhFi501TwN22IW
q6NxkkdTVcGvL0Gz+PvjcM3mo0xFfh9Ma1CWQYnEdGILEINBhzOKgbEwWOxaBDKM
aLOPHd5lc/9nXmW8Sdh2nzMUZaF3lMktAgMBAAGjggF6MIIBdjAOBgNVHQ8BAf8E
BAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUK9BpR5R2Cf70a40uQKb3
R01/CF4wHwYDVR0jBBgwFoAUK9BpR5R2Cf70a40uQKb3R01/CF4wggERBgNVHSAE
ggEIMIIBBDCCAQAGCSqGSIb3Y2QFATCB8jAqBggrBgEFBQcCARYeaHR0cHM6Ly93
d3cuYXBwbGUuY29tL2FwcGxlY2EvMIHDBggrBgEFBQcCAjCBthqBs1JlbGlhbmNl
IG9uIHRoaXMgY2VydGlmaWNhdGUgYnkgYW55IHBhcnR5IGFzc3VtZXMgYWNjZXB0
YW5jZSBvZiB0aGUgdGhlbiBhcHBsaWNhYmxlIHN0YW5kYXJkIHRlcm1zIGFuZCBj
b25kaXRpb25zIG9mIHVzZSwgY2VydGlmaWNhdGUgcG9saWN5IGFuZCBjZXJ0aWZp
Y2F0aW9uIHByYWN0aWNlIHN0YXRlbWVudHMuMA0GCSqGSIb3DQEBBQUAA4IBAQBc
NplMLXi37Yyb3PN3m/J20ncwT8EfhYOFG5k9RzfyqZtAjizUsZAS2L70c5vu0mQP
y3lPNNiiPvl4/2vIB+x9OYOLUyDTOMSxv5pPCmv/K/xZpwUJfBdAVhEedNO3iyM7
R6PVbyTi69G3cN8PReEnyvFteO3ntRcXqNx+IjXKJdXZD9Zr1KIkIxH3oayPc4Fg
xhtbCS+SsvhESPBgOJ4V9T0mZyCKM2r3DYLP3uujL/lTaltkwGMzd/c6ByxW69oP
IQ7aunMZT7XZNn/Bh1XZp5m5MkL72NVxnn6hUrcbvZNCJBIqxw8dtk2cXmPIS4AX
UKqK1drk/NAJBzewdXUh
-----END CERTIFICATE-----`

func findCertificate(name string) (string, error) {
	out, err := command.New("security", "find-certificate", "-c", name, "-p").RunAndReturnTrimmedCombinedOutput()
	if err != nil {
		return "", fmt.Errorf("failed to find certificate: %s, out: %s, error: %s", name, out, err)
	}
	return out, nil
}

// Apple Worldwide Developer Relations Certification Authority
func findAWDRCACertificate() (string, error) {
	name := "Apple Worldwide Developer Relations Certification Authority"
	return findCertificate(name)
}

// Apple Root CA
func findARCACertificate() (string, error) {
	name := "Apple Root CA"
	return findCertificate(name)
}

func chainCertificates(certs ...string) string {
	return strings.Join(certs, "\n")
}

func createAppleChainCertificate() (string, error) {
	tmpDir, err := pathutil.NormalizedOSTempDirPath("__certificate__")
	if err != nil {
		return "", err
	}

	// // create chain certificate
	// awdrCACertificate, err := findAWDRCACertificate()
	// if err != nil {
	// 	return "", err
	// }
	// arCACertificate, err := findARCACertificate()
	// if err != nil {
	// 	return "", err
	// }
	// chainCertificate := chainCertificates(awdrCACertificate, arCACertificate)

	chainCertificatePth := filepath.Join(tmpDir, "chain.pem")
	if err := fileutil.WriteStringToFile(chainCertificatePth, appleCACertificateChain); err != nil {
		return "", err
	}

	return chainCertificatePth, nil
}

// BrewUpdateOpenSSL ...
func BrewUpdateOpenSSL() (string, error) {
	if err := command.New("brew", "update").Run(); err != nil {
		return "", err
	}

	if err := command.New("brew", "install", "openssl").Run(); err != nil {
		return "", err
	}

	pattern := "/usr/local/Cellar/openssl/*/bin/openssl"
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return "", err
	}
	if len(matches) == 0 {
		return "", fmt.Errorf("failed to find updated openssl with pattern: %s", pattern)
	}

	return matches[0], err
}

func getCertificatePemPth(p12Pth, password string) (string, error) {
	tmpDir, err := pathutil.NormalizedOSTempDirPath("__certificate__")
	if err != nil {
		return "", err
	}

	pemPth := filepath.Join(tmpDir, "cert.pem")
	if err := command.New("openssl", "pkcs12", "-in", p12Pth, "-out", pemPth, "-passin", "pass:"+password, "-nodes", "-nokeys").Run(); err != nil {
		return "", err
	}

	pem, err := fileutil.ReadStringFromFile(pemPth)
	if err != nil {
		return "", err
	}

	if matches := regexp.MustCompile(`(?s)(-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----)`).FindAllString(string(pem), -1); len(matches) > 0 {
		pem = matches[0]
	} else {
		return "", fmt.Errorf("failed to trimm certificate: %#v", matches)
	}

	if err := fileutil.WriteStringToFile(pemPth, pem); err != nil {
		return "", err
	}

	return pemPth, nil
}

func getOCSPURI(pemPth string) (string, error) {
	out, err := command.New("openssl", "x509", "-in", pemPth, "-noout", "-ocsp_uri").RunAndReturnTrimmedCombinedOutput()
	if err != nil {
		return "", err
	}
	return out, nil
}

// IsCertificateP12Revoked ...
func IsCertificateP12Revoked(p12Pth, password, openSSLPth string) (bool, error) {
	appleChainCertificatePth, err := createAppleChainCertificate()
	if err != nil {
		return false, err
	}

	pemPth, err := getCertificatePemPth(p12Pth, password)
	if err != nil {
		return false, err
	}

	ocspURL, err := getOCSPURI(pemPth)
	if err != nil {
		return false, err
	}

	parsedURL, err := url.Parse(ocspURL)
	if err != nil {
		return false, err
	}

	ocspCmd := command.New(openSSLPth, "ocsp", "-issuer", appleChainCertificatePth, "-cert", pemPth, "-url", ocspURL, "-CAfile", appleChainCertificatePth, "-header", "HOST", parsedURL.Host)
	out, err := ocspCmd.RunAndReturnTrimmedCombinedOutput()
	if err != nil {
		return false, err
	}

	return !strings.Contains(out, "out: Response verify OK"), nil
}
