package certificateutil

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/bitrise-io/go-utils/fileutil"

	"github.com/bitrise-io/go-utils/command"
	"github.com/bitrise-io/go-utils/pkcs12"
	"github.com/pkg/errors"
)

// CertificateInfoModel ...
type CertificateInfoModel struct {
	UserID     string
	CommonName string
	TeamID     string
	Name       string
	Local      string
	EndDate    time.Time

	Serial string
	Hash   string

	RawSubject string
	RawEndDate string
}

// IsExpired ...
func (cert CertificateInfoModel) IsExpired() bool {
	if cert.EndDate.IsZero() {
		return false
	}

	return cert.EndDate.Before(time.Now())
}

func commandError(printableCmd string, cmdOut string, cmdErr error) error {
	return errors.Wrapf(cmdErr, "%s failed, out: %s", printableCmd, cmdOut)
}

func convertP12ToPem(p12Pth, password string) (string, error) {
	cmd := command.New("openssl", "pkcs12", "-in", p12Pth, "-nodes", "-passin", "pass:"+password)
	out, err := cmd.RunAndReturnTrimmedCombinedOutput()
	if err != nil {
		return "", commandError(cmd.PrintableCommandArgs(), out, err)
	}
	return out, nil
}

func parsePemEndDateSubjectAndSerial(out string) (CertificateInfoModel, error) {
	lines := strings.Split(out, "\n")
	if len(lines) < 3 {
		return CertificateInfoModel{}, fmt.Errorf("failed to parse certificate info output: %s", out)
	}

	certificateInfos := CertificateInfoModel{}

	// notAfter=Aug 15 14:15:19 2018 GMT
	{
		line := strings.TrimSpace(lines[0])
		certificateInfos.RawEndDate = line

		pattern := `notAfter=(?P<date>.*)`
		re := regexp.MustCompile(pattern)
		if matches := re.FindStringSubmatch(line); len(matches) == 2 {
			endDateStr := matches[1]
			endDate, err := time.Parse("Jan 2 15:04:05 2006 MST", endDateStr)
			if err == nil {
				certificateInfos.EndDate = endDate
			}
		}
	}

	// subject= /UID=5KN/CN=iPhone Developer: Bitrise Bot (T36)/OU=339/O=Bitrise Bot/C=US
	{
		line := strings.TrimSpace(lines[1])
		certificateInfos.RawSubject = line

		pattern := `subject= /UID=(?P<userID>.*)/CN=(?P<commonName>.*)/OU=(?P<teamID>.*)/O=(?P<name>.*)/C=(?P<local>.*)`
		re := regexp.MustCompile(pattern)
		if matches := re.FindStringSubmatch(line); len(matches) == 6 {
			certificateInfos.UserID = matches[1]
			certificateInfos.CommonName = matches[2]
			certificateInfos.TeamID = matches[3]
			certificateInfos.Name = matches[4]
			certificateInfos.Local = matches[5]
		}
	}

	// serial=123
	{
		line := strings.TrimSpace(lines[2])

		pattern := `serial=(?P<serial>.*)`
		re := regexp.MustCompile(pattern)
		if matches := re.FindStringSubmatch(line); len(matches) == 2 {
			certificateInfos.Serial = matches[1]
		} else {
			return CertificateInfoModel{}, fmt.Errorf("failed to parse certificate serial: %s", line)
		}
	}

	return certificateInfos, nil
}

// CertificateInfosFromPemContent ...
func CertificateInfosFromPemContent(pem string) ([]CertificateInfoModel, error) {
	certInfoModels := []CertificateInfoModel{}

	pattern := `(?s)(-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----)`
	pems := regexp.MustCompile(pattern).FindAllString(pem, -1)
	if len(pems) == 0 {
		return []CertificateInfoModel{}, fmt.Errorf("no certificates found in pem: %s", pem)
	}

	for _, pem := range pems {
		cmd := command.New("openssl", "x509", "-noout", "-enddate", "-subject", "-serial")
		cmd.SetStdin(bytes.NewReader([]byte(pem)))
		out, err := cmd.RunAndReturnTrimmedCombinedOutput()
		if err != nil {
			return []CertificateInfoModel{}, commandError(cmd.PrintableCommandArgs(), out, err)
		}

		certInfoModel, err := parsePemEndDateSubjectAndSerial(out)
		if err != nil {
			return []CertificateInfoModel{}, err
		}

		certInfoModels = append(certInfoModels, certInfoModel)
	}

	return certInfoModels, nil
}

// CertificateInfosFromDerContent ...
func CertificateInfosFromDerContent(pemContent []byte) (CertificateInfoModel, error) {
	cmd := command.New("openssl", "x509", "-inform", "DER", "-noout", "-enddate", "-subject", "-serial")
	cmd.SetStdin(bytes.NewReader(pemContent))
	out, err := cmd.RunAndReturnTrimmedCombinedOutput()
	if err != nil {
		return CertificateInfoModel{}, commandError(cmd.PrintableCommandArgs(), out, err)
	}

	return parsePemEndDateSubjectAndSerial(out)
}

// CertificateInfosFromP12 ...
func CertificateInfosFromP12(p12Pth, password string) ([]CertificateInfoModel, error) {
	p12, err := fileutil.ReadBytesFromFile(p12Pth)
	if err != nil {
		return nil, err
	}

	_, certificates, err := pkcs12.DecodeAllCerts(p12, password)
	if err != nil {
		return nil, err
	}

	for _, certificate := range certificates {
		b, err := json.MarshalIndent(certificate, "", "\t")
		if err != nil {
			return nil, err
		}

		fmt.Printf("cert: %s\n", string(b))
	}

	return nil, nil
}

// InstalledCodesigningCertificateNamesFromOutput ...
func InstalledCodesigningCertificateNamesFromOutput(out string) ([]string, error) {
	pettern := `^[0-9]+\) (?P<hash>.*) "(?P<name>.*)"`
	re := regexp.MustCompile(pettern)

	certificateNameMap := map[string]bool{}
	scanner := bufio.NewScanner(strings.NewReader(out))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if matches := re.FindStringSubmatch(line); len(matches) == 3 {
			name := matches[2]
			certificateNameMap[name] = true
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	names := []string{}
	for name := range certificateNameMap {
		names = append(names, name)
	}
	return names, nil
}

// InstalledCodesigningCertificateNames ...
func InstalledCodesigningCertificateNames() ([]string, error) {
	cmd := command.New("security", "find-identity", "-v", "-p", "codesigning")
	out, err := cmd.RunAndReturnTrimmedCombinedOutput()
	if err != nil {
		return nil, commandError(cmd.PrintableCommandArgs(), out, err)
	}
	return InstalledCodesigningCertificateNamesFromOutput(out)
}

func trimAndParseSHA1HashLines(out string) ([]string, string, error) {
	hashes := []string{}
	trimmedLines := []string{}
	scanner := bufio.NewScanner(strings.NewReader(out))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "SHA-1 hash: ") {
			hash := strings.TrimPrefix(line, "SHA-1 hash: ")
			hashes = append(hashes, hash)
		} else {
			trimmedLines = append(trimmedLines, line)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, "", err
	}
	return hashes, strings.Join(trimmedLines, "\n"), nil
}

// InstalledCertificates ...
func InstalledCertificates() ([]CertificateInfoModel, error) {
	certificateNames, err := InstalledCodesigningCertificateNames()
	if err != nil {
		return nil, err
	}

	certificates := []CertificateInfoModel{}
	for _, name := range certificateNames {
		cmd := command.New("security", "find-certificate", "-c", name, "-a", "-p", "-Z")
		out, err := cmd.RunAndReturnTrimmedCombinedOutput()
		if err != nil {
			return nil, commandError(cmd.PrintableCommandArgs(), out, err)
		}

		hashes, trimmedOut, err := trimAndParseSHA1HashLines(out)
		if err != nil {
			return nil, err
		}

		certs, err := CertificateInfosFromPemContent(trimmedOut)
		if err != nil {
			return nil, err
		}

		if len(hashes) != len(certs) {
			return nil, fmt.Errorf("certificates (%d) and its hashes (%d) count should equal", len(certs), len(hashes))
		}

		for idx, cert := range certs {
			hash := hashes[idx]
			cert.Hash = hash
			cert.Name = name

			certificates = append(certificates, cert)
		}
	}

	return certificates, nil
}
