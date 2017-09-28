package certificateutil

import (
	"bytes"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/bitrise-io/go-utils/command"
	"github.com/bitrise-io/go-utils/pathutil"
)

// CertificateInfosModel ...
type CertificateInfosModel struct {
	UserID         string
	CommonName     string
	TeamID         string
	Name           string
	Local          string
	EndDate        time.Time
	RawSubject     string
	RawEndDate     string
	IsDevelopement bool
}

func convertP12ToPem(p12Pth, password string) (string, error) {
	tmpDir, err := pathutil.NormalizedOSTempDirPath("__pem__")
	if err != nil {
		return "", err
	}

	pemPth := filepath.Join(tmpDir, "certificate.pem")
	if out, err := command.New("openssl", "pkcs12", "-in", p12Pth, "-out", pemPth, "-nodes", "-passin", "pass:"+password).RunAndReturnTrimmedCombinedOutput(); err != nil {
		return "", fmt.Errorf("failed to convert .p12 certificate to .pem file, out: %s, error: %s", out, err)
	}

	return pemPth, nil
}

func certificateInfosByPath(pemPth string) (CertificateInfosModel, error) {
	out, err := command.New("openssl", "x509", "-in", pemPth, "-noout", "-enddate", "-subject").RunAndReturnTrimmedCombinedOutput()
	if err != nil {
		return CertificateInfosModel{}, fmt.Errorf("failed to read certificate infos, out: %s, error: %s", out, err)
	}

	return parseCertificateInfoOutput(out)
}

func certificateInfosByContent(pemContent []byte) (CertificateInfosModel, error) {
	cmd := command.New("openssl", "x509", "-noout", "-enddate", "-subject")
	cmd.SetStdin(bytes.NewReader(pemContent))
	out, err := cmd.RunAndReturnTrimmedCombinedOutput()
	if err != nil {
		return CertificateInfosModel{}, fmt.Errorf("failed to read certificate infos, out: %s, error: %s", out, err)
	}

	return parseCertificateInfoOutput(out)
}

func parseCertificateInfoOutput(out string) (CertificateInfosModel, error) {
	lines := strings.Split(out, "\n")
	if len(lines) < 2 {
		return CertificateInfosModel{}, fmt.Errorf("failed to parse certificate infos")
	}

	certificateInfos := CertificateInfosModel{}

	// notAfter=Aug 15 14:15:19 2018 GMT
	endDateLine := strings.TrimSpace(lines[0])
	endDatePattern := `notAfter=(?P<date>.*)`
	endDareRe := regexp.MustCompile(endDatePattern)
	if matches := endDareRe.FindStringSubmatch(endDateLine); len(matches) == 2 {
		endDateStr := matches[1]
		endDate, err := time.Parse("Jan 2 15:04:05 2006 MST", endDateStr)
		if err != nil {
			return CertificateInfosModel{}, fmt.Errorf("Failed to parse certificate end date, error: %s", err)
		}

		certificateInfos.EndDate = endDate
	} else {
		certificateInfos.RawEndDate = endDateLine
	}

	// subject= /UID=5KN/CN=iPhone Developer: Bitrise Bot (T36)/OU=339/O=Bitrise Bot/C=US
	subjectLine := strings.TrimSpace(lines[1])
	subjectPattern := `subject= /UID=(?P<userID>.*)/CN=(?P<commonName>.*)/OU=(?P<teamID>.*)/O=(?P<name>.*)/C=(?P<local>.*)`
	subjectRe := regexp.MustCompile(subjectPattern)
	if matches := subjectRe.FindStringSubmatch(subjectLine); len(matches) == 6 {
		userID := matches[1]
		commonName := matches[2]
		teamID := matches[3]
		name := matches[4]
		local := matches[5]

		certificateInfos.UserID = userID
		certificateInfos.CommonName = commonName
		certificateInfos.TeamID = teamID
		certificateInfos.Name = name
		certificateInfos.Local = local
		certificateInfos.IsDevelopement = (strings.Contains(commonName, "Developer:") || strings.Contains(commonName, "Development:"))
	} else {
		certificateInfos.IsDevelopement = (strings.Contains(subjectLine, "Developer:") || strings.Contains(subjectLine, "Development:"))
		certificateInfos.RawSubject = subjectLine
	}

	return certificateInfos, nil
}

// CertificateInfosFromP12 ...
func CertificateInfosFromP12(p12Pth, password string) (CertificateInfosModel, error) {
	pemPth, err := convertP12ToPem(p12Pth, password)
	if err != nil {
		return CertificateInfosModel{}, err
	}

	return certificateInfosByPath(pemPth)
}

// CertificateInfosFromPemContent ...
func CertificateInfosFromPemContent(pemContent []byte) (CertificateInfosModel, error) {
	return certificateInfosByContent(pemContent)
}

func (certInfo CertificateInfosModel) String() string {
	certInfoString := ""

	if certInfo.RawSubject == "" {
		certInfoString += fmt.Sprintf("- UserID: %s\n", certInfo.UserID)
		certInfoString += fmt.Sprintf("- CommonName: %s\n", certInfo.CommonName)
		certInfoString += fmt.Sprintf("- TeamID: %s\n", certInfo.TeamID)
		certInfoString += fmt.Sprintf("- Locale: %s\n", certInfo.Local)
		certInfoString += fmt.Sprintf("- UserID: %s\n", certInfo.UserID)
	} else {
		certInfoString += fmt.Sprintf("- RawSubject: %s\n", certInfo.RawSubject)
	}

	if certInfo.RawEndDate == "" {
		certInfoString += fmt.Sprintf("- EndDate: %s\n", certInfo.EndDate)
	} else {
		certInfoString += fmt.Sprintf("- RawEndDate: %s\n", certInfo.RawEndDate)
	}
	certInfoString += fmt.Sprintf("- IsDevelopement: %t", certInfo.IsDevelopement)

	return certInfoString
}
