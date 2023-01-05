package main

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/bitrise-io/go-steputils/input"
	"github.com/bitrise-io/go-steputils/v2/stepconf"
	v1command "github.com/bitrise-io/go-utils/command"
	"github.com/bitrise-io/go-utils/log"
	"github.com/bitrise-io/go-utils/pathutil"
	"github.com/bitrise-io/go-utils/retry"
	"github.com/bitrise-io/go-utils/v2/command"
	"github.com/bitrise-io/go-utils/v2/env"
	"github.com/bitrise-io/go-xcode/certificateutil"
	"github.com/bitrise-io/go-xcode/plistutil"
	"github.com/bitrise-io/go-xcode/profileutil"
	"github.com/bitrise-io/go-xcode/v2/autocodesign/certdownloader"
	"github.com/bitrise-io/go-xcode/v2/autocodesign/codesignasset"
	"github.com/bitrise-io/go-xcode/v2/autocodesign/keychain"
	"github.com/bitrise-io/go-xcode/v2/autocodesign/profiledownloader"
	"github.com/pkg/errors"
)

// Config ...
type Config struct {
	CertificateURL         string
	CertificatePassphrase  string
	ProvisioningProfileURL string

	InstallDefaults               string
	DefaultCertificateURL         string
	DefaultCertificatePassphrase  string
	DefaultProvisioningProfileURL string

	KeychainPath     string
	KeychainPassword string
}

func createConfigFromEnvs() Config {
	return Config{
		CertificateURL:         os.Getenv("certificate_url"),
		CertificatePassphrase:  os.Getenv("certificate_passphrase"),
		ProvisioningProfileURL: os.Getenv("provisioning_profile_url"),

		InstallDefaults:               os.Getenv("install_defaults"),
		DefaultCertificateURL:         os.Getenv("default_certificate_url"),
		DefaultCertificatePassphrase:  os.Getenv("default_certificate_passphrase"),
		DefaultProvisioningProfileURL: os.Getenv("default_provisioning_profile_url"),

		KeychainPath:     os.Getenv("keychain_path"),
		KeychainPassword: os.Getenv("keychain_password"),
	}
}

func secureInput(str string) string {
	if str == "" {
		return ""
	}

	secureStr := func(s string, show int) string {
		runeCount := utf8.RuneCountInString(s)
		if runeCount < 6 || show == 0 {
			return strings.Repeat("*", 3)
		}
		if show*4 > runeCount {
			show = 1
		}

		sec := fmt.Sprintf("%s%s%s", s[0:show], strings.Repeat("*", 3), s[len(s)-show:])
		return sec
	}

	prefix := ""
	cont := str
	sec := secureStr(cont, 0)

	if strings.HasPrefix(str, "file://") {
		prefix = "file://"
		cont = strings.TrimPrefix(str, prefix)
		sec = secureStr(cont, 3)
	} else if strings.HasPrefix(str, "http://www.") {
		prefix = "http://www."
		cont = strings.TrimPrefix(str, prefix)
		sec = secureStr(cont, 3)
	} else if strings.HasPrefix(str, "https://www.") {
		prefix = "https://www."
		cont = strings.TrimPrefix(str, prefix)
		sec = secureStr(cont, 3)
	} else if strings.HasPrefix(str, "http://") {
		prefix = "http://"
		cont = strings.TrimPrefix(str, prefix)
		sec = secureStr(cont, 3)
	} else if strings.HasPrefix(str, "https://") {
		prefix = "https://"
		cont = strings.TrimPrefix(str, prefix)
		sec = secureStr(cont, 3)
	}

	return prefix + sec
}

func (c Config) print() {
	fmt.Println()
	log.Infof("Configs:")
	log.Printf(" - CertificateURL: %s", secureInput(c.CertificateURL))
	log.Printf(" - CertificatePassphrase: %s", secureInput(c.CertificatePassphrase))
	log.Printf(" - ProvisioningProfileURL: %s", secureInput(c.ProvisioningProfileURL))

	log.Printf(" - InstallDefaults: %s", c.InstallDefaults)
	log.Printf(" - DefaultCertificateURL: %s", secureInput(c.DefaultCertificateURL))
	log.Printf(" - DefaultCertificatePassphrase: %s", secureInput(c.DefaultCertificatePassphrase))
	log.Printf(" - DefaultProvisioningProfileURL: %s", secureInput(c.DefaultProvisioningProfileURL))

	log.Printf(" - KeychainPath: %s", c.KeychainPath)
	log.Printf(" - KeychainPassword: %s", secureInput(c.KeychainPassword))
}

func (c Config) validate() error {
	if err := input.ValidateWithOptions(c.InstallDefaults, "yes", "no"); err != nil {
		return fmt.Errorf("issue with input InstallDefaults: %s", err)
	}

	if err := input.ValidateIfNotEmpty(c.KeychainPath); err != nil {
		return fmt.Errorf("issue with input KeychainPath: %s", err)
	}

	if err := input.ValidateIfNotEmpty(c.KeychainPassword); err != nil {
		return fmt.Errorf("issue with input KeychainPassword: %s", err)
	}

	return nil
}

func downloadFile(destionationPath, URL string) error {
	url, err := url.Parse(URL)
	if err != nil {
		return err
	}

	scheme := url.Scheme

	tmpDstFilePath := ""
	if scheme != "file" {
		tmpDir, err := pathutil.NormalizedOSTempDirPath("download")
		if err != nil {
			return err
		}

		tmpDst := path.Join(tmpDir, "tmp_file")
		tmpDstFile, err := os.Create(tmpDst)
		if err != nil {
			return err
		}
		defer func() {
			if err := tmpDstFile.Close(); err != nil {
				log.Errorf("Failed to close file (%s), error: %s", tmpDst, err)
			}
		}()

		success := false
		var response *http.Response
		for i := 0; i < 3 && !success; i++ {
			if i > 0 {
				fmt.Println("-> Retrying...")
				time.Sleep(3 * time.Second)
			}

			response, err = http.Get(URL)
			if err != nil {
				log.Errorf(err.Error())
			} else {
				success = true
			}

			if response != nil {
				defer func() {
					if err := response.Body.Close(); err != nil {
						log.Errorf("Failed to close response body, error: %s", err)
					}
				}()
			}
		}
		if !success {
			return err
		}

		_, err = io.Copy(tmpDstFile, response.Body)
		if err != nil {
			return err
		}

		tmpDstFilePath = tmpDstFile.Name()
	} else {
		tmpDstFilePath = strings.Replace(URL, scheme+"://", "", -1)
	}

	return v1command.CopyFile(tmpDstFilePath, destionationPath)
}

func strip(str string) string {
	str = strings.TrimSpace(str)
	return strings.Trim(str, "\"")
}

func splitAndStrip(str, sep string) []string {
	items := []string{}
	split := strings.Split(str, sep)
	for _, item := range split {
		item = strings.TrimSpace(item)
		item = strings.Trim(item, "\"")
		if item != "" {
			items = append(items, item)
		}
	}
	return items
}

func splitAndTrimSpace(str, sep string) []string {
	items := []string{}
	split := strings.Split(str, sep)
	for _, item := range split {
		item = strings.TrimSpace(item)
		if item != "" {
			items = append(items, item)
		}
	}
	return items
}

func appendWithoutDuplicatesAndKeepOrder(items []string, item string) []string {
	result := []string{}
	resultMap := map[string]bool{}

	list := append(items, item)
	for _, i := range list {
		exist := resultMap[i]
		if !exist {
			result = append(result, i)
			resultMap[i] = true
		}
	}

	return result
}

func printCertificateInfo(info certificateutil.CertificateInfoModel) {
	log.Donef(info.CommonName)
	log.Printf("serial: %s", info.Serial)
	log.Printf("team: %s (%s)", info.TeamName, info.TeamID)
	log.Printf("expire: %s", info.EndDate)

	if err := info.CheckValidity(); err != nil {
		log.Errorf("[X] %s", err)
	}
}

func collectCapabilities(profileType profileutil.ProfileType, entitlements plistutil.PlistData) map[string]interface{} {
	capabilities := map[string]interface{}{}
	for key, value := range entitlements {
		found := profileutil.KnownProfileCapabilitiesMap[profileType][key]
		if found {
			capabilities[key] = value
		}
	}
	return capabilities
}

func printProfileInfo(profileType profileutil.ProfileType, info profileutil.ProvisioningProfileInfoModel, installedCertificates []certificateutil.CertificateInfoModel) {
	log.Donef("%s (%s)", info.Name, info.UUID)
	log.Printf("exportType: %s", string(info.ExportType))
	log.Printf("team: %s (%s)", info.TeamName, info.TeamID)
	log.Printf("bundleID: %s", info.BundleID)

	capabilities := collectCapabilities(profileType, info.Entitlements)
	if len(capabilities) > 0 {
		log.Printf("capabilities:")
		for key, value := range capabilities {
			log.Printf("- %s: %v", key, value)
		}
	}

	log.Printf("certificates:")
	for _, certificateInfo := range info.DeveloperCertificates {
		log.Printf("- %s", certificateInfo.CommonName)
		log.Printf("  serial: %s", certificateInfo.Serial)
		log.Printf("  teamID: %s", certificateInfo.TeamID)
	}

	if len(info.ProvisionedDevices) > 0 {
		log.Printf("devices:")
		for _, deviceID := range info.ProvisionedDevices {
			log.Printf("- %s", deviceID)
		}
	}

	log.Printf("expire: %s", info.ExpirationDate)

	if !info.HasInstalledCertificate(installedCertificates) {
		log.Errorf("[X] none of the profile's certificates are installed")
	}

	if err := info.CheckValidity(); err != nil {
		log.Errorf("[X] %s", err)
	}

	if info.IsXcodeManaged() {
		log.Warnf("[!] xcode managed profile")
	}
}

func commandError(printableCmd string, cmdOut string, cmdErr error) error {
	return errors.Wrapf(cmdErr, "%s failed, out: %s", printableCmd, cmdOut)
}

func failF(format string, v ...interface{}) {
	log.Errorf(format, v...)
	os.Exit(1)
}

func failE(err error) {
	log.Errorf(err.Error())
	os.Exit(1)
}

func main() {
	configs := createConfigFromEnvs()
	configs.print()
	if err := configs.validate(); err != nil {
		failF("Issue with input: %s", err)
	}
	fmt.Println()

	// Collect Certificates
	var certificateURLPassphraseMap []certdownloader.CertificateAndPassphrase

	if configs.CertificateURL != "" {
		certificateURLs := splitAndTrimSpace(configs.CertificateURL, "|")

		// Do not splitAndTrimSpace passphrases, since a passphrase might be empty!
		certificatePassphrases := strings.Split(configs.CertificatePassphrase, "|")

		if len(certificateURLs) != len(certificatePassphrases) {
			failF(
				"Certificate URL count: (%d), is not equal to Certificate passphrase count: (%d).\n"+
					"This could be because one of your passphrases contains a pipe character (\"|\") "+
					"which is not supported, as it is used as the delimiter in the step input.",
				len(certificateURLs),
				len(certificatePassphrases),
			)
		}

		for i := 0; i < len(certificateURLs); i++ {
			certificateURL := certificateURLs[i]
			certificatePassphrase := certificatePassphrases[i]

			certificateURLPassphraseMap = append(certificateURLPassphraseMap, certdownloader.CertificateAndPassphrase{
				URL:        certificateURL,
				Passphrase: certificatePassphrase,
			})
		}
	}

	if configs.DefaultCertificateURL != "" && configs.InstallDefaults == "yes" {
		log.Printf("Default Certificate given")
		certificateURLPassphraseMap = append(certificateURLPassphraseMap, certdownloader.CertificateAndPassphrase{
			URL:        configs.DefaultCertificateURL,
			Passphrase: configs.DefaultCertificatePassphrase,
		})
	}

	certificateCount := len(certificateURLPassphraseMap)
	log.Printf("Provided Certificate count: %d", certificateCount)

	if certificateCount == 0 {
		log.Warnf("No Certificate provided")
	}

	// Collect Provisioning Profiles
	provisioningProfileURLs := splitAndTrimSpace(configs.ProvisioningProfileURL, "|")

	if configs.DefaultProvisioningProfileURL != "" && configs.InstallDefaults == "yes" {
		log.Printf("Default Provisioning Profile given")
		provisioningProfileURLs = append(provisioningProfileURLs, configs.DefaultProvisioningProfileURL)
	}

	profileCount := len(provisioningProfileURLs)
	log.Printf("Provided Provisioning Profile count: %d", profileCount)

	if profileCount == 0 {
		log.Warnf("No Provisioning Profile provided")
	}

	keychainWriter, err := keychain.New(configs.KeychainPath, stepconf.Secret(configs.KeychainPassword), command.NewFactory(env.NewRepository()))
	if err != nil {
		failE(fmt.Errorf("Failed to open Keychain: %w", err))
	}

	fmt.Println()
	log.Infof("Downloading certificate(s)...")
	fmt.Println()

	httpClient := retry.NewHTTPClient().StandardClient()
	certDownloader := certdownloader.NewDownloader(certificateURLPassphraseMap, httpClient)
	certificates, err := certDownloader.GetCertificates()
	if err != nil {
		failE(fmt.Errorf("Download failed: %w", err))
	}

	log.Printf("%d Certificate(s) downloaded.", len(certificates))

	fmt.Println()
	log.Infof("Installing downloaded Certificates...")
	fmt.Println()

	for i, cert := range certificates {
		log.Printf("%d/%d Certificate", i, len(certificates))
		printCertificateInfo(cert)

		// Empty passphrase provided, as already parsed certificate + private key
		if err := keychainWriter.InstallCertificate(cert, ""); err != nil {
			failE(fmt.Errorf("Failed to install certificate: %w", err))
		}

		fmt.Println()
	}

	fmt.Println()
	log.Infof("Downloading Provisioning Profile(s)...")

	profileDownloader := profiledownloader.New(provisioningProfileURLs, httpClient)
	assetInstaller := codesignasset.New(keychainWriter)

	profiles, err := profileDownloader.GetProfiles()
	if err != nil {
		failE(fmt.Errorf("Download failed: %w", err))
	}

	log.Printf("%d Provisoning Profile(s) downlaoded.", len(profiles))

	fmt.Println()
	log.Infof("Installing Provisioning Profile(s)")
	for i, profile := range profiles {
		log.Printf("%d/%d Provisioning Profile", i, len(profiles))
		log.Printf("%s", profile.Info.String(certificates...))
		fmt.Println()

		if err := assetInstaller.InstallProfile(profile.Profile); err != nil {
			failE(fmt.Errorf("Failed to install Provisioning Profile: %w", err))
		}
	}
}
