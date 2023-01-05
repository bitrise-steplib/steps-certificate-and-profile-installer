package main

import (
	"fmt"
	"os"
	"strings"
	"unicode/utf8"

	"github.com/bitrise-io/go-steputils/input"
	"github.com/bitrise-io/go-steputils/v2/stepconf"
	"github.com/bitrise-io/go-utils/log"
	"github.com/bitrise-io/go-utils/retry"
	"github.com/bitrise-io/go-utils/v2/command"
	"github.com/bitrise-io/go-utils/v2/env"
	"github.com/bitrise-io/go-xcode/certificateutil"
	"github.com/bitrise-io/go-xcode/v2/autocodesign/certdownloader"
	"github.com/bitrise-io/go-xcode/v2/autocodesign/codesignasset"
	"github.com/bitrise-io/go-xcode/v2/autocodesign/keychain"
	"github.com/bitrise-io/go-xcode/v2/autocodesign/profiledownloader"
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
	log.Printf("expiry: %s", info.EndDate)

	if err := info.CheckValidity(); err != nil {
		log.Errorf("[X] %s", err)
	}
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

	httpClient := retry.NewHTTPClient().StandardClient()
	certDownloader := certdownloader.NewDownloader(certificateURLPassphraseMap, httpClient)
	profileDownloader := profiledownloader.New(provisioningProfileURLs, httpClient)
	assetInstaller := codesignasset.NewWriter(*keychainWriter)

	fmt.Println()
	log.Infof("Downloading certificate(s)...")

	certificates, err := certDownloader.GetCertificates()
	if err != nil {
		failE(fmt.Errorf("Download failed: %w", err))
	}

	log.Printf("%d Certificate(s) downloaded.", len(certificates))

	fmt.Println()
	log.Infof("Installing downloaded Certificates")
	fmt.Println()

	for i, cert := range certificates {
		log.Printf("%d/%d Certificate:", i+1, len(certificates))
		printCertificateInfo(cert)

		if err := assetInstaller.InstallCertificate(cert); err != nil {
			failE(fmt.Errorf("Failed to install certificate: %w", err))
		}

		fmt.Println()
	}

	fmt.Println()
	log.Infof("Downloading Provisioning Profile(s)...")

	profiles, err := profileDownloader.GetProfiles()
	if err != nil {
		failE(fmt.Errorf("Download failed: %w", err))
	}

	log.Printf("%d Provisoning Profile(s) downloaded.", len(profiles))

	fmt.Println()
	log.Infof("Installing Provisioning Profile(s)")
	for i, profile := range profiles {
		log.Printf("%d/%d Provisioning Profile", i+1, len(profiles))
		log.Printf("%s", profile.Info.String(certificates...))
		fmt.Println()

		if err := assetInstaller.InstallProfile(profile.Profile); err != nil {
			failE(fmt.Errorf("Failed to install Provisioning Profile: %w", err))
		}
	}
}
