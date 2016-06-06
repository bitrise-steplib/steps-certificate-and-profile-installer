package main

import (
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"regexp"
	"strings"
	"time"
)

//--------------------
// Functions
//--------------------

// PrintErrorlnf ...
func PrintErrorlnf(format string, a ...interface{}) {
	errorMsg := fmt.Sprintf(format, a...)
	Printlnf("\x1b[31;1m%s\x1b[0m", errorMsg)
}

// Printlnf ...
func Printlnf(format string, a ...interface{}) {
	fmt.Printf(format, a...)
	fmt.Println()
}

func normalizedOSTempDirPath(tmpDirNamePrefix string) (retPth string, err error) {
	retPth, err = ioutil.TempDir("", tmpDirNamePrefix)
	if strings.HasSuffix(retPth, "/") {
		retPth = retPth[:len(retPth)-1]
	}
	return
}

func isPathExists(pth string) (bool, error) {
	if pth == "" {
		return false, errors.New("No path provided")
	}
	_, err := os.Stat(pth)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

func validateRequiredInput(key string) (string, error) {
	value := os.Getenv(key)
	if value == "" {
		return "", fmt.Errorf("[!] Missing required input: %s", key)
	}
	return value, nil
}

func printConfig(
	certificateURL,
	certificatePassphrase,
	provisioningProfileURL,
	keychainPath,
	keychainPassword,
	defaultCertificateURL,
	defaultCertificatePassphrase,
	defaultProvisioningProfileURL string) {
	fmt.Println()
	fmt.Println("Configs:")
	fmt.Println("--------")
	if keychainPath != "" {
		Printlnf(" * keychain_path: %s", keychainPath)
	}

	if keychainPassword != "" {
		keychainPassword = "***"
	}
	Printlnf(" * keychain_password: %s", keychainPassword)

	if certificateURL != "" {
		certificateURL = "***"
	}
	Printlnf(" * certificate_url: %s", certificateURL)

	if certificatePassphrase != "" {
		certificatePassphrase = "***"
	}
	Printlnf(" * certificate_passphrase: %s", certificatePassphrase)

	if provisioningProfileURL != "" {
		provisioningProfileURL = "***"
	}
	Printlnf(" * provisioning_profile_url: %s", provisioningProfileURL)

	if defaultCertificateURL != "" {
		defaultCertificateURL = "***"
	}
	Printlnf(" * default_certificate_url: %s", defaultCertificateURL)

	if defaultCertificatePassphrase != "" {
		defaultCertificatePassphrase = "***"
	}
	Printlnf(" * default_certificate_passphrase: %s", defaultCertificatePassphrase)

	if defaultProvisioningProfileURL != "" {
		defaultProvisioningProfileURL = "***"
	}
	Printlnf(" * default_provisioning_profile_url: %s", defaultProvisioningProfileURL)

	fmt.Println()
}

func downloadFile(destionationPath, URL string) error {
	url, err := url.Parse(URL)
	if err != nil {
		return err
	}

	scheme := url.Scheme
	tokens := strings.Split(URL, "/")
	fileName := tokens[len(tokens)-1]

	tmpDstFilePath := ""
	if scheme != "file" {
		Printlnf("   Downloading (***) to (%s)", destionationPath)

		tmpDir, err := normalizedOSTempDirPath("download")
		if err != nil {
			return err
		}
		tmpDst := path.Join(tmpDir, fileName)
		tmpDstFile, err := os.Create(tmpDst)
		if err != nil {
			return err
		}
		defer tmpDstFile.Close()

		success := false
		var response *http.Response
		for i := 0; i < 3 && !success; i++ {
			if i > 0 {
				fmt.Println("-> Retrying...")
				time.Sleep(3 * time.Second)
			}

			response, err = http.Get(URL)
			if err != nil {
				PrintErrorlnf("%s", err)
			} else {
				success = true
			}

			if response != nil {
				defer response.Body.Close()
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
		Printlnf("   Moving (***) to (%s)", destionationPath)
		tmpDstFilePath = strings.Replace(URL, scheme+"://", "", -1)
	}

	if out, err := runCommandAndReturnCombinedStdoutAndStderr("cp", tmpDstFilePath, destionationPath); err != nil {
		Printlnf("Move out: %s", out)
		return err
	}

	return nil
}

func runCommandAndReturnCombinedStdoutAndStderr(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	outBytes, err := cmd.CombinedOutput()
	outStr := string(outBytes)
	return strings.TrimSpace(outStr), err
}

func writeBytesToFileWithPermission(pth string, fileCont []byte, perm os.FileMode) error {
	if pth == "" {
		return errors.New("No path provided")
	}

	var file *os.File
	var err error
	if perm == 0 {
		file, err = os.Create(pth)
	} else {
		// same as os.Create, but with a specified permission
		//  the flags are copy-pasted from the official
		//  os.Create func: https://golang.org/src/os/file.go?s=7327:7366#L244
		file, err = os.OpenFile(pth, os.O_RDWR|os.O_CREATE|os.O_TRUNC, perm)
	}
	if err != nil {
		return err
	}
	defer func() {
		if err := file.Close(); err != nil {
			log.Println(" [!] Failed to close file:", err)
		}
	}()

	if _, err := file.Write(fileCont); err != nil {
		return err
	}

	return nil
}

func searchIphoneAndMacCreatificates(lines []string) []string {
	// "labl"<blob>="iPhone Distribution: XYZ (72SAXYZ)"
	certExp := regexp.MustCompile(`\"labl\"<blob>=\"(?P<profile>.*)\"`)

	// "labl"<blob>=0x6950686F6E6520446973747269627574696F6E3A20436C616E2056656E74757265205547202868616674756E6773626573636872EFBFBD6E6B7429202844564D455A524D50444D29  "iPhone Distribution: XYZ (xyz\357\277\275xyz) (XYZ)"
	longCertExp := regexp.MustCompile(`\"labl\"<blob>=.* \"(?P<profile>.*)\"`)

	certs := []string{}
	certFound := false

	for _, line := range lines {
		certRes := certExp.FindStringSubmatch(line)
		if certRes != nil {
			cert := certRes[1]
			certs = append(certs, cert)
			certFound = true
		}
		if !certFound {
			certRes := longCertExp.FindStringSubmatch(line)
			if certRes != nil {
				cert := certRes[1]
				certs = append(certs, cert)
			}
		}
		certFound = false
	}

	filteredCerts := []string{}
	for _, cert := range certs {
		if strings.HasPrefix(cert, "iPhone") || strings.HasPrefix(cert, "Mac") || strings.HasPrefix(cert, "3rd Party Mac") {
			filteredCerts = append(filteredCerts, cert)
		}
	}

	return filteredCerts
}

func searchFriendlyName(certStr string) string {
	// friendlyName: iPhone Distribution: XYZ (72SXYZ)
	certificateIdentityExp := regexp.MustCompile(`friendlyName: (?P<identity>.*)`)
	certificateIdentityRes := certificateIdentityExp.FindStringSubmatch(certStr)
	if certificateIdentityRes != nil {
		return certificateIdentityRes[1]
	}
	return ""
}

func certificateFriendlyName(certificatePath, certificatePassphrase string) (string, error) {
	out, err := runCommandAndReturnCombinedStdoutAndStderr("openssl", "pkcs12", "-info", "-nodes", "-in", certificatePath, "-passin", "pass:"+certificatePassphrase)
	if err != nil {
		return out, err
	}
	name := searchFriendlyName(out)
	return name, nil
}

func availableCertificates(keychainPath string) ([]string, error) {
	out, err := runCommandAndReturnCombinedStdoutAndStderr("security", "find-certificate", "-a", keychainPath)
	if err != nil {
		return []string{}, fmt.Errorf("Failed to list keys, err: %s", err)
	}

	outSplit := strings.Split(out, "\n")
	certs := searchIphoneAndMacCreatificates(outSplit)
	return certs, nil
}

func strip(str string) string {
	dirty := true
	strippedStr := str
	for dirty {
		hasWhiteSpacePrefix := false
		if strings.HasPrefix(strippedStr, " ") {
			hasWhiteSpacePrefix = true
			strippedStr = strings.TrimPrefix(strippedStr, " ")
		}

		hasWhiteSpaceSuffix := false
		if strings.HasSuffix(strippedStr, " ") {
			hasWhiteSpaceSuffix = true
			strippedStr = strings.TrimSuffix(strippedStr, " ")
		}

		hasNewlinePrefix := false
		if strings.HasPrefix(strippedStr, "\n") {
			hasNewlinePrefix = true
			strippedStr = strings.TrimPrefix(strippedStr, "\n")
		}

		hasNewlineSuffix := false
		if strings.HasSuffix(strippedStr, "\n") {
			hasNewlinePrefix = true
			strippedStr = strings.TrimSuffix(strippedStr, "\n")
		}

		hasQuotationPrefix := false
		if strings.HasPrefix(strippedStr, "\"") {
			hasQuotationPrefix = true
			strippedStr = strings.TrimPrefix(strippedStr, "\"")
		}

		hasQuotationSuffix := false
		if strings.HasSuffix(strippedStr, "\"") {
			hasQuotationSuffix = true
			strippedStr = strings.TrimSuffix(strippedStr, "\"")
		}

		if !hasWhiteSpacePrefix && !hasWhiteSpaceSuffix &&
			!hasNewlinePrefix && !hasNewlineSuffix &&
			!hasQuotationPrefix && !hasQuotationSuffix {
			dirty = false
		}
	}
	return strippedStr
}

func addKeyChainToList(keyChainList []string, keyChain string) []string {
	keyChains := []string{}
	keyChainMap := map[string]bool{}

	keyChainList = append(keyChainList, keyChain)

	for _, aKeyChain := range keyChainList {
		found, _ := keyChainMap[aKeyChain]
		if !found {
			keyChains = append(keyChains, aKeyChain)
			keyChainMap[aKeyChain] = true
		}
	}

	return keyChains
}

//--------------------
// Main
//--------------------

func main() {
	printFatallnf := func(exitCode int, format string, a ...interface{}) {
		errorMsg := fmt.Sprintf(format, a...)
		Printlnf("\x1b[31;1m%s\x1b[0m", errorMsg)
		os.Exit(exitCode)
	}

	//
	// Required parameters
	keychainPath, err := validateRequiredInput("keychain_path")
	if err != nil {
		log.Fatalf("Input validation failed, err: %s", err)
	}

	keychainPassword, err := validateRequiredInput("keychain_password")
	if err != nil {
		log.Fatalf("Input validation failed, err: %s", err)
	}

	//
	// Optional parameters
	certificateURL, err := validateRequiredInput("certificate_url")
	certificatePassphrase := os.Getenv("certificate_passphrase")
	provisioningProfileURL, err := validateRequiredInput("provisioning_profile_url")

	defaultCertificateURL := os.Getenv("default_certificate_url")
	defaultCertificatePassphrase := os.Getenv("default_certificate_passphrase")
	defaultProvisioningProfileURL := os.Getenv("default_provisioning_profile_url")

	printConfig(
		certificateURL,
		certificatePassphrase,
		provisioningProfileURL,
		keychainPath,
		keychainPassword,
		defaultCertificateURL,
		defaultCertificatePassphrase,
		defaultProvisioningProfileURL)

	//
	// Init
	homeDir := os.Getenv("HOME")
	provisioningProfileDir := path.Join(homeDir, "Library/MobileDevice/Provisioning Profiles")
	if exist, err := isPathExists(provisioningProfileDir); err != nil {
		printFatallnf(1, "Failed to check path (%s), err: %s", provisioningProfileDir, err)
	} else if !exist {
		if err := os.MkdirAll(provisioningProfileDir, 0777); err != nil {
			printFatallnf(1, "Failed to create path (%s), err: %s", provisioningProfileDir, err)
		}
	}

	tempDir, err := normalizedOSTempDirPath("bitrise-cert-tmp")
	if err != nil {
		printFatallnf(1, "Failed to create tmp directory, err: %s", err)
	}

	if exist, err := isPathExists(keychainPath); err != nil {
		printFatallnf(1, "Failed to check path (%s), err: %s", keychainPath, err)
	} else if !exist {
		Printlnf("Creating keychain: %s", keychainPath)

		if out, err := runCommandAndReturnCombinedStdoutAndStderr("security", "-v", "create-keychain", "-p", keychainPassword, keychainPath); err != nil {
			PrintErrorlnf("Failed to create keychain, output: %s", out)
			printFatallnf(1, "Failed to create keychain, err: %s", err)
		}
	} else {
		Printlnf("Keychain already exists, using it: %s", keychainPath)
	}

	//
	// Download certificate
	fmt.Println()
	Printlnf("Downloading & installing Certificate(s)")

	certificateURLPassphraseMap := map[string]string{}

	if certificateURL != "" {
		certificateURLPassphraseMap[certificateURL] = certificatePassphrase
	}

	if defaultCertificateURL != "" {
		fmt.Println("Default Certificate given")
		certificateURLPassphraseMap[defaultCertificateURL] = defaultCertificatePassphrase
	}

	certificateCount := len(certificateURLPassphraseMap)
	Printlnf("Provided Certificate count: %d", certificateCount)

	certificatePassphraseMap := map[string]string{}
	idx := 0
	for certURL, pass := range certificateURLPassphraseMap {
		fmt.Println()
		Printlnf("=> Downloading certificate: %d/%d", idx+1, certificateCount)

		certPath := path.Join(tempDir, fmt.Sprintf("Certificate-%d.p12", idx))
		if err := downloadFile(certPath, certURL); err != nil {
			printFatallnf(1, "Download failed, err: %s", err)
		}
		certificatePassphraseMap[certPath] = pass

		idx++
	}

	//
	// Install certificate
	fmt.Println()
	if len(certificatePassphraseMap) > 0 {
		Printlnf("=> Installing downloaded certificate")

		for cert, pass := range certificatePassphraseMap {
			// Import items into a keychain.
			importOut, err := runCommandAndReturnCombinedStdoutAndStderr("security", "import", cert, "-k", keychainPath, "-P", pass, "-A")
			if err != nil {
				PrintErrorlnf("Command failed, output: %s", importOut)
				printFatallnf(1, "Command failed, err: %s", err)
			}
		}

		// Set keychain settings: Lock keychain when the system sleeps, Lock keychain after timeout interval, Timeout in seconds
		settingsOut, err := runCommandAndReturnCombinedStdoutAndStderr("security", "-v", "set-keychain-settings", "-lut", "72000", keychainPath)
		if err != nil {
			PrintErrorlnf("Command failed, output: %s", settingsOut)
			printFatallnf(1, "Command failed, err: %s", err)
		}

		// List keychains
		listKeychainsOut, err := runCommandAndReturnCombinedStdoutAndStderr("security", "list-keychains")
		if err != nil {
			PrintErrorlnf("Command failed, output: %s", listKeychainsOut)
			printFatallnf(1, "Command failed, err: %s", err)
		}

		keychainList := strings.Split(listKeychainsOut, "\n")
		strippedKeychainList := []string{}

		for _, keychain := range keychainList {
			strippedKeychain := strip(keychain)
			strippedKeychainList = append(strippedKeychainList, strippedKeychain)
		}

		strippedKeychainList = addKeyChainToList(strippedKeychainList, keychainPath)

		// Set keychain search path
		args := []string{"-v", "list-keychains", "-s"}
		args = append(args, strippedKeychainList...)

		listKeychainsOut, err = runCommandAndReturnCombinedStdoutAndStderr("security", args...)
		if err != nil {
			PrintErrorlnf("Command failed, output: %s", listKeychainsOut)
			printFatallnf(1, "Command failed, err: %s", err)
		}

		// Set the default keychain
		defaultKeychainOut, err := runCommandAndReturnCombinedStdoutAndStderr("security", "-v", "default-keychain", "-s", keychainPath)
		if err != nil {
			PrintErrorlnf("Command failed, output: %s", defaultKeychainOut)
			printFatallnf(1, "Command failed, err: %s", err)
		}

		// Unlock the specified keychain
		unlockOut, err := runCommandAndReturnCombinedStdoutAndStderr("security", "-v", "unlock-keychain", "-p", keychainPassword, keychainPath)
		if err != nil {
			PrintErrorlnf("Command failed, output: %s", unlockOut)
			printFatallnf(1, "Command failed, err: %s", err)
		}

		for cert, pass := range certificatePassphraseMap {
			certificateIdentity, err := certificateFriendlyName(cert, pass)
			if err != nil {
				PrintErrorlnf("Failed to get cert identity, output: %s", certificateIdentity)
				printFatallnf(1, "Failed to get cert identity, err: %s", err)
			}
			if certificateIdentity == "" {
				printFatallnf(1, "Failed to get cert identity")
			}

			Printlnf("   Installed certificate: %s", certificateIdentity)
		}

		certs, err := availableCertificates(keychainPath)
		if err != nil {
			printFatallnf(1, "Failed to get certificate list, err:%s", err)
		}
		if len(certs) == 0 {
			printFatallnf(1, "Failed to import certificate, no certificates found")
		}

		fmt.Println()
		Printlnf("Available certificates:")
		fmt.Println("-----------------------")
		for _, cert := range certs {
			Printlnf(" * %s", cert)
		}
	} else {
		Printlnf("[!] NO Certificate provided")
	}

	//
	// Install provisioning profiles
	// NOTE: the URL can be a pipe (|) separated list of Provisioning Profile URLs
	fmt.Println()
	Printlnf("Downloading & installing Provisioning Profile(s)")

	split := strings.Split(provisioningProfileURL, "|")
	provisioningProfileURLs := []string{}
	for _, s := range split {
		if s != "" {
			provisioningProfileURLs = append(provisioningProfileURLs, s)
		}
	}

	if defaultProvisioningProfileURL != "" {
		fmt.Println("Default Provisioning Profile given")
		provisioningProfileURLs = append(provisioningProfileURLs, defaultProvisioningProfileURL)
	}

	profileCount := len(provisioningProfileURLs)
	Printlnf("Provided Provisioning Profile count: %d", profileCount)

	for idx, profileURL := range provisioningProfileURLs {
		fmt.Println()
		Printlnf("=> Downloading provisioning profile: %d/%d", idx+1, profileCount)

		provisioningProfileExt := "provisionprofile"
		if !strings.Contains(profileURL, "."+provisioningProfileExt) {
			provisioningProfileExt = "mobileprovision"
		}

		tmpPath := path.Join(tempDir, fmt.Sprintf("profile-%d.%s", idx, provisioningProfileExt))
		if err := downloadFile(tmpPath, profileURL); err != nil {
			printFatallnf(1, "Download failed, err: %s", err)
		}

		fmt.Println()
		fmt.Println("=> Installing provisioning profile")
		out, err := runCommandAndReturnCombinedStdoutAndStderr("/usr/bin/security", "cms", "-D", "-i", tmpPath)
		if err != nil {
			PrintErrorlnf("Command failed, output: %s", out)
			printFatallnf(1, "Command failed, err: %s", err)
		}

		tmpProvProfilePth := path.Join(tempDir, "prov")
		writeBytesToFileWithPermission(tmpProvProfilePth, []byte(out), 0)

		profileUUID, err := runCommandAndReturnCombinedStdoutAndStderr("/usr/libexec/PlistBuddy", "-c", "Print UUID", tmpProvProfilePth)
		if err != nil {
			PrintErrorlnf("Command failed, output: %s", profileUUID)
			printFatallnf(1, "Command failed, err: %s", err)
		}

		Printlnf("   Installed Profile UUID: %s", profileUUID)
		profileFinalPth := path.Join(provisioningProfileDir, profileUUID+"."+provisioningProfileExt)

		Printlnf("   Moving it to: %s", profileFinalPth)

		if out, err := runCommandAndReturnCombinedStdoutAndStderr("cp", tmpPath, profileFinalPth); err != nil {
			PrintErrorlnf("Command failed, output: %s", out)
			printFatallnf(1, "Command failed, err: %s", err)
		}
	}

	if len(provisioningProfileURLs) == 0 {
		fmt.Println()
		Printlnf("[!] NO Provisioning Profile provided")
	}

	fmt.Println()
	fmt.Println("Done")
}
