#!/bin/bash

set -e

#
# Init
export provisioning_profile_dir="${HOME}/Library/MobileDevice/Provisioning Profiles"
export temp_dir="${HOME}/tmp_dir"
export keychain_name="bitrise.keychain"

#
# Required parameters
if [ -z "${certificate_url}" ] ; then
  echo "Missing required input: certificate_url"
  exit 1
fi

if [ -z "${keychain_name}" ] ; then
  echo "Missing required input: keychain_name"
  exit 1
fi

if [ -z "${certificate_passphrase}" ] ; then
  echo "Missing required input: certificate_passphrase"
  exit 1
fi

if [ -z "${provisioning_profile_url}" ] ; then
  echo "Missing required input: provisioning_profile_url"
  exit 1
fi

if [ -z "${provisioning_profile_dir}" ] ; then
  echo "Missing required input: provisioning_profile_dir"
  exit 1
else
  mkdir -p "${provisioning_profile_dir}"
fi

if [ -z "${temp_dir}" ] ; then
  echo "Missing required input: temp_dir"
  exit 1
else
  mkdir -p "${temp_dir}"
fi

#
# Download certificate and profile
function download_file {
  local path="$1"
  local url="$2"

  curl -Lfso "${path}" "${url}"
  result=$?
  
  if [ ${result} -ne 0 ]; then
    echo " (i) Failed to download, retrying..."
    sleep 5
    curl -Lfso "${path}" "${url}"
  fi

  if [[ ! -f "${path}" ]]; then
    echo "Failed to download file: #{url}"
    exit 1
  fi
}

echo "Downloading certificate"
export CERTIFICATE_PATH="${temp_dir}/Certificate.p12"
download_file "${CERTIFICATE_PATH}" "${certificate_url}"

#
# Install certificate
echo "Creating keychain"
export KEYCHAIN_PASSPHRASE="$(cat /dev/urandom | LC_ALL=C tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1)"

# Todo: check if exists
security -v create-keychain -p "${KEYCHAIN_PASSPHRASE}" "${keychain_name}"
security -v import "${CERTIFICATE_PATH}" -k "${keychain_name}" -P "${certificate_passphrase}" -A
security -v set-keychain-settings -lut 72000 "${keychain_name}"
security -v list-keychains -s $(security -v list-keychains | tr -d '"') "${keychain_name}"
security -v default-keychain -s "${keychain_name}"
security -v unlock-keychain -p "${KEYCHAIN_PASSPHRASE}" "${keychain_name}"

export CERTIFICATE_IDENTITY=$(security find-certificate -a ${keychain_name} | grep -Ei '"labl"<blob>=".*"' | grep -oEi '=".*"' | grep -oEi '[^="]+' | head -n 1)
echo "Installed certificate: $CERTIFICATE_IDENTITY"
echo

#
# Install provisioning profile
IFS='|' read -a profile_urls <<< "${provisioning_profile_url}"

profile_count="${#profile_urls[@]}"
for idx in "${!profile_urls[@]}"
do
  profile_url="${profile_urls[idx]}"
  echo "Downloading provisioning profile: ${idx+1}/${profile_count}"

  tmp_path="${temp_dir}/profile-${idx}.mobileprovision"
  download_file "${tmp_path}" "${profile_url}"

  echo "Installing provisioning profile"
  profile_uuid=$(/usr/libexec/PlistBuddy -c "Print UUID" /dev/stdin <<< $(/usr/bin/security cms -D -i "${tmp_path}"))
  echo "Profile UUID: ${profile_uuid}"
  mv "${tmp_path}" "${provisioning_profile_dir}/${profile_uuid}.mobileprovision"
done