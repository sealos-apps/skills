#!/usr/bin/env bash
set -euo pipefail

APP_NAME="example-app"
VALUES_DIR="/root/.sealos/cloud/values/apps/${APP_NAME}"
if [ ! -d "${VALUES_DIR}" ]; then
  echo "WARN: ${VALUES_DIR} missing, copying default values"
  mkdir -p "${VALUES_DIR}"
  cp "./charts/${APP_NAME}/${APP_NAME}-values.yaml" "${VALUES_DIR}/"
fi
values_args=()
while IFS= read -r values_file; do
  values_args+=("-f" "${values_file}")
done < <(find "${VALUES_DIR}" -name '*-values.yaml' -type f | sort)
helm upgrade -i "${APP_NAME}" ./charts/${APP_NAME} -n example-system --create-namespace "${values_args[@]}" --set-string "cloudDomain=example.test" --set-string "cloudPort=443" --set-string "httpPort=80" --set-string "disableHttps=false" --set-string "certSecretName=example-cert"

