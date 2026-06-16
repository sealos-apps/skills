#!/usr/bin/env bash
set -euo pipefail

source /root/.sealos/cloud/scripts/tools.sh

APP_NAME="example-app"
VALUES_DIR="/root/.sealos/cloud/values/apps/${APP_NAME}"
DEFAULT_VALUES="./charts/${APP_NAME}/${APP_NAME}-values.yaml"

if [ ! -d "${VALUES_DIR}" ]; then
  echo "WARN: ${VALUES_DIR} missing, copying default values"
  mkdir -p "${VALUES_DIR}"
  cp "${DEFAULT_VALUES}" "${VALUES_DIR}/"
fi

cloudDomain="$(get_cm_value sealos-system sealos-config cloudDomain)"
cloudPort="$(get_cm_value sealos-system sealos-config cloudPort)"
httpPort="$(get_cm_value sealos-system sealos-config httpPort)"
disableHttps="$(global_http_disable_https)"
certSecretName="$(get_cm_value sealos-system sealos-config certSecretName)"
tls_reject_unauthorized="$(read_cert_tls_reject_unauthorized)"

values_args=()
while IFS= read -r values_file; do
  values_args+=("-f" "${values_file}")
done < <(find "${VALUES_DIR}" -name '*-values.yaml' -type f | sort)

helm upgrade -i "${APP_NAME}" ./charts/${APP_NAME} \
  -n example-system \
  --create-namespace \
  "${values_args[@]}" \
  --set-string "cloudDomain=${cloudDomain}" \
  --set-string "cloudPort=${cloudPort}" \
  --set-string "httpPort=${httpPort}" \
  --set-string "disableHttps=${disableHttps}" \
  --set-string "certSecretName=${certSecretName}" \
  --set-string "platform.tlsRejectUnauthorized=${tls_reject_unauthorized}"
