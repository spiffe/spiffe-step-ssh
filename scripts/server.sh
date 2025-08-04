#!/bin/bash -e

cd "/var/run/spiffe/step-ssh-server/$INSTANCE"
mkdir -p "/var/run/spiffe/step-ssh-fetchca/$INSTANCE/fetchca"
chown 755 "/var/run/spiffe/step-ssh-fetchca/$INSTANCE/fetchca"

if [ -f "/etc/spiffe/step-ssh-server/${INSTANCE}/ssh_x5c.tpl" ]; then
  cp -af "/etc/spiffe/step-ssh-server/${INSTANCE}/ssh_x5c.tpl" .
else
  cp -af "/usr/libexec/spiffe/step-ssh-server/ssh_x5c.tpl" .
fi

PREFIX=sshd

sed -i "s/@TRUST_DOMAIN@/${SPIFFE_TRUST_DOMAIN}/g; s/@PREFIX@/${PREFIX}/g" ssh_x5c.tpl

export ROOTS=$(base64 ca.crt | tr '\n' ' ' | sed 's/ //g')

echo Updating Roots to "$ROOTS"

VALUES=/etc/spiffe/step-ssh-server/$INSTANCE/values.yaml

yq e '.inject.certificates.intermediate_ca' "$VALUES" > intermediate_ca.crt
yq e '.inject.certificates.root_ca' "$VALUES" > root_ca.crt
yq e '.inject.certificates.root_ca' "$VALUES" > "/var/run/spiffe/step-ssh-fetchca/$INSTANCE/fetchca/root_ca.crt"
yq e '.inject.certificates.ssh_host_ca' "$VALUES" > ssh_host_ca
yq e '.inject.certificates.ssh_user_ca' "$VALUES" > ssh_user_ca
yq e '.inject.secrets.x509.intermediate_ca_key' "$VALUES" > intermediate_ca_key
yq e '.inject.secrets.x509.root_ca_key' "$VALUES" > root_ca_key
yq e '.inject.secrets.ssh.host_ca_key' "$VALUES" > ssh_host_ca_key
yq e '.inject.secrets.ssh.user_ca_key' "$VALUES" > ssh_user_ca_key
yq e '.inject.config.files."ca.json" | .root="root_ca.crt" | .crt="intermediate_ca.crt" | .key="intermediate_ca_key" | .ssh.hostKey="ssh_host_ca_key" | .ssh.userKey="ssh_user_ca_key" | .db.dataSource="db" | .authority.provisioners=[{"type": "X5C", "name": "x5c@spiffe", "roots": "", "claims": {"maxTLSCertDuration": "24h", "defaultTLSCertDuration": "1h", "disableRenewal": true, "enableSSHCA": true, "disableCustomSANs": true}, "options": {"ssh": {"templateFile": "./ssh_x5c.tpl"}}}]' "$VALUES" -o json > ca.json
yq e -i -ojson '.authority.provisioners |= map(select(.name == "x5c@spiffe").roots = env(ROOTS))' ca.json

exec step-ca ca.json --password-file "/etc/spiffe/step-ssh-server/${INSTANCE}/password.txt"
