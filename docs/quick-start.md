# Quick Start

Deploy the SECentral server from Quay, install an agent from COPR, and investigate
a real SELinux denial. No application build or Go/Ruby installation is needed.

## Prerequisites

- A Linux amd64 server with Podman, `podman-compose`, curl and OpenSSL. Start with
  2 vCPU, 2 GB RAM and 10 GB free disk for a small evaluation.
- A public DNS name pointing to the server, with inbound TCP ports 80 and 443
  available for Caddy's automatic Let's Encrypt HTTPS.
- An agent host with SELinux, systemd, auditd and outbound HTTPS access to the
  server. RPMs are available for COPR-supported Fedora and RHEL-family systems.
  Use a disposable host without an existing web workload for the denial exercise.

Run the commands in a root Bash shell (`sudo -i`) on the indicated host. Use the
same root account for all server Podman commands. On AlmaLinux 9, install the
server tooling with:

```sh
dnf install -y epel-release
dnf install -y podman podman-compose curl openssl
```

## 1. Prepare the server

On the **server host**, download the deployment files for version `0.0.10`:

```sh
umask 077
install -d -m 0700 /opt/secentral
cd /opt/secentral
curl -fLO https://raw.githubusercontent.com/SECentral/server/v0.0.10/compose.yaml
curl -fLO https://raw.githubusercontent.com/SECentral/server/v0.0.10/Caddyfile
curl -fLO https://raw.githubusercontent.com/SECentral/server/v0.0.10/.env.example
cp .env.example .env
```

Edit `.env`:

- Set `DOMAIN` to your hostname, without `https://` or a path.
- Set `SECRET_KEY_BASE`, `SECENTRAL_SERVER_DATABASE_PASSWORD`, and
  `SECENTRAL_INGESTION_KEY` to different random values. Run `openssl rand -hex 32`
  separately for each value.
- Choose `ADMIN_USERNAME` and generate a password digest using the server image:

```sh
read -rsp 'Operator password: ' ADMIN_PASSWORD; printf '\n'
printf '%s' "$ADMIN_PASSWORD" | podman run --rm -i --entrypoint bundle \
  quay.io/secentral/server:0.0.10 exec ruby -rbcrypt \
  -e 'puts BCrypt::Password.create(STDIN.read)'
unset ADMIN_PASSWORD
```

Put the printed digest in `.env` as `ADMIN_PASSWORD_DIGEST`, enclosed in single
quotes so Compose preserves its `$` characters. For example:

```dotenv
ADMIN_USERNAME=admin
ADMIN_PASSWORD_DIGEST='$2a$12$replace-with-the-complete-generated-digest'
```

Keep `.env` private. Operator credentials are for the web UI; agents use the
separate shared ingestion key.

## 2. Start the server

Allow HTTP and HTTPS in the host and cloud firewalls. If firewalld is running:

```sh
firewall-cmd --permanent --add-service=http
firewall-cmd --permanent --add-service=https
firewall-cmd --reload
```

Then, from `/opt/secentral`:

```sh
podman-compose up -d
podman-compose ps
curl --fail --show-error https://YOUR_HOSTNAME/up
```

Replace `YOUR_HOSTNAME` with your DNS name. Allow a little time for first startup
and certificate issuance. Caddy obtains and renews the certificate; Rails prepares
the database and initial organization automatically. PostgreSQL is not exposed
to the host.

Open `https://YOUR_HOSTNAME` and sign in with your operator username and password.
Hosts and Issues should initially be empty. On AlmaLinux 9, enable container
restart recovery after a host reboot:

```sh
systemctl enable podman-restart.service
```

## 3. Install and configure an agent

On the **agent host**, install the RPM and the SELinux inspection tools:

```sh
dnf install -y dnf-plugins-core audit initscripts-service \
  policycoreutils-python-utils setools-console
dnf copr enable -y mikelo2/secentral-agent
dnf install -y secentral-agent
```

The RPM installs the systemd service, state directory and
`/etc/secentral/agent.env`. Edit that file, replacing the example hostname and
key with your server's hostname and `SECENTRAL_INGESTION_KEY` value:

```dotenv
SECENTRAL_ENDPOINT=https://YOUR_HOSTNAME/api/v1/events
SECENTRAL_INGESTION_KEY=YOUR_SERVER_INGESTION_KEY
```

Then start collection:

```sh
chmod 0600 /etc/secentral/agent.env
service auditd start
systemctl enable --now secentral-agent
systemctl is-active secentral-agent
```

Open **Hosts** in SECentral. The agent sends a startup heartbeat and normally
reports every five minutes. Your host should appear with its SELinux mode and
agent version. A recent heartbeat establishes reporting, not complete audit
capture. If you later edit `agent.env`, restart the agent to apply the changes.

## 4. Generate a test denial

On the disposable **agent host**, install and start Apache:

```sh
dnf install -y httpd
systemctl enable --now httpd
getenforce
```

Keep the host's SELinux mode unchanged. Create a file labeled `user_home_t` and
copy it into the web root without changing its label:

```sh
TEST_FILE=$(mktemp /home/secentral-test-XXXXXX.txt)
printf 'SECentral test file\n' > "$TEST_FILE"
chmod 0644 "$TEST_FILE"
chcon -t user_home_t "$TEST_FILE"
cp --preserve=context "$TEST_FILE" /var/www/html/
ls -lZ "/var/www/html/$(basename "$TEST_FILE")"
curl -i "http://localhost/$(basename "$TEST_FILE")"
```

In Enforcing mode, expect HTTP **403**. In Permissive mode, expect **200** with
AVCs recording what would have been blocked. Confirm the local audit record:

```sh
ausearch -if /var/log/audit/audit.log -m AVC -ts recent -i
```

In SECentral, open **Issues**, select the new issue, and inspect the affected
host, occurrence and raw evidence. Look for source `httpd_t`, target
`user_home_t`, and denied file access. The SELinux log also exposes individual
events. Events normally arrive within a few seconds.

Clean up the test in the same shell. Restore the expected label and repeat the
request; it should now return **200** in Enforcing mode too:

```sh
restorecon -v "/var/www/html/$(basename "$TEST_FILE")"
curl -i "http://localhost/$(basename "$TEST_FILE")"
rm -- "/var/www/html/$(basename "$TEST_FILE")" "$TEST_FILE"
systemctl disable --now httpd
```

Catalogs are optional for this first investigation. To add a reviewed reference,
follow [Managing catalogs](catalog-lifecycle.md) and the
[catalog source contract](../catalogs/README.md). Startup and upgrades do not
automatically import catalogs.

## Upgrades and shutdown

On the server, from `/opt/secentral`, back up the database before upgrading:

```sh
umask 077
podman-compose exec -T db pg_dump -U secentral_server secentral_server_production \
  > "secentral-$(date -u +%Y%m%dT%H%M%SZ).sql"
```

Change the server image tag in `compose.yaml` to the desired published version,
then run:

```sh
podman-compose pull server
podman-compose up -d
podman-compose ps
```

Confirm the version in the UI and that previous hosts and issues remain.
`restart` alone does not switch images. Database migrations run automatically;
reverting the image does not undo migrations.

`podman-compose down` stops the deployment and preserves named database and Caddy
volumes. `podman-compose down -v` deletes those volumes and their data. Before
permanently removing an evaluation, stop its agent with
`systemctl disable --now secentral-agent` on the agent host. The RPM preserves
edited configuration during upgrades; `dnf upgrade secentral-agent` upgrades it.

## Troubleshooting

- **Startup or HTTPS:** inspect `podman-compose logs --tail=50 server caddy db`.
  Check DNS and firewall access to 80/443. `/up` checks server health; open the UI
  as well to confirm the application renders.
- **Host missing:** inspect `journalctl -u secentral-agent -n 50 --no-pager`.
  Check the endpoint path, ingestion key, certificate trust and auditd. Diagnose
  missing service paths or permissions from the journal rather than disabling
  the unit's hardening.
- **No denial:** check `getenforce`, the file's label, the local audit log and
  agent journal. Neither a heartbeat nor an empty issue list proves complete
  capture. Preserve pending spool files under `/var/lib/secentral/spool`.
- **Small host stalls during updates:** provide adequate RAM or swap; the
  512 MB evaluation agent needed swap to complete a full OS update.

Keep secrets and sensitive host evidence out of shared logs and bug reports.
