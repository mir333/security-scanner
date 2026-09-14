# Running the stack under a dedicated Linux user

By default the scanner containers run as root and write **root-owned** files into
`reports/`, and talking to a normal Docker daemon needs `docker`-group membership
(which is effectively root on the host). To run everything as one confined,
non-privileged account instead, use a dedicated service user with **rootless
Docker**.

Why rootless Docker:

* the daemon runs *as the service user* — no root daemon, and no `docker` group
  (which would be root-equivalent and defeat the purpose);
* container "root" maps to the unprivileged user via user namespaces, so a
  container breakout can't become host root;
* files written into bind mounts (`reports/`) come out owned by the service user
  — the root-owned-`semgrep.json` annoyance goes away.

Port `8080` is unprivileged, so DefectDojo works under rootless with no extra setup.

---

## 1. Create the service account (both distros)

A real shell is needed so `sudo -iu` and the rootless setup tool get a proper
user session; lock the password so it can't be logged into directly.

```bash
sudo useradd --create-home --shell /bin/bash devsecops
sudo passwd --lock devsecops          # no direct login; switch in with sudo
sudo loginctl enable-linger devsecops # user services run without an active login
```

## 2. Install rootless Docker

### Arch Linux

```bash
sudo pacman -S --needed docker docker-compose docker-rootless-extras
```

### Ubuntu (24.04 / 22.04)

Use Docker's official apt repository (the distro `docker.io` package lacks the
rootless extras):

```bash
# prerequisites for rootless + systemd --user
sudo apt-get update
sudo apt-get install -y uidmap dbus-user-session ca-certificates curl

# Docker's official repo
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] \
https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo $VERSION_CODENAME) stable" \
  | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io \
  docker-buildx-plugin docker-compose-plugin docker-ce-rootless-extras

# the system-wide daemon isn't needed; the per-user one replaces it
sudo systemctl disable --now docker.service docker.socket 2>/dev/null || true
```

## 3. Set up the per-user daemon (both distros)

```bash
sudo -iu devsecops bash -lc '
  export XDG_RUNTIME_DIR=/run/user/$(id -u)
  dockerd-rootless-setuptool.sh install
  systemctl --user enable --now docker
'
```

Make `docker` talk to the rootless socket automatically for that user:

```bash
sudo -iu devsecops bash -lc '
  echo "export XDG_RUNTIME_DIR=/run/user/\$(id -u)" >> ~/.bashrc
  echo "export DOCKER_HOST=unix:///run/user/\$(id -u)/docker.sock" >> ~/.bashrc
'
```

## 4. Give the user the repo and lock down secrets

```bash
sudo install -d -o devsecops -g devsecops /srv/devsecops
sudo cp -a /path/to/devsecops-stack /srv/devsecops/
sudo chown -R devsecops:devsecops /srv/devsecops/devsecops-stack
sudo chmod 600 /srv/devsecops/devsecops-stack/.env   # tokens + passwords live here
```

## 5. Run it as the service user

```bash
sudo -iu devsecops bash -lc '
  cd /srv/devsecops/devsecops-stack
  docker compose up -d
  DD_PRODUCT_NAME=ProventeqCloud docker compose --profile scan run --rm import-trivy
'
```

Reports now land in `reports/` owned by `devsecops`, no `sudo` needed to clean them.

---

## Optional: scheduled scans via the user's own systemd (no root cron)

Because lingering is enabled, the service user can run scans on a timer:

```ini
# ~devsecops/.config/systemd/user/scan.service
[Unit]
Description=DevSecOps scan run

[Service]
Type=oneshot
WorkingDirectory=/srv/devsecops/devsecops-stack
Environment=DD_PRODUCT_NAME=ProventeqCloud
ExecStart=/usr/bin/docker compose --profile scan run --rm import-semgrep
ExecStart=/usr/bin/docker compose --profile scan run --rm import-trivy
```

```ini
# ~devsecops/.config/systemd/user/scan.timer
[Unit]
Description=Daily DevSecOps scan

[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
```

```bash
sudo -iu devsecops bash -lc 'systemctl --user daemon-reload && systemctl --user enable --now scan.timer'
```

---

## Alternative: normal (rootful) Docker + `docker` group

Simpler, but adding the user to the `docker` group grants **root-equivalent**
access to the host — only do this on a trusted machine.

```bash
sudo usermod -aG docker devsecops   # root-equivalent; understand the risk
```

To stop the scanners writing root-owned files in this mode, pin the
scanner/exporter services to your UID/GID in `compose.yaml`:

```yaml
  semgrep:
    user: "${HOST_UID:-1000}:${HOST_GID:-1000}"
  trivy:
    user: "${HOST_UID:-1000}:${HOST_GID:-1000}"
  sonarqube:
    user: "${HOST_UID:-1000}:${HOST_GID:-1000}"
```

and run with `HOST_UID=$(id -u) HOST_GID=$(id -g) docker compose ...`.

> **Do not add `user:` to the `zap`, `zap-full` or `zap-api` services.** ZAP's
> packaged scripts must run as the image's built-in `zap` user (uid 1000);
> forcing another uid makes them fail with
> `PermissionError: /home/zap/zap.yaml`. Leave the DefectDojo core
> (postgres/uwsgi/nginx) and the ZAP services as-is — those images start as root
> (or their own user) and drop privileges themselves.

Because ZAP then writes reports as uid 1000 while `semgrep`/`trivy`/`sonarqube`
write as your uid, make the shared output dir writable by both, and clear any
stale ZAP report owned by another uid so it can be recreated:

```bash
chmod 777 reports          # scratch output dir shared across uids (1777 for sticky bit)
rm -f reports/zap-*.xml     # only if a previous run left one owned by another user
```
