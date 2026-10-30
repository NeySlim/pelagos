# Web certificates

**Administration, Certificates** manages the HTTPS certificate of each
node's web interface (`:8443`): where it comes from, the checks before it is
installed, its renewal, and one setting applied to every node at once. It
needs the `admin:certificates` permission (the `admin` role has it).

The replication certificates (internal CA and node certificates on `:8444`)
stay separate: their expiry raises alerts on this screen's behalf, they are
never replaced here. The certificates of the Kea HA listeners are listed
here too and renewed by a plan ([Kea HA certificates](#kea-ha-certificates)).

- [The screen](#the-screen)
- [Sources](#sources)
- [Manual certificate](#manual-certificate)
- [ACME](#acme)
- [UCM through its API](#ucm-through-its-api)
- [All nodes at once](#all-nodes-at-once)
- [Install, hot reload, rollback](#install-hot-reload-rollback)
- [Renewal and alerts](#renewal-and-alerts)
- [Kea HA certificates](#kea-ha-certificates)
- [Settings](#settings)
- [Audit and secrets](#audit-and-secrets)
- [Troubleshooting](#troubleshooting)

## The screen

One card per node: issuer, names (SAN), expiry with the days left
(green, then warning and critical by the alert thresholds), key type,
fingerprint, the source, the last issuance, the next renewal and, after a
failed automatic request, the number of failures, the next try and the
error. **Log** shows the last 50 events of the node (requests, challenges,
installs, errors). A node that does not answer shows the certificate its web
listener presents, read by a TLS handshake.

Actions per node: **Source** (choose where the certificate comes from),
**Upload** (manual certificate, or a request made on the node), **Renew now**
(automatic sources), **New self-signed**. The **All nodes** card holds the
source applied to several nodes; **Apply to all nodes** sets it.

## Sources

| Source | Key | Renewal |
| --- | --- | --- |
| Self-signed (default) | made on the node | none: the install creates one valid 10 years, **New self-signed** replaces it |
| Manual | made on the node (request) or given with the certificate | none: the expiry alert reminds you |
| ACME | made on the node at each issuance | automatic, when a third of the lifetime is left |
| [Ultimate CA Manager (UCM)](https://github.com/NeySlim/ultimate-ca-manager) | made on the node at each issuance | automatic, `ucm_renew_days` (30) before the end |

Common options of ACME and UCM: **Added names** (beside the node name and
the host of its web URL), **Key type** (ECDSA P-256 or RSA 3072), and **One
name for the cluster** when a load balancer fronts the nodes: every
certificate then carries the cluster name instead of the node's own names.
ACME certifies only DNS names with a dot: a short node name or an IP address
is left out.

## Manual certificate

**Upload** offers three ways:

1. **Signed certificate for the request made on the node.** Choose the key
   type (ECDSA P-256 or RSA 3072) and the added names, then **Make the key and
   request**. The node keeps the key (`/var/lib/pelagos/webcert/pending.key`,
   0600); copy or download the CSR, have it signed by any CA, paste the
   certificate and its chain. The key never left the node.
2. **Certificate, chain and key (PEM)**, pasted or picked as files. The
   chain may be in any order; it is installed in order.
3. **PKCS#12 file** (`.p12`, `.pfx`) with its password.

**Check** runs the checks without installing:

| Check | Error when | Warning when |
| --- | --- | --- |
| Key | no key, or the key does not match the certificate | |
| Dates | not valid yet, or expired | expires within a week |
| Names | the host of the node's web URL is not covered | another wanted name is not covered |
| Usage | no `serverAuth` in the extended key usage, or a CA certificate | |
| Chain | no issuer given for a certificate that is not self-signed, and no trust root closes it | only the root is missing above a given CA certificate (private CA), given out of order, extra certificates left out |
| Trust | | self-signed, or the issuer is not in the system's CA store |

**Install** is offered once no check is in error. **Install on other nodes
too** sends the same certificate and key to the nodes ticked, when the
certificate covers their names: the key goes encrypted in `cluster.toml`
(replicated), each node installs it through its own pipeline within a minute
and removes it from `cluster.toml`. A key made on the node never travels.

## ACME

**ACME server**:

- **Let's Encrypt** and **Let's Encrypt staging** (use staging to try:
  its certificates are not trusted, its limits are generous). The client is
  tested on every change against Pebble, Let's Encrypt's own test server
  (DNS-01 on a zone of a real named, 90 day certificates renewed with a
  third left, nonces rejected at random as Let's Encrypt may; also run once on
  arm64 under qemu with Debian 13 and BIND 9.20.30);
- **Private ACME (step-ca, UCM)**: the directory URL (for example
  `https://ca.example.lan/acme/acme/directory`) and the **trust root** used
  to reach the server (PEM, added to the system store);
- **Other ACME URL**: any RFC 8555 server.

**EAB key id** and **EAB HMAC key** when the server requires external account
binding. **Contact email** is optional. **Test the ACME server** reads the
directory and says whether EAB is required. The ACME account key is made
once per directory URL and shared by the nodes (encrypted in
`cluster.toml`).

### DNS-01 (preferred)

The node puts a TXT record `_acme-challenge.<name>`, waits until **every
authoritative server** of the zone answers it (up to
`propagation_seconds`), tells the ACME server, and removes the record
afterwards, also when the validation failed.

**TXT records put by Pelagos** (a zone the cluster serves): the node sends a
signed UPDATE with the TSIG key `ddi-acme` to the zone's primary (empty
**DNS server** field: this node's BIND; otherwise `host[:port]` of the
primary). **Prepare the DNS-01 setup** builds a plan that creates the key
and adds to each zone Pelagos manages on this node a grant limited to the
challenge records:

```
update-policy { grant ddi-admin zonesub ANY; grant ddi-acme name _acme-challenge.ns1.example.lan. TXT; };
```

Zones of your own `named.conf` files are listed with the statement to add
by hand, and so is a zone that has an `allow-update` and no `update-policy`:
BIND does not take both, so convert its `allow-update` to an `update-policy`
first, or use a CNAME delegation or a DNS provider. Run the plan on the node
that holds the zones as primary.

**Let's Encrypt needs a public zone.** When your public domain lives at
another DNS host, either

- delegate the challenges to a zone Pelagos serves: set the **Delegation
  zone** (for example `acme.example.lan`), create at the public DNS host the
  CNAME records the setup shows
  (`_acme-challenge.ns1.example.lan. CNAME ns1-example-lan.acme.example.lan.`),
  and the setup grants `ddi-acme` the whole delegation zone; or
- let the node use the **DNS provider API**: Hetzner DNS, through the
  Hetzner Cloud API (`https://api.hetzner.cloud/v1`), the DNS API
  that replaces the legacy DNS Console API (`dns.hetzner.com`); it has been generally
  available since 2025-11-10, after which no zone can be created in the legacy console
  (docs.hetzner.cloud/changelog, checked 2026-10-26).
  Create the API token (read and write) in the Hetzner Console project that
  holds the zone. The node finds the zone by name, adds the TXT record with
  the `add_records` action of the RRSet, follows the action until it
  succeeds and removes the record with `remove_records`. **Test** lists the
  zones the token sees. Providers are modules of `core/webcert/dns01.py`:
  others can be added the same way.

### HTTP-01

The node opens a listener on **HTTP-01 listening port** (default 8080) for
the time of the validation and answers only
`/.well-known/acme-challenge/<token>`. ACME servers connect to port 80,
which the service cannot bind (it runs without privileges) and which is
often taken: forward port 80 to this port, or route
`/.well-known/acme-challenge/` to it from the web server that holds port 80.

## UCM through its API

UCM signs a request made on the node; the key never leaves it.

1. In UCM, create an API key (Account, API keys) with the permissions
   `read:cas`, `read:templates`, `read:csrs`, `write:csrs`,
   `read:certificates` and `write:certificates` (the last one signs and
   revokes); nothing more is needed.
2. Set **UCM URL**, **API key** and the **trust root**: the root of the CA
   that signs. UCM's export leaves a self-signed root out of the chain, so
   the node needs it to check the chain, and it also serves to reach UCM
   when UCM's own HTTPS certificate comes from that CA. UCM's first HTTPS
   certificate names an IP address as a DNS name, which no client accepts:
   give UCM a certificate for its name (or an IP SAN) before using its
   address.
3. **Test the connection** lists the CAs and templates: choose the
   **Signing CA**, a **Template** if any, and the **Validity** (365 days by
   default).
4. **Revoke the previous certificate** revokes the old certificate (reason
   superseded) once the new one is installed.

The calls are `POST /api/v2/csrs/upload`, `POST /api/v2/csrs/<id>/sign`,
`GET /api/v2/certificates/<id>/export?format=pem&include_chain=true` and
`POST /api/v2/certificates/<id>/revoke`, with the key in `X-API-Key`. A
signing policy that requires approval in UCM fails the request with that
message: approve it in UCM, then **Renew now**. A revocation queued for
approval is logged as not done.

UCM also serves ACME: the **Private ACME** profile works with it too
(directory `https://<ucm>:8443/acme/directory`, no EAB by default). For
DNS-01 on a zone Pelagos serves, UCM must reach that zone's servers: in UCM,
ACME settings, set the DNS-01 resolver mode to custom with those servers.

Both were run against UCM 2.245 built from its repository, on a two node
cluster: one year certificates on every node, forced renewal, the previous
certificates revoked, the renewal due 30 days before the end, then the
Private ACME profile with DNS-01 (lab tier, `tests/lab/test_ucm_lab.py`).

## All nodes at once

**Apply to all nodes** sets one ACME or UCM source for every node, or for
the nodes ticked. It is replicated in `cluster.toml`; each node makes its
own key and requests its own certificate for its own names (node name, web
URL host, added names), and no private key travels. **Save and request on
every node** runs a job with one line per node: a node that fails keeps its
current certificate and does not stop the others; the job ends failed and
names the nodes that failed. Each node starts its request once it has
received the new setting; a node that has not within 30 seconds fails with
"source not replicated yet" and requests on its own at its next pass. The selected nodes show the source as
"(cluster)"; a node can still get a source of its own (**Source**), or come
back to the cluster's with **Cluster setting**. With **Every node**, a node
enrolled later follows the setting and requests its certificate within a
minute of joining. Renewal stays per node, each on its own schedule.
**Remove** drops the common setting: the nodes keep their certificate and
stop renewing it until they get a source of their own.

## Install, hot reload, rollback

Every install goes through the write pipeline: backup of the current files
(`/var/lib/pelagos/backups/webtls/`), key written 0600 and chain 0644,
validation that the pair loads, hot reload, then a TLS handshake with the
node's own web listener that must present the new fingerprint within 15
seconds. If it does not, the previous files come back.

The web process reloads its TLS context without a restart: new connections
get the new certificate, connections already open (WebSocket included) keep
the old one, and sessions stay signed in. A request still being received
when the certificate changes completes normally (daemon tier,
`test_renewal_hot_reload_keeps_inflight_request_and_websocket`: a renewal
run by the web process while a login body trickles in and a WebSocket is
open). A certificate written by hand in
`/etc/pelagos/tls/` is picked up the same way within a second: no
`systemctl restart` is needed.

## Renewal and alerts

The collector looks at the web certificate every minute. An automatic
source requests a new certificate when:

- the source or the names changed (a new web URL, a name added);
- a third of the lifetime is left (ACME: 30 days of a 90-day Let's Encrypt
  certificate, 8 hours of a 24-hour step-ca one) or `ucm_renew_days` before
  the end (UCM);
- the certificate was replaced outside the source.

A failed request is retried after `retry_min_seconds` (300), doubling up to
`retry_max_seconds` (6 hours), and raises `cert_renewal_failed` until a
request succeeds. Saving the source again starts over without waiting.

**Upload** or **New self-signed** on a node with an automatic source switches
the node to manual or self-signed (its names and key type are kept, its own
ACME or UCM credentials removed); the certificate installed is never
replaced by a renewal of the previous source.

`cert_expiry` watches three certificates of each node: the web certificate
(`cert:web`), the node's replication certificate (`cert:node`) and the
internal CA (`cert:ca`). Warning at `checks.cert_warning_days` (30) left,
critical at `checks.cert_critical_days` (7); for a short-lived certificate,
at a third and a tenth of its lifetime when that is shorter, so a 24-hour
certificate renewed on time never alerts. The alert names the source of the
web certificate (manual: renew by hand).

## Kea HA certificates

The card **Kea HA certificates** lists, per node, the certificates its Kea
configuration names for HA TLS (`cert-file` and `trust-anchor` of each
relationship, or of a peer when set there), read from the files: issuer,
names (SAN), expiry with the days left, and whether the issuer is the
cluster CA ("cluster CA", "other CA"). "TLS incomplete" marks a relationship
with only some of the three files. Certificates issued by hand with the
cluster CA key (as before Pelagos did it) are listed and renewed like the
ones Pelagos issued.

`cert_expiry` watches them with the same thresholds as the other
certificates (subject `cert:kea_ha:<path>`); a trust anchor other than the
cluster CA is watched as well, the cluster CA itself by its own `cert:ca`
alert.

**Plan the renewal (every peer)** builds one plan for the whole HA set
(`POST /install/security/ha-tls/plan`): new certificates from the cluster CA
at the same paths on every node, then one `config-reload` per node (Kea
reloads the files its hooks name on every reload), each node checked with
`status-get` before the next. The HA stays up: no restart, no switch back
to clear HTTP. Certificates from another CA are renewed by hand, or
replaced by the cluster CA's through the same plan. How the HA listener is
switched to TLS in the first place:
[DHCP: securing the HA listener](dhcp.md#securing-the-ha-listener).

## Settings

In **Administration, Settings** (`cluster.toml [settings]`):

| Key | Default | Effect |
| --- | --- | --- |
| `checks.cert_warning_days` | `30` | `cert_expiry` warning |
| `checks.cert_critical_days` | `7` | `cert_expiry` critical |
| `certificates.ucm_renew_days` | `30` | UCM renewal before the end |
| `certificates.retry_min_seconds` | `300` | first retry after a failed automatic request |
| `certificates.retry_max_seconds` | `21600` | longest delay between retries |
| `certificates.propagation_seconds` | `180` | DNS-01: how long to wait for the TXT on every authoritative server |

The sources themselves are set on this screen only
(`[settings.certificates.cluster]` and `[settings.certificates.nodes.<id>]`).

## Audit and secrets

Every issuance, renewal, upload, transfer and failure is in the audit log
(`admin.cert.apply`, `admin.cert.replace`, `admin.cert.add`,
`admin.cert.delete`) with the names, issuer, expiry and fingerprint, never
a key. The EAB key, the DNS provider token, the UCM API key, the ACME
account key and the `ddi-acme` TSIG secret are stored encrypted with the
master key in `cluster.toml [secrets]`, like the other secrets; the API and
the screen only say whether each one is set.

## Troubleshooting

- **`TXT _acme-challenge... not visible on ...`**: a secondary did not get
  the change (check `also-notify` and transfers), or a public authoritative
  server is not the one you think. Raise `propagation_seconds` for slow
  providers.
- **`UPDATE ... refused: REFUSED (check the update-policy grant for key
  ddi-acme)`**: run **Prepare the DNS-01 setup** again, or add the grant to
  your own zone statement.
- **HTTP-01 `connection refused` from the ACME server**: port 80 does not
  reach the listening port; see [HTTP-01](#http-01).
- **`install rolled back: ...`**: the web listener did not present the new
  certificate; the previous one is back. Check the web process log
  (`journalctl -u pelagos`).
- **`UCM queued the request for approval`**: approve it in UCM, then
  **Renew now**.
- **Let's Encrypt `rateLimited`**: use the staging profile while trying;
  failed requests back off on their own.
