# Migrating from mkconfig.sh

A one-time cutover on `orion`. Two independent halves:

1. **Firewall** — move forwarding and NAT from `wg0.conf`'s `PostUp` rules to
   ufw. Touches the live server.
2. **Registry** — import the existing peer directories into `peers.json`.
   Read-only until you pass `--write`.

Do the firewall first: it must be correct *before* peers get globally routable
IPv6 addresses. Neither half can lock you out of SSH — everything here is the
`FORWARD` chain, your session is `INPUT`.

## Why

`mkconfig.sh` combined two things that made no file authoritative:

- **`SaveConfig = true`** made `wg-quick down` regenerate `wg0.conf` from live
  kernel state. Peer sections come from `wg showconf`, which emits no
  comments, so there was nowhere to durably record which peer belonged to
  whom, and any hand edit was discarded at the next stop.
- **`wg addconf`** wrote only to the running interface. A new peer was
  persisted solely as a side effect of a *clean* `wg-quick down`. Power loss,
  a killed unit, or an OOM kill lost every peer added since the last clean
  stop.

Together that also explains why there was no way to remove a peer: there was
no list to remove one from.

The firewall rules had two separate problems:

- `iptables -A FORWARD …` in `PostUp` **appends** to a chain that ufw rebuilds
  on `ufw reload`, `ufw enable/disable`, or a package upgrade. Those rules
  disappear while `wg0` stays up and keeps handshaking — VPN connected,
  healthy handshakes, zero traffic passing, and no obvious cause.
- `iptables -A FORWARD -o wg0 -j ACCEPT` accepts anything forwarded *toward*
  the clients, from any source. With NAT'd IPv4 that is inert, because nobody
  can route to `10.8.0.0/24`. A **routed** IPv6 prefix removes that accident
  of protection and would expose every client directly to the internet.

`DEFAULT_FORWARD_POLICY="DROP"` never conflicted with any of this: it sets the
chain *policy*, the last-resort verdict after all rules, so the appended
`ACCEPT` rules won first. Nothing was misconfigured — the two mechanisms just
did not know about each other.

## Part 1: firewall

### 1.1 Back up

```bash
sudo iptables-save  > ~/iptables-backup-$(date +%F).rules
sudo ip6tables-save > ~/ip6tables-backup-$(date +%F).rules
sudo cp /etc/wireguard/wg0.conf ~/wg0.conf.backup-$(date +%F)
```

### 1.2 Check Docker's chain ordering

Docker inserts its jumps at the *head* of `FORWARD`, ahead of ufw's. What
matters is only this: nothing in Docker's chains may issue a verdict for
traffic that is not on a Docker bridge.

```bash
sudo iptables -S DOCKER-USER
sudo iptables -S DOCKER-FORWARD
sudo iptables -S DOCKER-CT
sudo iptables -S DOCKER-INTERNAL
sudo iptables -S DOCKER-BRIDGE
```

The exact layout varies by Docker version. On Docker 28 (Ubuntu 22.04 with
docker-ce) it looks like this:

```
-N DOCKER-USER
-N DOCKER-FORWARD
-A DOCKER-FORWARD -j DOCKER-CT
-A DOCKER-FORWARD -j DOCKER-INTERNAL
-A DOCKER-FORWARD -j DOCKER-BRIDGE
-A DOCKER-FORWARD -i docker0 -j ACCEPT
-A DOCKER-FORWARD -i br-... -j ACCEPT
```

Both are fine:

- **An empty `DOCKER-USER` is equivalent to `-j RETURN`.** A user-defined chain
  that matches nothing falls through to its caller. Older Docker wrote the
  `RETURN` explicitly. (This is also the chain Docker intends *you* to add
  rules to, which is why it is empty.)
- **The `-i docker0` / `-i br-*` rules match on ingress interface**, so VPN
  traffic arriving on `wg0` never matches them. They let containers talk
  outbound.
- **`DOCKER-CT`, `DOCKER-INTERNAL` and `DOCKER-BRIDGE` should be scoped to a
  Docker bridge** in every rule. An unscoped conntrack `ESTABLISHED` accept is
  also harmless — it is the same thing ufw does. An unscoped `ACCEPT` or `DROP`
  on new connections is not: stop and reassess.

Your existing ruleset is the stronger evidence, and needs no interpretation.
In `sudo iptables -S FORWARD`, ufw's jumps are listed *before* the `PostUp`
rules appended at the bottom:

```
-A FORWARD -j DOCKER-USER
-A FORWARD -j DOCKER-FORWARD
-A FORWARD -j ufw-before-forward      <- ufw-user-forward is reached from here
...
-A FORWARD -i wg0 -j ACCEPT           <- PostUp, last
-A FORWARD -o wg0 -j ACCEPT
```

The VPN working today means traffic reaches those bottom two rules, so it
already traverses every Docker and ufw chain without any of them issuing a
verdict. `ufw route` rules land in `ufw-user-forward` — strictly *earlier* than
the rules they replace.

That ordering also shows what each of the two `PostUp` rules is doing:
`-i wg0 -j ACCEPT` accepts NEW outbound connections from clients (nothing
earlier does), while `-o wg0 -j ACCEPT` is already redundant because replies
are accepted by ufw's conntrack rule. That redundancy is why dropping it is
safe, and dropping it is what closes the IPv6 exposure.

### 1.2b Confirm the conntrack rule

The design below adds no `eth0 -> wg0` rule, relying on ufw to accept replies.
Verify that rule exists before removing anything:

```bash
sudo iptables -S ufw-before-forward | head -5
```

Expect `-A ufw-before-forward -m conntrack --ctstate RELATED,ESTABLISHED -j
ACCEPT` near the top. If it is missing, stop: removing `-o wg0 -j ACCEPT`
would break all return traffic.

### 1.3 Add the rules

`*nat` block at the top of `/etc/ufw/before.rules`, above `*filter`:

```
*nat
:POSTROUTING ACCEPT [0:0]
-A POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE
COMMIT
```

This replaces the old unscoped `-A POSTROUTING -o eth0 -j MASQUERADE`, which
masqueraded everything leaving `eth0` rather than only VPN traffic.

```bash
sudo ufw route allow in on wg0 out on eth0
sudo ufw route allow in on wg0 out on wg0
sudo ufw reload
```

The second rule is easy to miss and carries peer-to-peer traffic — including
everything to the in-VPN DNS server. The old blanket `-i wg0 -j ACCEPT`
covered it implicitly.

Do **not** add a rule for `eth0 -> wg0`. Reply traffic is already handled by
ufw's `RELATED,ESTABLISHED` rule, and leaving unsolicited inbound to the
`DROP` policy is what protects the clients' IPv6 addresses.

### 1.4 Prove the ufw rules work before making it permanent

Remove the old rules from the live chain without editing any file, so a
failure is one command from fixed:

```bash
sudo iptables -D FORWARD -i wg0 -j ACCEPT
sudo iptables -D FORWARD -o wg0 -j ACCEPT
```

From a connected client:

```bash
ping 10.8.0.1                              # server reachable
ping 1.1.1.1                               # forwarding + NAT
dig @10.8.0.22 immich.hugo-klepsch.tech    # peer-to-peer
curl https://example.com                   # end to end
```

If anything fails, re-add with `-A` (or reboot) and investigate before going
further.

### 1.5 Make it permanent

Remove the `PostUp` and `PostDown` lines from `/etc/wireguard/wg0.conf`. They
are gone for good once `./wgctl apply` generates that file in part 2.

Confirm they survive a reload, which is the whole point of the change:

```bash
sudo ufw reload
sudo iptables -S FORWARD | grep wg0    # ufw's rules, still present
```

## Part 2: registry

### 2.1 Configure

Nothing is installed; `wgctl` runs from this checkout and keeps its state in
`state/` beside it.

```bash
cd ~/wireguard          # wherever this repo is checked out
cp wgctl.conf.example wgctl.conf
vim wgctl.conf
```

Set `endpoint` and `ipv6_subnet` (the routed prefix from the Linode console).
Leave `private_key_file` pointing at `/etc/wireguard/privatekey` — that key
already exists and must not change, or every client config breaks.

If this checkout *is* `~/wireguard`, the legacy peer directories are already
sitting next to the script. That is fine: `import` reads them, and `state/`
plus `wgctl.conf` are gitignored.

### 2.2 Dry-run the import

The legacy peer directories are still in `~/wireguard`, one per peer, and
carry everything needed: the directory name is the peer name, `public` and
`private` are the keys, and `server.conf`'s `AllowedIPs` is the assigned
address. No manual pubkey-to-person mapping is required.

```bash
sudo ./wgctl import ~/wireguard
```

This writes nothing. It prints every peer it found with its derived IPv6
address, whether the private key is on disk, and its last handshake — then
reconciles that against the live interface and flags:

- **peers live on `wg0` with no directory** — `apply` would drop them. Dig out
  where they came from, or let them go.
- **directories not currently loaded** — harmless; they were removed earlier.
- **address collisions and unparseable directories** — must be fixed first.

Read the handshake column and prune anything dormant now, while it is one
`rm -rf` rather than a registry edit.

### 2.3 Write it

```bash
sudo ./wgctl import ~/wireguard --write
sudo ./wgctl check
sudo ./wgctl render --all
```

Peers are imported with their existing keys, so nothing is invalidated. They
get the default profile set and no preshared key.

### 2.4 Apply

```bash
sudo ./wgctl apply --dry-run    # review: peer list and config diff, keys redacted
sudo ./wgctl apply
```

`apply` backs up the existing `wg0.conf` first, writes the generated one
(`SaveConfig` absent, no `PostUp`), and reloads with `wg syncconf` so
established sessions survive.

### 2.5 Verify

```bash
sudo wg show                  # same peers as before, plus nothing unexpected
sudo ./wgctl list
sudo systemctl restart wg-quick@wg0
sudo ./wgctl list               # peers still there after a full restart
```

That last pair is the fix landing: with `SaveConfig = true` and `wg addconf`,
peer persistence depended on a clean shutdown. Now the file is generated from
the registry and a restart is uneventful.

Then confirm IPv6 works end to end from a client (`ping -6 orion...`,
`curl -6 https://example.com`) and, separately, that unsolicited inbound does
**not**: from a machine outside the VPN with IPv6, try to reach a client
address such as `2600:3c03:e000:0315::22` on an open port. It must time out.

### 2.6 Redistribute

Every client config changes in this migration — peers gain IPv6 addresses, and
the four profiles replace the old `<name>.conf` / `<name>all.conf` pair. They
land in `state/out/<name>/` as `<profile>.conf`. Keys are unchanged, so old
configs keep working until you are ready.

```bash
sudo ./wgctl qr hugo-iphone full-vpndns
```

## Afterwards

Once everything is confirmed, retire the legacy directories. They hold client
private keys, so overwrite rather than just unlink, and keep in mind `wgctl`
now has its own copies under `state/secrets/`:

```bash
sudo find ~/wireguard -maxdepth 2 -name private -exec shred -u {} +
```

Check nothing secret was ever committed before pushing:

```bash
git log --all --name-only --pretty=format: | sort -u | grep -E 'private|\.conf$'
```

`.gitignore` blocks these going forward. If a private key does appear in
history, rotate those peers rather than trying to rewrite it.

## Rollback

Before 2.4 nothing on the server has changed except the firewall; revert with
`iptables-restore < ~/iptables-backup-*.rules` and re-add the `PostUp` lines.

After 2.4, `wg0.conf.bak-*` next to the generated file is the previous
version. Restore it and `systemctl restart wg-quick@wg0`.
