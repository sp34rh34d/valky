# valky

Client/server tunnel in Go, **a single binary**. The server is the hub: clients
connect to it and can reach other clients' network segments **only** according to
the rules you define live from the server's **interactive console**.

```
 host1 (192.168.1.0/24) ──┐      server hub       ┌── host2 (192.168.2.0/24)
       TUN 10.9.0.x  ──────┤   172.16.71.134:9000  ├──── TUN 10.9.0.y
                           └──  console: ls/route  ─┘
```

## Build

```sh
make            # bin/valky for your machine
make linux      # bin/valky-linux (amd64) for a Linux server and hosts
make release    # all 11 OS/arch binaries into dist/
```

A single binary acts as both server and client.

## Generate config.ini (server)

```sh
valky server --create-config                 # creates ./config.ini with a random MD5 key
valky server --create-config --config /path/to/my.ini
```

Generates the server's `config.ini` with a random `key` (MD5, 32 hex). It will
not overwrite an existing file.

## Server

```sh
sudo ./bin/valky server --config config.ini
```

The server always runs as a **background daemon**; the console is just a client
that attaches to it over a local control channel (`127.0.0.1:47655` by default).
This lets you close the console without disconnecting the clients.

```sh
sudo ./bin/valky server --config config.ini          # start the daemon and open the console
sudo ./bin/valky server --config config.ini --bg     # start in the background, no console
valky --resume                                        # reopen the daemon's console
valky --stop                                          # stop the daemon (disconnects clients)
```

Inside the console, `detach` (or `bg`, `quit`, `Ctrl-D`) **detaches** the console
and leaves the server running; `stop` stops it. If you use a non-default `--ctrl`
at startup, pass it to `--resume`/`--stop` as well. Logging is **off by default**:
pass `--log /path/to/log` to capture the daemon's output.

`config.ini` only defines the port, the key and the overlay:

```ini
[server]
listen  = 0.0.0.0:9000
key     = change-this-key
overlay = 10.9.0.0/24
encrypt = false   ; set true (or pass --encrypt) to require an encrypted link
```

Each agent has a **stable UUID** (the client generates and persists it), so rules
keep applying even if the agent reconnects. Rules are objects with their **own
UUID**, so you can delete them by id.

The interactive console provides **Tab completion**, **command history (`↑/↓`,
persisted across sessions)** and line editing.

On startup it opens an **interactive console**:

```
> ls
AGENT-UUID                  MODE    OVERLAY    REMOTE              SEGMENTS
3f1c...abcd                 tunnel  10.9.0.1   192.168.1.50:51000  192.168.1.0/24
9a77...ef02                 proxy   10.9.0.2   192.168.2.80:52000  192.168.2.0/24

> route --add 192.168.2.0/24 --id 3f1c...abcd
rule created: 8d9fd4d8-918b-4dfd-8bca-7bcd84de37ad
  agent 3f1c... can reach 192.168.2.0/24 (route pushed to agent)

> route --list
ROUTE-UUID                            AGENT-UUID                 NETWORK         AGENT
8d9fd4d8-918b-4dfd-8bca-7bcd84de37ad  3f1c...abcd                192.168.2.0/24  online

> route --del 8d9fd4d8          # a unique prefix of the rule uuid is enough
rule removed: 8d9fd4d8-...

> show 3f1c...abcd              # details of an agent and its rules
> quit
```

Routes are **pushed automatically** to the affected agent: as soon as you create
or delete a rule, the client installs or removes the matching route.

Console commands:

| Command | Action |
|---|---|
| `ls` / `list` | list connected agents (uuid, mode, overlay IP, remote, segments) |
| `route --add <CIDR> --id <agent-uuid> [--random] [--no-nat]` | create a rule; prints its uuid (egress NAT is on by default; `--no-nat` keeps the real overlay source) |
| `route --del <route-uuid>` | delete the rule with that uuid |
| `route --list` / `-l` | list rules (route-uuid, agent, network, status) |
| `route --via <agent-uuid> <CIDR>` | publish a subnet route: the agent delivers a network it did not auto-advertise |
| `route --via-del <uuid>` / `--via-list` | remove / list published subnet routes |
| `forward --add --id <agent-uuid> --listen <ip:port> --to <ip:port>` | create a port-forward on the agent |
| `forward --del <forward-uuid>` | delete the port-forward |
| `forward --list` / `-l` | list port-forwards |
| `socks --add --id <agent-uuid> --listen <ip:port>` | run a SOCKS5 proxy on the agent |
| `socks --del <socks-uuid>` | delete the SOCKS5 proxy |
| `socks --list` / `-l` | list SOCKS5 proxies |
| `show <agent-uuid>` | details of an agent, its rules, forwards and proxies |
| `kick <agent-uuid>` / `rm` | disconnect an agent (its config persists; it re-registers on reconnect) |
| `destroy <agent-uuid> <config-key>` | **self-destruct** a compromised agent — requires the config.ini key |
| `help` | help |
| `quit` / `exit` | detach (leave the server running) |

**uuid prefixes** are accepted as long as they are unique. You can create a rule
for an agent that is still offline using its full uuid; it applies when it
connects.

## Client

No config file; everything on the command line:

```sh
sudo ./bin/valky client --ip 172.16.71.134 --port 9000 --passwd change-this-key
```

Options:

- `--ip`      server IP (required)
- `--port`    server port (required)
- `--passwd`  shared key (required)
- `--dev`     TUN interface name (optional, Linux only)
- `--id`      agent UUID (optional; generated and persisted if omitted)
- `--encrypt` require an encrypted link; refuse a server that offers plaintext
- `--bg`      run the client in the background
- `--log`     log file (optional; no log is written without this flag)
- `--cctrl`   client control channel (default `127.0.0.1:47656`)
- `--name`    process title shown in `ps` (e.g. `--name valky`) — hides the args,
  including `--passwd`, from `ps auxf` (Linux)

### Hiding from `ps`

```sh
valky client --ip 172.16.71.134 --port 9000 --passwd <key> --name mitunnel --bg
# ps              ->  mitunnel
# ps auxf         ->  ... mitunnel            (no args, no key)
# ps -axE / -E    ->  mitunnel ...            (key is NOT in the environment)
```

The title defaults to `valky`; set it with `--name`. The key appears nowhere in
`ps` or `ps -E` — not in argv, not in the environment — on Linux, macOS and BSD.
Only the original command you typed is visible for the instant it runs (and in
your shell history), so still prefer a one-time key per session.

Like the server, the client always runs as a **background engine** with a local
control channel (`127.0.0.1:47656` by default); the console is just a client that
attaches to it. This lets you close and reopen the console without dropping the
tunnel.

```sh
sudo ./bin/valky client --ip 172.16.71.134 --port 9000 --passwd <key>        # engine + console
sudo ./bin/valky client --ip 172.16.71.134 --port 9000 --passwd <key> --bg   # background, no console
valky client --resume     # reopen the console of a backgrounded client
valky client --stop       # stop the client
```

The console (`Tab` completes, `↑/↓` history):

| Command | Action |
|---|---|
| `status` | show connection, mode (tunnel/proxy), overlay, segments, forwards and proxies |
| `detach` / `bg` / `quit` / `exit` | close the console; the client keeps running in the background |
| `stop` | stop the client (disconnect) |
| `help` | help |

If you use a non-default `--cctrl` at startup, pass it to `--resume`/`--stop` as
well. Logging is off by default; use `--log /path` to capture it.

The client:
1. uses a **stable UUID**: it takes it from `--id`, or generates and stores it in
   the user's config directory (`~/.config/valky/agent-id` on Linux);
2. automatically detects its local LAN segments and advertises them to the server;
3. receives a virtual overlay IP (e.g. `10.9.0.3/24`);
4. installs/removes the routes the server tells it to, live.

To see an agent's UUID, check the client's startup log or run `ls` in the server
console.

The client **re-scans its local segments every 30s** and pushes any change to the
server, so routing follows the host's current networks without reconnecting.

Reconnecting is **last-connection-wins**: if a client restarts and reconnects
with the same UUID, the server drops the previous (possibly half-open) session
and accepts the new one, re-registering its current segments and reusing its
overlay IP. You can also force a disconnect from the console with
`kick <agent-uuid>` (its rules/forwards/socks/published routes persist).

## Tunnel mode (admin) vs proxy mode (no admin)

The client detects privileges automatically at startup:

- **With admin/root** → it creates the **TUN** interface and enables the full L3
  tunnel: routing between segments, `ping`, any protocol, plus port-forwards.
- **Without privileges** → no TUN; it falls back to **proxy mode**. Port-forwards
  and SOCKS5 still work, carried over a userspace TCP stream multiplexer on the
  server link. A proxy agent also runs a **userspace TCP/IP stack** so it can act
  as the **L3 delivery agent** for a network it owns: raw IP packets routed to it
  (e.g. from another agent's TUN) are turned into real OS sockets to the target,
  **TCP and UDP, no admin and no TUN required**. ICMP (`ping`) is not forwarded in
  proxy mode — emitting echo requests on the LAN would need a raw socket (root).

In both cases **port-forwards use the same stream path**: the destination agent
dials the service with an ordinary socket, so **no admin is needed on either end**
for a port-forward (nor `ip_forward`/NAT).

### Who can reach whom (ingress × egress)

Where operator traffic **enters** the overlay (ingress) and which agent
**delivers** it into the LAN (egress) can be in either mode independently:

| Ingress (how traffic enters the overlay) | Egress (delivery agent) | Path | Works |
|---|---|---|---|
| tunnel — TUN, raw L3 | tunnel | written to the egress TUN | ✓ |
| tunnel — TUN, raw L3 | **proxy** | **egress userspace TCP/IP stack** | ✓ |
| proxy — SOCKS5 / port-forward | tunnel | stream → `net.Dial` on egress | ✓ |
| proxy — SOCKS5 / port-forward | proxy | stream → `net.Dial` on egress | ✓ |

- A **tunnel** agent gives you raw-L3 ingress: route the target CIDR into its TUN
  and drive tools directly (`nxc rdp -t 172.16.5.0/24 ...`), no proxychains.
- A **proxy** agent has no TUN, so it can only *inject* operator traffic via its
  **SOCKS5/forward** (there is no raw-L3 ingress without a TUN). Point your tools
  at the proxy (`proxychains ...`); the egress agent delivers in either mode.
- As a **delivery** agent, both modes now work for L3: a tunnel agent writes to
  its TUN, a proxy agent dials from its userspace stack. So a tunnel-mode operator
  box can reach a subnet published by a proxy-mode pivot **directly**, with no
  SOCKS in the path.

On Linux you can enable the TUN without full root by granting a capability once:

```sh
./valky client --ip 172.16.71.134 --port 9000 --passwd <key>   # creates the TUN as a normal user
```

## Port-forward

An agent can expose a local port that forwards, **through the tunnel**, to a
service reachable by another agent. Configured from the server console.

Example: agent A (`192.168.1.10`, which reaches `10.10.10.0/24`) must expose port
80 of host `192.168.3.12` (on agent B's network) at `192.168.1.10:1234`. Hosts in
`10.10.10.0/24` connect to `192.168.1.10:1234` and reach `192.168.3.12:80`:

```
> ls                       # find agent A's uuid
> forward --add --id <A-uuid> --listen 192.168.1.10:1234 --to 192.168.3.12:80
port-forward created: 83cb811d-...
  agent <A-uuid>: 192.168.1.10:1234 -> 192.168.3.12:80 (forward active on agent)

> forward --list
> forward --del 83cb811d   # remove it (uuid prefix accepted)
```

When you create the forward, the server:
1. tells agent A to **listen** on `192.168.1.10:1234` and act as a TCP proxy;
2. **authorizes and routes** the destination (`192.168.3.12/32`) toward the tunnel
   for that agent automatically, with no separate `route` rule needed.

Each incoming connection on `192.168.1.10:1234` is forwarded over the stream
multiplexer to the agent that owns `192.168.3.12`, which dials `:80` with an
ordinary socket. It needs no TUN or NAT on either end, so it works even when the
clients run **without administrator privileges**.

## SOCKS5 proxy (proxy mode, no admin)

When a client runs **without privileges** (proxy mode, no TUN), it has no local
kernel route into the overlay, so you cannot drive raw-L3 tools from *that*
machine (that needs a tunnel-mode agent's TUN). To reach **any TCP port** of a
network from the proxy agent's own host without a per-port `forward`, the agent
can expose a **SOCKS5 proxy**: each `CONNECT` travels over the stream multiplexer
to the agent that owns the destination, and the server enforces the **same `route`
rules as the ACL**. (As a *delivery* target for other agents' traffic, a proxy
agent still handles L3 via its userspace stack — see the ingress × egress table.)

```
valky❯ socks --add --id <agent-uuid> --listen 127.0.0.1:1080
valky❯ route --add 172.16.71.0/24 --id <agent-uuid>   # define what the proxy may reach
valky❯ socks --list
valky❯ socks --del <socks-uuid>
```

From the agent's machine, point your tools at the proxy:

```sh
curl --socks5 127.0.0.1:1080 http://172.16.71.135/
proxychains4 ssh 172.16.71.135
```

- No admin or TUN needed on either end.
- The **agent's `route` rule is the proxy's allow-list**.
- **TCP only** (no `ping`/UDP). IPs work directly; for domain names, use the
  segment's IP (the server routes by IP).

## Published subnet routes (networks not auto-advertised)

An agent auto-advertises only its **directly connected** LAN segments. For a
network reachable *behind* an agent (via a next hop, not on a local interface),
tell the server that agent delivers it with a **published subnet route**:

```
valky❯ route --via <B-uuid> 10.20.30.0/24      # agent B becomes the delivery target
valky❯ route --add 10.20.30.0/24 --id <A-uuid> # authorize source A to reach it
valky❯ route --via-list
valky❯ route --via-del <via-uuid>              # uuid prefix accepted
```

Two different things are involved:
- **delivery** (`--via`): which agent the server hands the traffic to;
- **authorization** (`--add`): which source agent may send to that network.

Both are needed. If agent B is a **tunnel-mode** delivery agent, enable
`ip_forward` + `MASQUERADE` on it to reach real hosts behind it (see below). If
agent B is in **proxy mode**, its userspace stack dials each target from an
ordinary OS socket, so the kernel does the SNAT for free — **no `ip_forward` or
`MASQUERADE` needed** (TCP/UDP only). Published routes persist across the agent's
reconnects (keyed by its stable UUID) and only deliver while it is online.

### Overlapping or duplicate networks

When several agents advertise overlapping or duplicate networks, delivery is
**deterministic**: the server picks the **most specific match (longest prefix)**,
and breaks exact ties by the lowest agent UUID — so traffic for a destination
always goes to the same agent (no flapping).

Example with these agents:

```
A  172.16.71.0/24  172.16.4.0/23
B  172.16.0.0/16   172.16.4.0/23
```

- `172.16.71.5` → **A** (its `/24` beats B's `/16`).
- `172.16.200.9` → **B** (only its `/16` covers it).
- `172.16.4.100` → exact `/23` tie, resolved deterministically to the lower UUID.

To force which agent owns an exactly-duplicated network, publish a **more
specific** route on the preferred one (e.g. `route --via <A> 172.16.4.0/24`),
since longest prefix wins.

### Load-balancing across duplicate agents (`--random`)

If several agents deliver the **same** network and you want to spread traffic
across them, add the source rule with `--random`:

```
route --add 172.16.4.0/23 --id <source> --random
```

Delivery is pinned by the **(client, destination)** pair, so every connection
from one client to one service always uses the same agent — its replies return
through that agent and, since egress NAT is on by default, the destination always
sees the **same source address**. That keeps stateful sessions intact (a web
login is not reset between requests). Different **clients** still spread across all
the delivering agents. Without `--random`, routing stays deterministic (lowest
uuid). `route --list` shows `random` in the `LB` column.

> Affinity is per client, not per connection: this is deliberate. Hashing each
> TCP connection separately (its own source port) would send a browser's many
> connections to different agents with different NAT source IPs, which resets
> logins on apps that bind the session to the client IP.

## Reaching a real LAN (not just the virtual IPs)

When an agent delivers tunneled traffic into its local LAN, the packets keep the
**originator's overlay source** (e.g. `10.9.0.7`). Hosts on the segment have no
route back to the overlay, so their replies are lost and connections hang at the
SYN (you see repeated `[TCP Retransmission] ... [SYN]` with no `SYN-ACK`).

### Automatic egress NAT (on by default)

Because a LAN host almost never has a route back to the overlay, **egress NAT is
on by default** for every `route --add`. The server pushes a masquerade
instruction to whichever agent **delivers** that network (not the authorized
agent — NAT belongs where packets leave the tunnel):

```
> route --add 192.168.2.0/24 --id <source-agent>            # NAT on
> route --add 10.0.0.0/24    --id <source-agent> --no-nat   # keep real source
```

The delivering agent enables IP forwarding and installs a scoped `iptables`
`MASQUERADE` (`-s <overlay> -d 192.168.2.0/24`), so LAN hosts reply to the
agent's own address and `conntrack` routes the reply back through the tunnel. The
rule set is reconciled live (and re-applied on reconnect / segment change) and
removed when the route is deleted or the agent stops. `route --list` shows `yes`
in the `NAT` column. **Linux agents only** — on macOS/Windows the push is a no-op;
configure NAT out of band.

Use `--no-nat` only when you want the destination to see the real overlay source
(per-client ACLs, attribution) **and** the LAN already routes the overlay back to
the delivering agent — otherwise replies are lost and connections hang at the SYN.

### Doing it by hand

Equivalently, on the host acting as its LAN's gateway, enable forwarding and NAT
yourself:

```sh
sysctl -w net.ipv4.ip_forward=1
iptables -t nat -A POSTROUTING -o <lan_iface> -j MASQUERADE
```

## Self-destruct

You can order to wipe a client itself from the server console:

```
valky❯ destroy <agent-uuid> <config.ini-key>
```

The second argument must be the server's `config.ini` key, as confirmation — a
wrong key is denied. On receipt the agent:

1. overwrites and removes its persisted identity (`agent-id`), pidfile and history;
2. deletes its own binary — on Unix the running binary is unlinked directly; on
   Windows (where a running `.exe` is locked) a detached helper deletes it right
   after the process exits;
3. exits immediately.

The server also purges that agent's rules, forwards, socks proxies and published
routes, since a destroyed agent never comes back. The agent must be online to
receive the order.

## Encryption (optional)

By default the channel is a plaintext TCP relay with shared-key authentication.
Start the server with **`--encrypt`** (or `encrypt = true` in `config.ini`) to
require an encrypted link instead:

```sh
sudo ./bin/valky server --config config.ini --encrypt
```

- **X25519** ephemeral key exchange (fresh per connection) → forward secrecy.
- The shared **key** is mixed into the key derivation, so a man-in-the-middle
  without it cannot derive the session keys (the first record fails to decrypt) —
  this authenticates the peer and hides the key, which is otherwise sent in the
  clear in the plaintext handshake.
- **AES-256-GCM** per-record AEAD (confidentiality + integrity).
- Standard-library only — no new dependencies, still a single binary.

A short hello negotiates the mode, so an encrypted server and a plaintext one both
interoperate with the same client binary. A client started with `--encrypt`
**refuses** a server that offers plaintext (downgrade protection); without it, the
client follows whatever the server offers.

```sh
./bin/valky client --ip <server> --port 9000 --passwd <key> --encrypt
```

## Reliability

- **Auto-reconnect.** If the link drops, the agent reconnects on its own with
  exponential backoff (1s → 30s), keeping its TUN device, routes and NAT up across
  reconnects. Its stable UUID means the server reattaches all its rules on return.
- **Dead-peer detection.** The server drops a session if no frame (the agent
  keepalives every 20s) arrives within 60s, reclaiming its overlay IP so stale
  agents don't linger as delivery candidates.

## Persistence

The server keeps the policy (rules, port-forwards, SOCKS proxies, published subnet
routes) in memory and writes it to `valky.state` (next to `config.ini`, or set
`--state <file>`) on every change. On restart it reloads the file, so a server
restart no longer loses your configuration — agents reconnect and their rules are
pushed again. Live connection state (sessions, IP allocations) is rebuilt as
agents reconnect and is intentionally not persisted.

## Security notes

- With `--encrypt` the transport is authenticated and encrypted (see above).
  Without it, the channel is plaintext with shared-key authentication — fine for
  labs and your own networks; prefer `--encrypt` otherwise.
- Authentication is a single shared key for all agents; there is no per-agent key
  or revocation yet (beyond `destroy`).

---

<sub>valky · crafted by [@spearh34d](https://github.com/spearh34d)</sub>
