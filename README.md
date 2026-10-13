# IP Field Kit

An installable web app (PWA) for networking students working in the field. It works offline once it has been opened one time.

- **Lookup**: enter an IPv4 address and mask (`/26`, `255.255.255.192`, or a wildcard like `0.0.0.63`), or an IPv6 address and prefix (`/64`), to get the network, range, address type (private, public, APIPA, CGNAT, unique local, link-local, multicast…), and more. IPv4 adds broadcast, host position, class, binary, and hex. IPv6 adds the short and full forms, interface ID (and the MAC behind an EUI-64 one), solicited-node multicast, embedded IPv4, and the hex digits colored by prefix. Both show the reverse DNS name and let you step through neighboring subnets.
- **Scan**: take a photo of a screen, label, or printout (or paste command output) and the app pulls out every IPv4 address, IPv4 and IPv6, labeled as IP, link-local, mask, gateway, DNS, and so on. It understands `ipconfig`, `ifconfig`, `ip addr`, `ip -6 addr`, `ip route`, and Cisco-style config. When it finds a full set of settings, one tap sends them to Check.
- **Check**: enter a device's IPv4 or IPv6 settings to catch common misconfigurations: a gateway outside the subnet or prefix, a network or broadcast address assigned to a device, an APIPA address from a failed DHCP lease, a non-/64 IPv6 prefix, or an IPv6 device with only a link-local address (no router advertisement). For IPv6 devices the commands switch to their IPv6 versions (`ping -6`, `ip -6 route`, `netsh interface ipv6`, `ndp`, neighbor discovery, Packet Too Big). Below that are Windows, macOS, and Linux commands to run on the device, filled in with its addresses, with example output for passing and failing results:
  - **Reachability**: loopback, gateway, remote host, DNS.
  - **MTU and fragmentation**: `ping -f -l 1472` (Windows), `ping -D -s 1472` (macOS), or `ping -M do -s 1472` (Linux), with a calculator (data size = MTU − 28) and presets for PPPoE, GRE, VXLAN, VPN, and jumbo frames.
  - **Routes**: `route print`, `Find-NetRoute`, `ip route get`, `tracert`, `traceroute`, `pathping`, `mtr`.
  - **ARP**: `arp -a`, `Get-NetNeighbor`, `ip neigh`, `arping`, including duplicate-IP detection.
  - **See it in Wireshark**: display filters for packet size, fragmentation, MSS, and black holes (under MTU) and for ARP problems such as duplicates and wrong subnets (under ARP).
  - **Tunnel and label overhead**: stack MPLS labels, GRE or GRE with key (mGRE/DMVPN), IPsec (tunnel or transport, several ciphers), NAT-T, PPPoE, VXLAN, and WireGuard to get the IP MTU, ping size, MSS, and Cisco `ip mtu` / `ip tcp adjust-mss` / `mpls mtu` settings. Work backward from the largest MTU that passed to the likely cause, and run Cisco IOS checks such as `ping ... size ... df-bit` and `ping mpls ipv4 ... sweep`.
- **Find a device**: a guided workflow for reaching equipment whose IP address you don't know, for Windows, macOS, and Linux laptops. Five steps, each with what to do, what you'll see, and a short explanation of why it works: get ready (cable, Wi-Fi off, MAC from the label); quick wins (default IP, DHCP, the maker's discovery tool); listen with Wireshark (annotated ARP, DHCP, link-local, LLDP/CDP, and mDNS examples); if it stays quiet (IPv6 all-nodes ping, sweeping common ranges, console port, factory reset); and connect (a suggested laptop address in the device's subnet, then commands to check it's free, set it, connect, and undo).
- **Practice**: subnetting practice and planning in IPv4 and IPv6. Enter a network and how many subnets or hosts you need, work it yourself, then check the borrowing-bits math and where the answer sits in the lookup tables. IPv6 adds nibble boundaries, which hextet changes and by how much, and how many /64s each subnet holds.

## Files

| File | Purpose |
|---|---|
| `index.html` | App shell and styles |
| `app.js` | All app logic |
| `sw.js` | Service worker that caches the app for offline use |
| `manifest.webmanifest` | Name, icons, and colors used when the app is installed |
| `icons/` | App icons |

## Hosting

A PWA has to be served over **HTTPS** to be installable. Any static host works:

- **GitHub Pages**: push this folder to a repository, then go to Settings → Pages and choose the branch.
- **Netlify Drop**: drag this folder onto https://app.netlify.com/drop.
- **Cloudflare Pages**: create a project and upload this folder.

All paths are relative, so the app also works from a subfolder such as `https://you.github.io/ip-field-kit/`.

To test on your own computer:

```bash
python3 -m http.server 8765 --directory ip-field-kit
```

Then open http://localhost:8765. Service workers are allowed on localhost without HTTPS.

## Installing

- **Android (Chrome)**: tap **Install** in the app bar, or use the browser menu → *Install app*.
- **iPhone and iPad (Safari)**: tap **Share** → **Add to Home Screen**. The app shows a reminder.
- **Windows, macOS, ChromeOS (Chrome or Edge)**: click the install icon in the address bar.

## Updating

After you change any file, bump `VERSION` in `sw.js` (for example `ipkit-v2`). Installed copies download the new version the next time they open online, then show a **Reload** prompt.

## What goes online

Everything is computed on the device, including reading text from photos: images are never uploaded. The text-recognition engine (Tesseract.js, about 7 MB) is downloaded from cdn.jsdelivr.net the first time you scan and cached for offline use after that.

Two optional buttons use the network, and only when tapped:

- **Look up owner** sends the address to `rdap.org`, which forwards to the regional internet registry (ARIN, RIPE NCC, APNIC, LACNIC, or AFRINIC).
- **Use my public IP** asks `api.ipify.org` for the device's public address.

Saved inputs stay in the browser's local storage on each device.
