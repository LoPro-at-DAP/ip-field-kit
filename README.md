# IP Field Kit

An installable web app (PWA) for IPv4 work in the field. It works offline once it has been opened one time.

- **Lookup**: enter an IP and a mask (`/26`, `255.255.255.192`, or a wildcard like `0.0.0.63`) to get the network, usable range, broadcast, host position, address type (private, public, APIPA, CGNAT, loopback, multicast…), class, binary, hex, and reverse DNS name. You can also step through neighboring subnets.
- **Scan**: take a photo of a screen, label, or printout (or paste command output) and the app pulls out every IPv4 address, labeled as IP, mask, gateway, DNS, and so on. It understands `ipconfig`, `ifconfig`, `ip addr`, `ip route`, and Cisco-style config. When it finds a full set of settings, one tap sends them to Check.
- **Check**: enter a device's IP, mask, and gateway to catch common misconfigurations: a gateway outside the subnet, a network or broadcast address assigned to a device, or an APIPA address from a failed DHCP lease. Below that are Windows and Linux commands to run on the device, filled in with its addresses, with example output for passing and failing results:
  - **Reachability**: loopback, gateway, remote host, DNS.
  - **MTU and fragmentation**: `ping -f -l 1472` (Windows) or `ping -M do -s 1472` (Linux), with a calculator (data size = MTU − 28) and presets for PPPoE, GRE, VXLAN, VPN, and jumbo frames.
  - **Routes**: `route print`, `Find-NetRoute`, `ip route get`, `tracert`, `traceroute`, `pathping`, `mtr`.
  - **ARP**: `arp -a`, `Get-NetNeighbor`, `ip neigh`, `arping`, including duplicate-IP detection.
- **Subnets**: the borrowing-bits solver, with worked math and the hosts and subnets lookup tables.

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
