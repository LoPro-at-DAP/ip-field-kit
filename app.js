/* IP Field Kit: IPv4 address lookup, device settings check, and subnet solver.
   Everything except the owner lookup and "Use my public IP" runs offline. */
(() => {
  'use strict';

  // ---------- Helpers ----------
  const $ = (id) => document.getElementById(id);
  const P2 = (n) => Math.pow(2, n);
  const MAX32 = P2(32);
  const ORD = ['1st', '2nd', '3rd', '4th'];
  const BITVAL = [128, 64, 32, 16, 8, 4, 2, 1];
  const fmt = (n) => n.toLocaleString('en-US');
  const pl = (n, w) => `${fmt(n)} ${w}${n === 1 ? '' : 's'}`;
  const pow = (b, e) => `${b}<sup>${e}</sup>`;
  const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);

  const store = {
    get(key, fallback) {
      try {
        const v = JSON.parse(localStorage.getItem('ipkit:' + key));
        return v === null ? fallback : v;
      } catch (e) { return fallback; }
    },
    set(key, value) {
      try { localStorage.setItem('ipkit:' + key, JSON.stringify(value)); } catch (e) { /* storage unavailable */ }
    },
  };

  let toastTimer = 0;
  function toast(text, action, onAction) {
    const el = $('toast');
    el.innerHTML = `<span>${esc(text)}</span>` + (action ? `<button type="button">${esc(action)}</button>` : '');
    if (action) el.querySelector('button').addEventListener('click', onAction);
    el.hidden = false;
    clearTimeout(toastTimer);
    if (!action) toastTimer = setTimeout(() => { el.hidden = true; }, 2400);
  }

  function fetchTimeout(url, ms) {
    const ctl = new AbortController();
    const t = setTimeout(() => ctl.abort(), ms);
    return fetch(url, { signal: ctl.signal }).finally(() => clearTimeout(t));
  }

  // ---------- IPv4 ----------
  const IP4 = /^\d{1,3}(\.\d{1,3}){3}$/;

  function parseIP(str) {
    const s = String(str).trim();
    if (!IP4.test(s)) return null;
    let n = 0;
    for (const part of s.split('.')) {
      const v = Number(part);
      if (v > 255) return null;
      n = n * 256 + v;
    }
    return n;
  }

  const octets = (n) => [Math.floor(n / 16777216) % 256, Math.floor(n / 65536) % 256, Math.floor(n / 256) % 256, n % 256];
  const ipStr = (n, bold) => octets(n).map((v, i) => (i === bold ? `<b>${v}</b>` : String(v))).join('.');
  const maskInt = (p) => MAX32 - P2(32 - p);
  const maskStr = (p) => ipStr(maskInt(p));
  const netOf = (ip, p) => { const s = P2(32 - p); return Math.floor(ip / s) * s; };

  function prefixOfMask(n) {
    for (let p = 0; p <= 32; p++) if (maskInt(p) === n) return p;
    return -1;
  }

  // Accepts "/26", "26", "255.255.255.192", or a wildcard like "0.0.0.63".
  function parseMask(str) {
    const s = String(str).trim();
    if (s === '') return { empty: true };
    const m = s.match(/^\/?\s*(\d{1,2})$/);
    if (m) {
      const p = Number(m[1]);
      return p <= 32 ? { p, kind: 'prefix' } : { error: `/${p} isn't a valid prefix. Use a number from 0 to 32.` };
    }
    const n = parseIP(s);
    if (n === null) return { error: 'Enter the mask as a prefix like /24 or in dotted decimal like 255.255.255.0.' };
    const p = prefixOfMask(n);
    if (p >= 0) return { p, kind: 'mask' };
    const w = prefixOfMask(MAX32 - 1 - n);
    if (w >= 0) return { p: w, kind: 'wildcard' };
    return { error: `${s} isn't a valid mask. The 1 bits must run unbroken from the left, like 255.255.255.192.` };
  }

  // Splits "10.1.2.3/24" or "10.1.2.3 255.255.255.0" typed into a single field.
  function splitCombined(str) {
    const m = String(str).trim().match(/^(\S+?)\s*(?:\/\s*(\d{1,2})|\s+(\S+))$/);
    if (!m) return { ip: String(str).trim(), mask: null };
    return { ip: m[1], mask: m[2] !== undefined ? '/' + m[2] : m[3] };
  }

  function commonPrefix(a, b) {
    let k = 0;
    while (k < 32 && netOf(a, k + 1) === netOf(b, k + 1)) k++;
    return k;
  }

  function classOf(ip) {
    const a = Math.floor(ip / 16777216);
    if (a < 128) return { cls: 'A', p: 8 };
    if (a < 192) return { cls: 'B', p: 16 };
    if (a < 224) return { cls: 'C', p: 24 };
    if (a < 240) return { cls: 'D', p: null };
    return { cls: 'E', p: null };
  }

  // IANA special-purpose ranges. dev = whether a device can use the address: ok, warn, or bad.
  const SPECIAL = [
    ['0.0.0.0', 32, 'Unspecified address', 'reserved', 'bad', 'Means "no address yet". In a routing table, 0.0.0.0/0 is the default route.'],
    ['0.0.0.0', 8, '"This network" (RFC 1122)', 'reserved', 'bad', 'Only valid as a source address while a device starts up.'],
    ['10.0.0.0', 8, 'Private (RFC 1918)', 'private', 'ok', 'For use inside an organization. Reaches the internet only through NAT.'],
    ['100.64.0.0', 10, 'Shared address space / CGNAT (RFC 6598)', 'special', 'ok', "Used between an ISP's carrier-grade NAT and its customers. Not routable on the internet."],
    ['127.0.0.0', 8, 'Loopback (RFC 1122)', 'special', 'bad', 'Traffic sent here never leaves the device.'],
    ['169.254.0.0', 16, 'Link-local / APIPA (RFC 3927)', 'warn', 'warn', "A device gives itself one of these when it can't reach a DHCP server."],
    ['172.16.0.0', 12, 'Private (RFC 1918)', 'private', 'ok', 'For use inside an organization. Reaches the internet only through NAT.'],
    ['192.0.0.0', 24, 'IETF protocol assignments (RFC 6890)', 'reserved', 'bad', 'Set aside for specific protocols.'],
    ['192.0.2.0', 24, 'Documentation, TEST-NET-1 (RFC 5737)', 'reserved', 'warn', 'Set aside for examples in documentation. Not used on real networks.'],
    ['192.88.99.0', 24, '6to4 relay anycast, deprecated (RFC 7526)', 'reserved', 'bad', 'Formerly used to tunnel IPv6 over IPv4.'],
    ['192.168.0.0', 16, 'Private (RFC 1918)', 'private', 'ok', 'For use inside an organization. Reaches the internet only through NAT.'],
    ['198.18.0.0', 15, 'Benchmark testing (RFC 2544)', 'reserved', 'warn', 'Set aside for lab testing of network equipment.'],
    ['198.51.100.0', 24, 'Documentation, TEST-NET-2 (RFC 5737)', 'reserved', 'warn', 'Set aside for examples in documentation. Not used on real networks.'],
    ['203.0.113.0', 24, 'Documentation, TEST-NET-3 (RFC 5737)', 'reserved', 'warn', 'Set aside for examples in documentation. Not used on real networks.'],
    ['224.0.0.0', 4, 'Multicast, Class D (RFC 5771)', 'special', 'bad', 'Addresses a group of receivers, not a single device.'],
    ['240.0.0.0', 4, 'Reserved, Class E (RFC 1112)', 'reserved', 'bad', 'Set aside for future use. Not routable.'],
    ['255.255.255.255', 32, 'Limited broadcast (RFC 919)', 'reserved', 'bad', 'Reaches every device on the local segment.'],
  ].map(([a, p, label, kind, dev, note]) => ({ net: parseIP(a), p, cidr: `${a}/${p}`, label, kind, dev, note }));
  const PUBLIC = { label: 'Public (globally routable)', kind: 'public', dev: 'ok', note: 'Registered to an organization and routable on the internet.' };

  function classify(ip) {
    let best = null;
    for (const s of SPECIAL) if (netOf(ip, s.p) === s.net && (!best || s.p > best.p)) best = s;
    return best || PUBLIC;
  }

  const COPY_SVG = '<svg viewBox="0 0 16 16" aria-hidden="true"><rect x="5" y="5" width="9" height="9" rx="1.5" fill="none" stroke="currentColor" stroke-width="1.4"/><path d="M3.5 10.5H3a1 1 0 0 1-1-1V3a1 1 0 0 1 1-1h6.5a1 1 0 0 1 1 1v.5" fill="none" stroke="currentColor" stroke-width="1.4"/></svg>';

  // rows: [label, valueHTML, copyText|null]
  function kvRows(rows) {
    return rows.filter(Boolean).map(([label, html, copy]) =>
      `<div class="kv-row"><dt>${label}</dt><dd>${copy != null
        ? `<button type="button" class="copy" data-copy="${esc(copy)}" title="Copy">${html}${COPY_SVG}</button>`
        : html}</dd></div>`
    ).join('');
  }

  document.addEventListener('click', (e) => {
    const btn = e.target.closest('[data-copy]');
    if (!btn) return;
    const text = btn.dataset.copy;
    const done = () => toast(`Copied ${text}`);
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(done, () => legacyCopy(text) && done());
    } else if (legacyCopy(text)) done();
  });

  function legacyCopy(text) {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.setAttribute('readonly', '');
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    let ok = false;
    try { ok = document.execCommand('copy'); } catch (e) { ok = false; }
    ta.remove();
    return ok;
  }

  // ---------- Lookup ----------
  function lookupCompute(ipText, maskText) {
    const comb = splitCombined(ipText);
    const ip = parseIP(comb.ip);
    if (ip === null) {
      return { error: comb.ip === '' ? 'Enter an IP address, like 192.168.1.130.' : `"${comb.ip}" isn't an IPv4 address. Use four numbers from 0 to 255 separated by dots.` };
    }
    const cls = classOf(ip);
    const mk = parseMask(comb.mask !== null ? comb.mask : maskText);
    if (mk.error) return { error: mk.error };
    let p, note = '';
    if (mk.empty) {
      if (cls.p !== null) { p = cls.p; note = `No mask entered, so this uses the Class ${cls.cls} default, /${p}.`; }
      else { p = 32; note = `No mask entered. Class ${cls.cls} addresses have no default mask, so this uses /32.`; }
    } else {
      p = mk.p;
      if (mk.kind === 'wildcard') note = `That looks like a wildcard mask, so this uses its inverse, ${maskStr(p)} (/${p}).`;
    }

    const size = P2(32 - p);
    const net = netOf(ip, p);
    const bc = net + size - 1;
    let first, last, usable, role, roleKind;
    if (p === 32) {
      first = last = net; usable = 1; roleKind = 'info';
      role = 'Single-host route (/32). The subnet is just this address.';
    } else if (p === 31) {
      first = net; last = bc; usable = 2; roleKind = 'info';
      role = "Point-to-point link (/31, RFC 3021). Both addresses are usable and there's no broadcast.";
    } else {
      first = net + 1; last = bc - 1; usable = size - 2;
      if (ip === net) { roleKind = 'bad'; role = "Network address. It names the subnet and can't be assigned to a device."; }
      else if (ip === bc) { roleKind = 'bad'; role = "Broadcast address. It reaches every host in the subnet and can't be assigned to a device."; }
      else { roleKind = 'ok'; role = `Usable host ${fmt(ip - net)} of ${fmt(usable)}.`; }
    }
    return { ip, p, size, net, bc, first, last, usable, role, roleKind, cls, special: classify(ip), note };
  }

  function addrBits(ip, p) {
    const io = octets(ip), mo = octets(maskInt(p));
    let html = `<div class="bits" role="img" aria-label="${ipStr(ip)} with mask /${p} in binary: ${p} network bits and ${32 - p} host bits">`;
    for (let o = 0; o < 4; o++) {
      let a = '', m = '';
      for (let j = 0; j < 8; j++) {
        const cls = o * 8 + j < p ? 'net' : 'hst';
        a += `<span class="bit ${cls}">${(io[o] >> (7 - j)) & 1}</span>`;
        m += `<span class="bit ${cls}">${o * 8 + j < p ? 1 : 0}</span>`;
      }
      html += `<div class="octet"><div class="obits">${a}</div><div class="obits mask">${m}</div><div class="odec"><b>${io[o]}</b><span>${mo[o]}</span></div></div>`;
    }
    return html + `</div><ul class="legend"><li><i class="sw net"></i>Network bits: ${p}</li><li><i class="sw hst"></i>Host bits: ${32 - p}</li><li>Top row is the address, bottom row is the mask</li></ul>`;
  }

  const REGISTRIES = { 'whois.arin.net': 'ARIN', 'whois.ripe.net': 'RIPE NCC', 'whois.apnic.net': 'APNIC', 'whois.lacnic.net': 'LACNIC', 'whois.afrinic.net': 'AFRINIC' };

  function vcardName(entity) {
    const card = entity && Array.isArray(entity.vcardArray) ? entity.vcardArray[1] : null;
    if (!Array.isArray(card)) return null;
    const fn = card.find((x) => Array.isArray(x) && x[0] === 'fn');
    return fn && fn[3] ? String(fn[3]) : null;
  }

  function parseRdap(d) {
    const rows = [];
    const ents = Array.isArray(d.entities) ? d.entities : [];
    const reg = ents.find((e) => Array.isArray(e.roles) && e.roles.includes('registrant'));
    const org = vcardName(reg);
    const desc = Array.isArray(d.remarks) ? d.remarks.find((r) => Array.isArray(r.description) && r.description.length) : null;
    if (org) rows.push(['Organization', org]);
    else if (desc) rows.push(['Description', desc.description[0]]);
    if (d.name) rows.push(['Network name', d.name]);
    if (d.startAddress && d.endAddress) rows.push(['Range', `${d.startAddress} – ${d.endAddress}`]);
    const cidrs = Array.isArray(d.cidr0_cidrs) ? d.cidr0_cidrs.filter((c) => c.v4prefix).map((c) => `${c.v4prefix}/${c.length}`) : [];
    if (cidrs.length) rows.push(['CIDR', cidrs.join(', ')]);
    if (d.country) rows.push(['Country', d.country]);
    const regEvent = Array.isArray(d.events) ? d.events.find((e) => e.eventAction === 'registration') : null;
    if (regEvent && regEvent.eventDate) rows.push(['Registered', String(regEvent.eventDate).slice(0, 10)]);
    const registry = REGISTRIES[String(d.port43 || '').toLowerCase()];
    if (registry) rows.push(['Registry', registry]);
    return rows;
  }

  function initLookup(solver) {
    const ipEl = $('lk-ip'), maskEl = $('lk-mask');
    const saved = store.get('lookup', { ip: '192.168.1.130', mask: '/26' });
    ipEl.value = typeof saved.ip === 'string' ? saved.ip : '';
    maskEl.value = typeof saved.mask === 'string' ? saved.mask : '';
    let current = null;
    let ownerIp = null;

    // Ranges reference table (static).
    $('lk-ranges').innerHTML = '<thead><tr><th scope="col">Range</th><th scope="col">Use</th></tr></thead><tbody>' +
      SPECIAL.filter((s) => s.p < 32).sort((a, b) => a.net - b.net).map((s) => `<tr><td>${s.cidr}</td><td>${esc(s.label)}</td></tr>`).join('') +
      '<tr><td>255.255.255.255/32</td><td>Limited broadcast (RFC 919)</td></tr></tbody>';

    function run() {
      const r = lookupCompute(ipEl.value, maskEl.value);
      current = r.error ? null : r;
      $('lk-error').hidden = !r.error;
      if (r.error) $('lk-error').textContent = r.error;
      $('lk-out').hidden = !!r.error;
      $('lk-note').hidden = !r.note;
      if (r.note) $('lk-note').textContent = r.note;
      if (!r.error) render(r);
      store.set('lookup', { ip: ipEl.value, mask: maskEl.value });
    }

    function render(r) {
      const s = r.special;
      $('lk-addr').innerHTML = `${ipStr(r.ip)}<span class="pfx">/${r.p}</span>`;
      const role = $('lk-role');
      role.className = 'role ' + r.roleKind;
      role.textContent = r.role;
      $('lk-badges').innerHTML = `<span class="badge ${s.kind}">${esc(s.label)}</span><span class="badge">Class ${r.cls.cls}</span>`;
      $('lk-type-note').textContent = s.note;

      const noBc = r.p >= 31;
      const wild = ipStr(MAX32 - 1 - maskInt(r.p));
      $('lk-subnet').innerHTML = kvRows([
        ['Network', `${ipStr(r.net)}<span class="pfx">/${r.p}</span>`, `${ipStr(r.net)}/${r.p}`],
        ['First usable', ipStr(r.first), ipStr(r.first)],
        ['Last usable', ipStr(r.last), ipStr(r.last)],
        ['Broadcast', noBc ? `<span class="muted">None at /${r.p}</span>` : ipStr(r.bc), noBc ? null : ipStr(r.bc)],
        ['Usable hosts', fmt(r.usable), null],
        ['Total addresses', fmt(r.size), null],
        ['Subnet mask', maskStr(r.p), maskStr(r.p)],
        ['Wildcard mask', wild, wild],
      ]);

      const prev = r.net > 0 ? r.net - r.size : null;
      const next = r.bc < MAX32 - 1 ? r.bc + 1 : null;
      const pb = $('lk-prev'), nb = $('lk-next');
      pb.hidden = prev === null;
      nb.hidden = next === null;
      if (prev !== null) { pb.querySelector('span').textContent = `${ipStr(prev)}/${r.p}`; pb.dataset.net = String(prev); }
      if (next !== null) { nb.querySelector('span').textContent = `${ipStr(next)}/${r.p}`; nb.dataset.net = String(next); }
      $('lk-split').hidden = !(r.p >= 8 && r.p <= 29);

      $('lk-bits').innerHTML = addrBits(r.ip, r.p);

      const o = octets(r.ip);
      const hex = o.map((v) => v.toString(16).toUpperCase().padStart(2, '0'));
      let classful = null;
      if (r.cls.p !== null) {
        const cp = r.cls.p, cnet = netOf(r.ip, cp);
        let text;
        if (r.p > cp) text = `Subnet ${fmt((r.net - cnet) / r.size + 1)} of ${fmt(P2(r.p - cp))} in ${ipStr(cnet)}/${cp} (${pl(r.p - cp, 'bit')} borrowed)`;
        else if (r.p === cp) text = `${ipStr(cnet)}/${cp}, the classful network itself`;
        else text = `Summary covering ${fmt(P2(cp - r.p))} classful /${cp} networks`;
        classful = ['Classful network', text, null];
      }
      const ptr = `${o[3]}.${o[2]}.${o[1]}.${o[0]}.in-addr.arpa`;
      $('lk-formats').innerHTML = kvRows([
        ['Class', `${r.cls.cls}${r.cls.p ? ` · default /${r.cls.p}` : r.cls.cls === 'D' ? ' · multicast' : ' · reserved'}`, null],
        classful,
        ['Hex', hex.join('.'), hex.join('.')],
        ['Hex (32-bit)', '0x' + hex.join(''), '0x' + hex.join('')],
        ['Decimal (32-bit)', String(r.ip), String(r.ip)],
        ['Reverse DNS name', ptr, ptr],
        ['IPv6-mapped', `::ffff:${ipStr(r.ip)}`, `::ffff:${ipStr(r.ip)}`],
      ]);

      const isPublic = s.kind === 'public';
      const ipText = ipStr(r.ip);
      $('lk-owner-btn').hidden = !isPublic;
      $('lk-owner-cap').textContent = isPublic
        ? 'Asks the regional internet registry who holds this address (ISP, company, or cloud provider). Sends the address to rdap.org.'
        : "Private and reserved addresses aren't registered to an owner, so there's nothing to look up.";
      if (ownerIp !== ipText) {
        ownerIp = null;
        $('lk-owner-out').hidden = true;
        $('lk-owner-out').innerHTML = '';
      }
    }

    async function lookupOwner() {
      const r = current;
      if (!r) return;
      const ip = ipStr(r.ip);
      const out = $('lk-owner-out'), btn = $('lk-owner-btn');
      btn.disabled = true;
      out.hidden = false;
      out.innerHTML = '<p class="cap">Looking up…</p>';
      ownerIp = ip;
      try {
        const res = await fetchTimeout('https://rdap.org/ip/' + ip, 12000);
        if (res.status === 404) throw new Error('No registry record was found for this address.');
        if (!res.ok) throw new Error(`The registry lookup failed (HTTP ${res.status}). Try again later.`);
        const d = await res.json();
        if (ownerIp !== ip) return;
        const rows = parseRdap(d);
        out.innerHTML = rows.length
          ? `<dl class="kv">${kvRows(rows.map(([l, v]) => [esc(l), esc(v), v]))}</dl>`
          : '<p class="cap">The registry returned no owner details for this address.</p>';
      } catch (e) {
        if (ownerIp !== ip) return;
        const msg = e.name === 'AbortError' ? 'The lookup timed out. Try again.'
          : e instanceof TypeError ? "Couldn't reach the registry. Check your connection."
          : e.message;
        out.innerHTML = `<p class="error">${esc(msg)}</p>`;
      } finally {
        btn.disabled = !navigator.onLine;
      }
    }

    function step(delta) {
      const comb = splitCombined(ipEl.value);
      if (comb.mask !== null) { ipEl.value = comb.ip; maskEl.value = comb.mask; }
      const mk = parseMask(maskEl.value);
      const p = mk.p !== undefined ? mk.p : current ? current.p : 24;
      maskEl.value = '/' + Math.max(0, Math.min(32, p + delta));
      run();
    }

    ipEl.addEventListener('input', run);
    maskEl.addEventListener('input', run);
    ipEl.addEventListener('change', () => {
      const comb = splitCombined(ipEl.value);
      if (comb.mask !== null && parseIP(comb.ip) !== null) { ipEl.value = comb.ip; maskEl.value = comb.mask; run(); }
    });
    $('lk-dec').addEventListener('click', () => step(-1));
    $('lk-inc').addEventListener('click', () => step(1));
    $('lk-owner-btn').addEventListener('click', lookupOwner);
    [$('lk-prev'), $('lk-next')].forEach((b) => b.addEventListener('click', () => {
      if (!current) return;
      ipEl.value = ipStr(Number(b.dataset.net));
      maskEl.value = '/' + current.p;
      run();
    }));
    $('lk-split').addEventListener('click', () => {
      if (!current) return;
      solver.setNetwork(ipStr(current.net), current.p);
      location.hash = '#subnets';
    });
    document.querySelectorAll('#lk-examples [data-ip]').forEach((b) => b.addEventListener('click', () => {
      ipEl.value = b.dataset.ip;
      maskEl.value = b.dataset.mask;
      run();
    }));
    function load(ip, mask) {
      ipEl.value = ip;
      maskEl.value = mask || '';
      run();
      location.hash = '#lookup';
    }

    $('lk-myip').addEventListener('click', async () => {
      const b = $('lk-myip');
      const label = b.textContent;
      b.disabled = true;
      b.textContent = 'Checking…';
      try {
        const res = await fetchTimeout('https://api.ipify.org?format=json', 8000);
        const d = await res.json();
        if (!d || parseIP(d.ip) === null) throw new Error('bad response');
        ipEl.value = d.ip;
        maskEl.value = '';
        run();
        toast(`Your public IP is ${d.ip}`);
      } catch (e) {
        toast("Couldn't reach the public IP service. Check your connection.");
      } finally {
        b.textContent = label;
        b.disabled = !navigator.onLine;
      }
    });

    run();
    return { load };
  }

  // ---------- Device check ----------
  function checkCompute(ipT, maskT, gwT) {
    const ipIn = ipT.trim(), gwIn = gwT.trim();
    const ip = parseIP(ipIn);
    if (ip === null) return { error: ipIn ? `"${ipIn}" isn't an IPv4 address. Use four numbers from 0 to 255 separated by dots.` : 'Enter the device IP address.' };
    const mk = parseMask(maskT);
    if (mk.empty) return { error: 'Enter the subnet mask, like 255.255.255.0 or /24.' };
    if (mk.error) return { error: mk.error };
    const gw = gwIn ? parseIP(gwIn) : null;
    if (gwIn && gw === null) return { error: `"${gwIn}" isn't an IPv4 address. Check the gateway.` };

    const p = mk.p, size = P2(32 - p), net = netOf(ip, p), bc = net + size - 1;
    const first = p >= 31 ? net : net + 1, last = p >= 31 ? bc : bc - 1;
    const range = `${ipStr(first)} – ${ipStr(last)}`;
    const items = [];
    const add = (s, html) => items.push({ s, html });

    if (mk.kind === 'wildcard') add('warn', `${esc(maskT.trim())} is a wildcard mask, the inverse of a subnet mask. Devices need the subnet mask <b>${maskStr(p)}</b>.`);
    else add('ok', `Mask <b>${maskStr(p)}</b> is valid (/${p}).`);

    const sp = classify(ip);
    if (sp.kind === 'warn') add('bad', `<b>${ipStr(ip)}</b> is a link-local (APIPA) address, so the device didn't get an address from DHCP. Check the cable, the VLAN, and the DHCP server.`);
    else if (sp.dev === 'bad') add('bad', `<b>${ipStr(ip)}</b> is in a ${esc(sp.label)} range and can't be a device address. ${esc(sp.note)}`);
    else if (sp.dev === 'warn') add('warn', `<b>${ipStr(ip)}</b> is in a ${esc(sp.label)} range. ${esc(sp.note)}`);

    if (p === 32) add('warn', 'A /32 mask leaves no other addresses in the subnet, so the device has no local neighbors and no gateway on its link.');
    else if (p === 31) add('ok', `/31 point-to-point link: ${range}, both usable (RFC 3021).`);
    else if (ip === net) add('bad', `<b>${ipStr(ip)}</b> is the network address of ${ipStr(net)}/${p}. Pick a host from ${range}.`);
    else if (ip === bc) add('bad', `<b>${ipStr(ip)}</b> is the broadcast address of ${ipStr(net)}/${p}. Pick a host from ${range}.`);
    else add('ok', `Device IP is usable host ${fmt(ip - net)} of ${fmt(size - 2)} in ${ipStr(net)}/${p}.`);

    if (!gwIn) {
      add('info', 'Enter the default gateway to check it too.');
    } else if (gw === ip) {
      add('bad', "The gateway is the device's own address. It should be the router's address on this subnet.");
    } else if (netOf(gw, p) !== net) {
      const cp = commonPrefix(ip, gw);
      add('bad', `Gateway <b>${ipStr(gw)}</b> is outside the device's subnet. The device is in ${ipStr(net)}/${p} (${range}), and the gateway falls in ${ipStr(netOf(gw, p))}/${p}. If the gateway is right, the mask would need to be /${cp} or shorter to include it.`);
    } else if (p <= 30 && (gw === net || gw === bc)) {
      add('bad', `Gateway <b>${ipStr(gw)}</b> is the ${gw === net ? 'network' : 'broadcast'} address. Use a host address from ${range}.`);
    } else {
      add('ok', `Gateway <b>${ipStr(gw)}</b> is in the same subnet.`);
      if (p <= 30 && gw === first) add('info', 'The gateway uses the first usable address, a common convention.');
      else if (p <= 30 && gw === last) add('info', 'The gateway uses the last usable address, a common convention.');
    }

    return {
      items, p, net, bc, first, last, size,
      bad: items.filter((i) => i.s === 'bad').length,
      warn: items.filter((i) => i.s === 'warn').length,
    };
  }

  function initCheck() {
    const ipEl = $('ck-ip'), maskEl = $('ck-mask'), gwEl = $('ck-gw');
    const saved = store.get('check', { ip: '10.20.30.40', mask: '255.255.255.0', gw: '10.20.30.1' });
    ipEl.value = typeof saved.ip === 'string' ? saved.ip : '';
    maskEl.value = typeof saved.mask === 'string' ? saved.mask : '';
    gwEl.value = typeof saved.gw === 'string' ? saved.gw : '';
    const MARK = { ok: ['✓', 'OK'], bad: ['✕', 'Problem'], warn: ['!', 'Warning'], info: ['i', 'Note'] };

    function run() {
      const r = checkCompute(ipEl.value, maskEl.value, gwEl.value);
      $('ck-error').hidden = !r.error;
      if (r.error) $('ck-error').textContent = r.error;
      $('ck-out').hidden = !!r.error;
      store.set('check', { ip: ipEl.value, mask: maskEl.value, gw: gwEl.value });
      if (r.error) return;

      const v = $('ck-verdict');
      if (r.bad) { v.className = 'verdict bad'; v.textContent = `${pl(r.bad, 'problem')} found`; }
      else if (r.warn) { v.className = 'verdict warn'; v.textContent = `Usable, with ${pl(r.warn, 'warning')}`; }
      else { v.className = 'verdict ok'; v.textContent = 'Settings look good'; }

      $('ck-list').innerHTML = r.items.map((i) =>
        `<li><span class="mark ${i.s}" aria-hidden="true">${MARK[i.s][0]}</span><p><span class="sr">${MARK[i.s][1]}: </span>${i.html}</p></li>`
      ).join('');

      const noBc = r.p >= 31;
      $('ck-subnet').innerHTML = kvRows([
        ['Network', `${ipStr(r.net)}<span class="pfx">/${r.p}</span>`, `${ipStr(r.net)}/${r.p}`],
        ['Usable range', `${ipStr(r.first)} – ${ipStr(r.last)}`, null],
        ['Broadcast', noBc ? `<span class="muted">None at /${r.p}</span>` : ipStr(r.bc), noBc ? null : ipStr(r.bc)],
        ['Usable hosts', fmt(r.p === 32 ? 1 : r.p === 31 ? 2 : r.size - 2), null],
      ]);
    }

    [ipEl, maskEl, gwEl].forEach((el) => el.addEventListener('input', run));
    document.querySelectorAll('[data-check]').forEach((b) => b.addEventListener('click', () => {
      const [a, m, g] = b.dataset.check.split('|');
      ipEl.value = a; maskEl.value = m; gwEl.value = g;
      run();
    }));
    run();
    return {
      load(ip, mask, gw) {
        ipEl.value = ip; maskEl.value = mask; gwEl.value = gw || '';
        run();
        location.hash = '#check';
      },
    };
  }

  // ---------- Scan ----------
  const ROLE_LABEL = { ip: 'IP address', mask: 'Mask', gateway: 'Gateway', dns: 'DNS server', dhcp: 'DHCP server', broadcast: 'Broadcast', address: 'Address' };
  const ROLE_CLASS = { ip: 'private', mask: '', gateway: 'special', dns: 'public', dhcp: '', broadcast: '', address: '' };
  // Checked in order against the words just before each address on its line.
  const ROLE_WORDS = [
    ['dhcp', /dhcp/i],
    ['dns', /dns|name ?server/i],
    ['gateway', /gateway|default via|\bvia\b|\bgw\b|router|next.?hop/i],
    ['mask', /mask/i],
    ['broadcast', /broadcast|\bbrd\b|bcast/i],
    ['ip', /ipv4|ip address|\binet\b|\baddr(ess)?\b|\bip\b/i],
  ];
  const IP_IN_TEXT = /(^|[^\d])(\d{1,3}) ?[.,] ?(\d{1,3}) ?[.,] ?(\d{1,3}) ?[.,] ?(\d{1,3})(?: ?\/ ?(\d{1,2}))?(?!\d)/g;

  // Fix common OCR mix-ups (O→0, l→1, S→5, B→8) inside runs that look like addresses.
  function fixOcr(line) {
    return line.replace(/[0-9OoIl|SB][0-9OoIl|SB.,]{6,}/g, (tok) =>
      (tok.match(/[.,]/g) || []).length >= 3 && (tok.match(/\d/g) || []).length >= 4
        ? tok.replace(/[Oo]/g, '0').replace(/[Il|]/g, '1').replace(/S/g, '5').replace(/B/g, '8')
        : tok);
  }

  function extractIPs(text) {
    const items = [];
    const seen = new Set();
    let last = null;
    text.split(/\r?\n/).forEach((raw, lineNo) => {
      const line = fixOcr(raw);
      IP_IN_TEXT.lastIndex = 0;
      let m, prevEnd = 0;
      const lineHits = [];
      while ((m = IP_IN_TEXT.exec(line))) {
        const start = m.index + m[1].length;
        const octs = [m[2], m[3], m[4], m[5]].map(Number);
        const prefix = m[6] !== undefined ? Number(m[6]) : null;
        if (octs.some((o) => o > 255) || (prefix !== null && prefix > 32)) { prevEnd = IP_IN_TEXT.lastIndex; continue; }
        const n = ((octs[0] * 256 + octs[1]) * 256 + octs[2]) * 256 + octs[3];
        const before = line.slice(prevEnd, start);
        let role = null;
        for (const [r, re] of ROLE_WORDS) if (re.test(before)) { role = r; break; }
        if (!role) {
          const onlyThis = line.replace(m[0].slice(m[1].length), '').replace(/[\s:.,()\[\]-]/g, '') === '';
          const mp = prefix === null ? prefixOfMask(n) : -1;
          if (onlyThis && last && last.lineNo === lineNo - 1 && !/[a-z]/i.test(before)) role = last.role;
          else if (mp >= 8) role = 'mask';
          else role = 'address';
        }
        lineHits.push({ n, prefix, role, lineNo, line: raw });
        prevEnd = IP_IN_TEXT.lastIndex;
      }
      lineHits.forEach((h) => {
        const key = `${h.role}|${h.n}|${h.prefix}`;
        last = h;
        if (seen.has(key)) return;
        seen.add(key);
        items.push(h);
      });
    });
    return items;
  }

  function settingsFrom(items) {
    const ipIdx = items.findIndex((i) => i.role === 'ip' && Math.floor(i.n / 16777216) !== 127 && prefixOfMask(i.n) < 8);
    if (ipIdx < 0) return null;
    const ipItem = items[ipIdx];
    const after = items.slice(ipIdx + 1);
    let mask = ipItem.prefix !== null ? '/' + ipItem.prefix : null;
    if (!mask) { const mi = after.find((i) => i.role === 'mask'); if (mi) mask = ipStr(mi.n); }
    if (!mask) return null;
    const gw = after.find((i) => i.role === 'gateway') || items.find((i) => i.role === 'gateway');
    return { ip: ipStr(ipItem.n), mask, gw: gw ? ipStr(gw.n) : '' };
  }

  const SCAN_EXAMPLE = `Windows IP Configuration

Wireless LAN adapter Wi-Fi:

   Connection-specific DNS Suffix  . : lan
   IPv4 Address. . . . . . . . . . . : 192.168.1.50
   Subnet Mask . . . . . . . . . . . : 255.255.255.192
   Default Gateway . . . . . . . . . : 192.168.1.65
   DNS Servers . . . . . . . . . . . : 1.1.1.1
                                       8.8.8.8`;

  function initScan(lookup, check) {
    const TESSERACT_URL = 'https://cdn.jsdelivr.net/npm/tesseract.js@5.1.1/dist/tesseract.min.js';
    const STATUS = {
      'loading tesseract core': 'Downloading the text engine',
      'initializing tesseract': 'Starting the text engine',
      'loading language traineddata': 'Downloading English language data',
      'loaded language traineddata': 'Starting the text engine',
      'initializing api': 'Starting the text engine',
      'recognizing text': 'Reading text',
    };
    const textEl = $('sc-text');
    let workerP = null;
    let previewUrl = null;
    let busy = false;
    let items = [];
    let found = null;
    let timer = 0;

    function showProgress(label, frac) {
      $('sc-progress').hidden = false;
      $('sc-status').textContent = `${label}${frac > 0 ? ` ${Math.round(frac * 100)}%` : ''}`;
      $('sc-bar').value = frac;
    }

    function loadScript(src) {
      return new Promise((resolve, reject) => {
        const el = document.createElement('script');
        el.src = src;
        el.onload = resolve;
        el.onerror = () => reject(new Error('script'));
        document.head.appendChild(el);
      });
    }

    function getWorker() {
      if (!workerP) {
        workerP = (async () => {
          if (!window.Tesseract) await loadScript(TESSERACT_URL);
          const w = await window.Tesseract.createWorker('eng', 1, {
            logger: (m) => showProgress((STATUS[m.status] || 'Working') + '…', m.progress || 0),
          });
          await w.setParameters({ preserve_interword_spaces: '1' });
          return w;
        })().catch((e) => { workerP = null; throw e; });
      }
      return workerP;
    }

    // Grayscale, stretch contrast, and turn light-on-dark screens into dark-on-light text.
    async function prepImage(url) {
      const img = await new Promise((resolve, reject) => {
        const i = new Image();
        i.onload = () => resolve(i);
        i.onerror = () => reject(new Error('decode'));
        i.src = url;
      });
      const scale = Math.min(2, 2000 / Math.max(img.naturalWidth, img.naturalHeight));
      const w = Math.max(1, Math.round(img.naturalWidth * scale));
      const h = Math.max(1, Math.round(img.naturalHeight * scale));
      const c = document.createElement('canvas');
      c.width = w;
      c.height = h;
      const ctx = c.getContext('2d', { willReadFrequently: true });
      ctx.drawImage(img, 0, 0, w, h);
      const im = ctx.getImageData(0, 0, w, h);
      const px = im.data;
      const hist = new Uint32Array(256);
      let sum = 0;
      for (let i = 0; i < px.length; i += 4) {
        const y = ((px[i] * 299 + px[i + 1] * 587 + px[i + 2] * 114) / 1000) | 0;
        px[i] = y;
        hist[y]++;
        sum += y;
      }
      const count = px.length / 4;
      const invert = sum / count < 110;
      let lo = 0, hi = 255, acc = 0;
      for (let v = 0; v < 256; v++) { acc += hist[v]; if (acc >= count * 0.02) { lo = v; break; } }
      acc = 0;
      for (let v = 255; v >= 0; v--) { acc += hist[v]; if (acc >= count * 0.02) { hi = v; break; } }
      const range = Math.max(1, hi - lo);
      for (let i = 0; i < px.length; i += 4) {
        let y = Math.max(0, Math.min(255, ((px[i] - lo) * 255) / range));
        if (invert) y = 255 - y;
        px[i] = px[i + 1] = px[i + 2] = y;
      }
      ctx.putImageData(im, 0, 0);
      return c;
    }

    async function scanFile(file) {
      if (!file || busy) return;
      busy = true;
      $('sc-error').hidden = true;
      if (previewUrl) URL.revokeObjectURL(previewUrl);
      previewUrl = URL.createObjectURL(file);
      $('sc-preview').src = previewUrl;
      $('sc-preview').hidden = false;
      showProgress('Preparing the photo…', 0);
      try {
        const canvas = await prepImage(previewUrl);
        const worker = await getWorker();
        showProgress('Reading text…', 0);
        const { data } = await worker.recognize(canvas);
        textEl.value = String(data.text || '').replace(/\n{3,}/g, '\n\n').trim();
        update();
        if (!items.length) toast('No addresses found. Try a closer, straighter photo.');
      } catch (e) {
        const err = $('sc-error');
        err.textContent = e.message === 'decode'
          ? "That file couldn't be opened as an image. Try a JPEG or PNG."
          : navigator.onLine
            ? "Couldn't read the photo. Try again, or paste the text instead."
            : "The text engine isn't on this device yet. Connect to the internet and scan once; after that it works offline.";
        err.hidden = false;
      } finally {
        busy = false;
        $('sc-progress').hidden = true;
        $('sc-camera').value = '';
        $('sc-file').value = '';
      }
    }

    function maskFor(idx) {
      const it = items[idx];
      if (it.prefix !== null) return '/' + it.prefix;
      if (it.role !== 'ip') return '';
      const mi = items.slice(idx + 1).find((i) => i.role === 'mask' || i.role === 'ip');
      return mi && mi.role === 'mask' ? ipStr(mi.n) : '';
    }

    function update() {
      const text = textEl.value;
      items = extractIPs(text);
      found = settingsFrom(items);
      const has = items.length > 0;
      $('sc-out').hidden = !has;
      $('sc-none').hidden = has || text.trim() === '';
      $('sc-suggest').hidden = !found;
      if (found) {
        $('sc-suggest-kv').innerHTML = kvRows([
          ['IP address', found.ip, null],
          ['Mask', found.mask, null],
          ['Gateway', found.gw || '<span class="muted">Not found</span>', null],
        ]);
      }
      $('sc-count').textContent = `${fmt(items.length)} ${items.length === 1 ? 'address' : 'addresses'} found`;
      $('sc-hits').innerHTML = items.map((it, i) => {
        const val = ipStr(it.n) + (it.prefix !== null ? `/${it.prefix}` : '');
        const ctx = it.line.replace(/(\s*\.){3,}\s*/g, ' … ').trim();
        return `<li class="hit"><div class="top"><span class="badge ${ROLE_CLASS[it.role]}">${ROLE_LABEL[it.role]}</span><span class="val">${val}</span></div>` +
          `<div class="acts">${it.role !== 'mask' ? `<button type="button" class="btn small" data-hit="${i}">Look up</button>` : ''}<button type="button" class="btn small" data-copy="${val}">Copy</button></div>` +
          `<div class="ctx">${esc(ctx)}</div></li>`;
      }).join('');
    }

    textEl.addEventListener('input', () => { clearTimeout(timer); timer = setTimeout(update, 200); });
    $('sc-camera').addEventListener('change', (e) => scanFile(e.target.files && e.target.files[0]));
    $('sc-file').addEventListener('change', (e) => scanFile(e.target.files && e.target.files[0]));
    $('sc-example').addEventListener('click', () => { textEl.value = SCAN_EXAMPLE; update(); });
    $('sc-clear').addEventListener('click', () => {
      textEl.value = '';
      $('sc-preview').hidden = true;
      $('sc-error').hidden = true;
      update();
    });
    $('sc-hits').addEventListener('click', (e) => {
      const b = e.target.closest('[data-hit]');
      if (!b) return;
      const i = Number(b.dataset.hit);
      lookup.load(ipStr(items[i].n), maskFor(i));
    });
    $('sc-check').addEventListener('click', () => { if (found) check.load(found.ip, found.mask, found.gw); });
    update();
  }

  // ---------- Subnet solver ----------
  function initSolver() {
    const MIN_P = 8, MAX_P = 30, PAGE = 8, STEP = 16;
    const state = { ip: '172.16.0.0', prefix: 16, mode: 'subnets', needSubnets: 50, needHosts: 500, shown: PAGE };
    const s = store.get('solver', null);
    if (s && typeof s === 'object') {
      if (typeof s.ip === 'string') state.ip = s.ip;
      if (Number.isInteger(s.prefix) && s.prefix >= MIN_P && s.prefix <= MAX_P) state.prefix = s.prefix;
      if (s.mode === 'subnets' || s.mode === 'hosts') state.mode = s.mode;
      if (Number.isInteger(s.needSubnets) && s.needSubnets > 0) state.needSubnets = s.needSubnets;
      if (Number.isInteger(s.needHosts) && s.needHosts > 0) state.needHosts = s.needHosts;
    }
    const save = () => store.set('solver', { ip: state.ip, prefix: state.prefix, mode: state.mode, needSubnets: state.needSubnets, needHosts: state.needHosts });

    const maskOctets = (p) => [0, 1, 2, 3].map((i) => 256 - P2(8 - Math.max(0, Math.min(8, p - 8 * i))));
    function octetOf(p) {
      const k = Math.ceil(p / 8) - 1;
      const bitsIn = p - 8 * k;
      return { k, bitsIn, mask: 256 - P2(8 - bitsIn), inc: P2(8 - bitsIn) };
    }

    function compute() {
      const base = state.prefix;
      const ip = parseIP(state.ip);
      if (ip === null) return { base, error: 'Enter the network as four numbers from 0 to 255 separated by dots, like 172.16.0.0.' };
      const net = netOf(ip, base);
      const r = { base, ip, net, adjusted: net !== ip, mode: state.mode };
      if (state.mode === 'subnets') {
        const S = state.needSubnets;
        if (!(Number.isInteger(S) && S >= 1)) return { ...r, error: 'Enter how many subnets you need, as a whole number of 1 or more.' };
        let n = 0;
        while (P2(n) < S) n++;
        r.need = S; r.n = n; r.p = base + n;
        if (r.p > MAX_P) {
          return { ...r, error: `Borrowing ${n} bits from /${base} gives /${r.p}, which leaves fewer than 2 host bits and no usable hosts. A /${base} can make at most ${fmt(P2(MAX_P - base))} subnets that still have usable hosts (borrow ${MAX_P - base} bits for /${MAX_P}).` };
        }
      } else {
        const H = state.needHosts;
        if (!(Number.isInteger(H) && H >= 1)) return { ...r, error: 'Enter how many hosts each subnet needs, as a whole number of 1 or more.' };
        const maxH = P2(32 - base) - 2;
        if (H > maxH) return { ...r, error: `A /${base} network has only ${fmt(maxH)} usable hosts in total, so ${fmt(H)} hosts won't fit in one subnet. Use a shorter prefix or fewer hosts.` };
        let h = 2;
        while (P2(h) - 2 < H) h++;
        r.need = H; r.h = h; r.p = 32 - h; r.n = r.p - base;
      }
      r.hostBits = 32 - r.p;
      r.subnets = P2(r.n);
      r.size = P2(r.hostBits);
      r.usable = r.size - 2;
      r.oct = octetOf(r.p);
      r.mask = maskOctets(r.p).join('.');
      return r;
    }

    const bitClass = (r, i) => (i < r.base ? 'net' : i < r.p ? 'brw' : 'hst');

    function renderAnswer(r) {
      const sub = r.mode === 'subnets';
      $('sv-answer-line').innerHTML = sub
        ? `To get ${pl(r.need, 'subnet')} from <b>${ipStr(r.net)}/${r.base}</b>, borrow <b>${pl(r.n, 'bit')}</b> for a <b>/${r.p}</b> prefix.`
        : `To fit ${pl(r.need, 'host')} in each subnet of <b>${ipStr(r.net)}/${r.base}</b>, keep <b>${r.h} host bits</b> for a <b>/${r.p}</b> prefix.`;
      const items = [
        ['New prefix', '/' + r.p, '', 'key'],
        ['Subnet mask', r.mask, '', 'wide'],
        ['Increment', fmt(r.oct.inc), ORD[r.oct.k] + ' octet', ''],
        ['Borrowed bits', String(r.n), '', ''],
        ['Subnets', fmt(r.subnets), sub ? 'need ' + fmt(r.need) : '', sub ? 'key' : ''],
        ['Host bits', String(r.hostBits), '', ''],
        ['Usable hosts', fmt(r.usable), sub ? 'per subnet' : 'need ' + fmt(r.need), sub ? '' : 'key'],
      ];
      $('sv-stats').innerHTML = items.map(([label, val, sub2, cls]) =>
        `<div class="stat ${cls}"><dt>${label}</dt><dd>${val}</dd>${sub2 ? `<dd class="sub">${sub2}</dd>` : ''}</div>`
      ).join('');
    }

    function ladder(r) {
      const sub = r.mode === 'subnets';
      const first = sub ? 0 : 2;
      const end = sub ? r.n : r.h;
      const start = Math.max(first, end - 4);
      let html = start > first ? '<li class="rung skip" aria-hidden="true">…</li>' : '';
      for (let i = start; i <= end; i++) {
        const v = sub ? P2(i) : P2(i) - 2;
        const ok = v >= r.need;
        const eq = sub ? `${pow(2, i)} = ${fmt(v)}` : `${pow(2, i)} − 2 = ${fmt(v)}`;
        html += `<li class="rung ${ok ? 'ok' : 'low'}"><span class="eq">${eq}</span><span class="tag">${ok ? 'Enough' : 'Too few'}</span></li>`;
      }
      return `<ul class="ladder">${html}</ul>`;
    }

    function bitsViz(r) {
      const mo = maskOctets(r.p);
      let html = `<div class="bits" role="img" aria-label="Mask /${r.p} in binary: ${r.base} network bits, ${r.n} borrowed bits, ${r.hostBits} host bits">`;
      for (let o = 0; o < 4; o++) {
        html += '<div class="octet"><div class="obits">';
        for (let j = 0; j < 8; j++) {
          const i = o * 8 + j;
          html += `<span class="bit ${bitClass(r, i)}">${i < r.p ? 1 : 0}</span>`;
        }
        html += `</div><div class="odec"><span>${ORD[o]}</span><b>${mo[o]}</b></div></div>`;
      }
      html += '</div>';
      html += `<ul class="legend"><li><i class="sw net"></i>Network bits: ${r.base}</li><li><i class="sw brw"></i>Borrowed: ${r.n}</li><li><i class="sw hst"></i>Host bits: ${r.hostBits}</li></ul>`;
      return html;
    }

    function octetBreakdown(r) {
      const { k, bitsIn, mask } = r.oct;
      let head = '', row = '';
      const ones = [];
      for (let j = 0; j < 8; j++) {
        const i = k * 8 + j;
        const on = i < r.p;
        head += `<th scope="col">${BITVAL[j]}</th>`;
        row += `<td class="bit ${bitClass(r, i)}${j === bitsIn - 1 ? ' last' : ''}">${on ? 1 : 0}</td>`;
        if (on) ones.push(BITVAL[j]);
      }
      return `<div class="scroll"><table class="obreak"><thead><tr>${head}</tr></thead><tbody><tr>${row}</tr></tbody></table></div>` +
        `<p class="sum">${ones.join(' + ')} = <b>${mask}</b></p>`;
    }

    function tableHelp(r) {
      const { k, mask: mv, inc } = r.oct;
      const o = ORD[k];
      const inHostTable = k >= 1;
      if (r.mode === 'subnets') {
        return `<p><b>Subnets table:</b> go down from /${r.base} until <i># of subnets</i> reaches ${fmt(r.need)}. The first row that does is <b>/${r.p}</b> (NET + ${r.n}, ${fmt(r.subnets)} subnets).</p>` +
          (inHostTable ? `<p><b>Hosts table:</b> find /${r.p} in the ${o} row and read down its column: SM ${mv}, INC ${inc}, and ${fmt(r.size)} addresses per subnet in the <i># in ${o}</i> row.</p>` : '');
      }
      return (inHostTable ? `<p><b>Hosts table:</b> each subnet needs ${fmt(r.need)} + 2 = ${fmt(r.need + 2)} addresses. The smallest <i>#</i> value that covers it is <b>${fmt(r.size)}</b> in the <i># in ${o}</i> row. Read up its column: /${r.p}, SM ${mv}, INC ${inc}.</p>` : '') +
        `<p><b>Subnets table:</b> the /${r.p} row shows NET + ${r.n}, ${fmt(r.subnets)} subnets, and ${fmt(r.usable)} usable hosts.</p>`;
    }

    const maskStep = (r, o) => `${bitsViz(r)}<p>The prefix ends in the <b>${o} octet</b>. Add up the bit values that are 1 in that octet:</p>${octetBreakdown(r)}<p class="calc">Mask = <b>${r.mask}</b></p>`;
    const incStep = (mv, inc, o) => `<p>The increment is the value of the last 1 bit (outlined above): <b>${inc}</b>. Check: 256 − ${mv} = ${inc}.</p><p>A new subnet starts every ${inc} in the ${o} octet.</p>`;

    function stepsHTML(r) {
      const { k, mask: mv, inc } = r.oct;
      const o = ORD[k];
      const steps = [];
      if (r.mode === 'subnets') {
        steps.push(['Find how many bits to borrow',
          `<p>Each borrowed bit doubles the number of subnets, so borrowing <var>n</var> bits makes ${pow(2, '<var>n</var>')} subnets. Find the smallest <var>n</var> where ${pow(2, '<var>n</var>')} ≥ ${fmt(r.need)}.</p>${ladder(r)}<p>Borrow <b>${pl(r.n, 'bit')}</b>.</p>`]);
        steps.push(['Add them to the prefix', `<p class="calc">/${r.base} + ${r.n} = <b>/${r.p}</b></p>`]);
        steps.push(['Write out the mask', maskStep(r, o)]);
        steps.push(['Find the increment', incStep(mv, inc, o)]);
        steps.push(['Count subnets and hosts',
          `<p class="calc">Subnets = ${pow(2, r.n)} = <b>${fmt(r.subnets)}</b><span class="aside">need ${fmt(r.need)}, ${fmt(r.subnets - r.need)} spare</span></p>` +
          `<p class="calc">Host bits = 32 − ${r.p} = ${r.hostBits}</p>` +
          `<p class="calc">Usable hosts = ${pow(2, r.hostBits)} − 2 = <b>${fmt(r.usable)}</b></p>`]);
      } else {
        steps.push(['Find how many host bits to keep',
          `<p>With <var>h</var> host bits, a subnet has ${pow(2, '<var>h</var>')} − 2 usable hosts, because the network and broadcast addresses can't be assigned. Find the smallest <var>h</var> where ${pow(2, '<var>h</var>')} − 2 ≥ ${fmt(r.need)}.</p>${ladder(r)}<p>Keep <b>${r.h} host bits</b>.</p>`]);
        steps.push(['Find the new prefix', `<p class="calc">32 − ${r.h} = <b>/${r.p}</b></p>`]);
        steps.push(['Count the borrowed bits',
          `<p class="calc">/${r.p} − /${r.base} = <b>${pl(r.n, 'borrowed bit')}</b></p>` +
          (r.n === 0 ? `<p>Nothing is borrowed, so the whole /${r.base} stays one subnet.</p>` : '')]);
        steps.push(['Write out the mask', maskStep(r, o)]);
        steps.push(['Find the increment', incStep(mv, inc, o)]);
        steps.push(['Count subnets and hosts',
          `<p class="calc">Usable hosts = ${pow(2, r.h)} − 2 = <b>${fmt(r.usable)}</b><span class="aside">need ${fmt(r.need)}, ${fmt(r.usable - r.need)} spare</span></p>` +
          `<p class="calc">Subnets = ${pow(2, r.n)} = <b>${fmt(r.subnets)}</b></p>`]);
      }
      steps.push(['Find it in the tables', tableHelp(r)]);
      return steps.map(([t, b]) => `<li><h3>${t}</h3><div class="step-body">${b}</div></li>`).join('');
    }

    function renderList(r) {
      const total = r.subnets;
      const shown = Math.min(state.shown, total);
      const row = (i) => {
        const a = r.net + i * r.size;
        return `<div class="srow"><span class="idx">${fmt(i + 1)}</span><span class="net">${ipStr(a, r.oct.k)}<span class="pfx">/${r.p}</span></span><span class="bc">${ipStr(a + r.size - 1)}</span><span class="rng">${ipStr(a + 1)} – ${ipStr(a + r.size - 2)}</span></div>`;
      };
      let html = '<div class="srow hdr"><span class="idx">#</span><span class="net">Network</span><span class="bc">Broadcast</span><span class="rng">Usable hosts</span></div>';
      for (let i = 0; i < shown; i++) html += row(i);
      const left = total - shown - 1;
      if (shown < total) {
        if (left > 0) html += `<div class="sgap">${pl(left, 'more subnet')}</div>`;
        html += row(total - 1);
      }
      $('sv-sublist').innerHTML = html;
      $('sv-list-cap').textContent = `${pl(total, 'subnet')}, ${fmt(r.size)} addresses each. The highlighted octet counts up by ${r.oct.inc}.`;
      const more = $('sv-more');
      more.hidden = left <= 0;
      more.textContent = `Show ${fmt(Math.min(STEP, Math.max(left, 0)))} more`;
    }

    function renderHostTable(r) {
      const base = state.prefix;
      const p = r ? r.p : null;
      const hiCol = r ? r.oct.bitsIn - 1 : -1;
      const hiOct = r ? r.oct.k : -1;
      const octs = (base < 16 || (p !== null && p <= 16)) ? [1, 2, 3] : [2, 3];
      const rows = [];
      octs.forEach((o) => rows.push({ label: ORD[o], hi: o === hiOct, pfx: true, vals: BITVAL.map((_, j) => o * 8 + j + 1) }));
      rows.push({ label: 'SM', hi: true, split: true, vals: BITVAL.map((_, j) => 256 - P2(7 - j)) });
      rows.push({ label: 'INC', hi: true, vals: BITVAL.map((_, j) => P2(7 - j)) });
      octs.forEach((o, idx) => rows.push({ label: '# in ' + ORD[o], hi: o === hiOct, split: idx === 0, vals: BITVAL.map((_, j) => P2(7 - j) * P2(8 * (3 - o))) }));

      $('sv-tbl-host').innerHTML = '<tbody>' + rows.map((row) => {
        const cells = row.vals.map((v, j) => {
          const c = [];
          if (j === hiCol) c.push(row.hi ? 'cell-hi' : 'col-hi');
          if (row.pfx && v < base) c.push('off');
          return `<td${c.length ? ` class="${c.join(' ')}"` : ''}>${row.pfx ? '/' + v : v}</td>`;
        }).join('');
        return `<tr${row.split ? ' class="split"' : ''}><th scope="row">${row.label}</th>${cells}</tr>`;
      }).join('') + '</tbody>';

      // On narrow screens, scroll the highlighted column into view.
      const sc = $('sv-host-scroll');
      const hc = sc.querySelector('.cell-hi');
      if (hc && sc.scrollWidth > sc.clientWidth) {
        const th = sc.querySelector('tbody th');
        const lw = th ? th.offsetWidth : 0;
        sc.scrollLeft = Math.max(0, hc.offsetLeft - lw - (sc.clientWidth - lw - hc.offsetWidth) / 2);
      }
    }

    function renderSubTable(r, any) {
      const base = state.prefix;
      $('sv-sub-title').textContent = `Subnets table · ${any.net !== undefined ? ipStr(any.net) : 'network'}/${base}`;
      let html = '<thead><tr><th scope="col">CIDR</th><th scope="col">Borrowed bits</th><th scope="col"># of subnets</th><th scope="col">Usable hosts</th></tr></thead><tbody>';
      for (let c = base; c <= MAX_P; c++) {
        html += `<tr${r && c === r.p ? ' class="row-hi"' : ''}><td>${c}</td><td>NET + ${c - base}</td><td>${P2(c - base)}</td><td>${P2(32 - c) - 2}</td></tr>`;
      }
      $('sv-tbl-sub').innerHTML = html + '</tbody>';
    }

    function render() {
      const r = compute();
      const ok = !r.error;
      const note = $('sv-note');
      note.hidden = !(r.net !== undefined && r.adjusted);
      if (!note.hidden) note.innerHTML = `${ipStr(r.ip)} isn't the first address of a /${r.base}. Using its network address, <b>${ipStr(r.net)}</b>.`;
      const err = $('sv-error');
      err.hidden = ok;
      if (!ok) err.textContent = r.error;
      ['sv-answer', 'sv-math', 'sv-list-sec'].forEach((id) => { $(id).hidden = !ok; });
      if (ok) {
        renderAnswer(r);
        $('sv-steps').innerHTML = stepsHTML(r);
        renderList(r);
      }
      $('sv-tstack').dataset.mode = state.mode;
      renderHostTable(ok ? r : null);
      renderSubTable(ok ? r : null, r);
    }

    const ipEl = $('sv-ip'), prefixEl = $('sv-prefix'), needEl = $('sv-need');
    for (let c = MIN_P; c <= MAX_P; c++) prefixEl.add(new Option('/' + c, String(c)));

    function syncInputs() {
      ipEl.value = state.ip;
      prefixEl.value = String(state.prefix);
      $('sv-mode-' + state.mode).checked = true;
      const v = state.mode === 'subnets' ? state.needSubnets : state.needHosts;
      needEl.value = Number.isFinite(v) ? String(v) : '';
      $('sv-need-label').textContent = state.mode === 'subnets' ? 'Subnets needed' : 'Hosts needed per subnet';
    }

    function update() {
      state.shown = PAGE;
      render();
      save();
    }

    ipEl.addEventListener('input', () => {
      let v = ipEl.value;
      const m = v.match(/^\s*([\d.]+)\s*\/\s*(\d{1,2})\s*$/);
      if (m) {
        const pf = Number(m[2]);
        if (pf >= MIN_P && pf <= MAX_P) {
          v = m[1];
          ipEl.value = v;
          state.prefix = pf;
          prefixEl.value = String(pf);
        }
      }
      state.ip = v;
      update();
    });
    prefixEl.addEventListener('change', () => { state.prefix = Number(prefixEl.value); update(); });
    needEl.addEventListener('input', () => {
      const v = needEl.value.trim() === '' ? NaN : Number(needEl.value);
      if (state.mode === 'subnets') state.needSubnets = v; else state.needHosts = v;
      update();
    });
    document.querySelectorAll('input[name="sv-mode"]').forEach((el) => {
      el.addEventListener('change', () => { state.mode = el.value; syncInputs(); update(); });
    });
    document.querySelectorAll('[data-net]').forEach((b) => {
      b.addEventListener('click', () => {
        const [a, c] = b.dataset.net.split('/');
        state.ip = a;
        state.prefix = Number(c);
        syncInputs();
        update();
      });
    });
    $('sv-more').addEventListener('click', () => { state.shown += STEP; render(); });

    syncInputs();
    render();

    return {
      render,
      setNetwork(ip, prefix) {
        state.ip = ip;
        state.prefix = Math.max(MIN_P, Math.min(MAX_P, prefix));
        syncInputs();
        update();
      },
    };
  }

  // ---------- App shell ----------
  const solver = initSolver();
  const lookup = initLookup(solver);
  const check = initCheck();
  initScan(lookup, check);

  const VIEWS = ['lookup', 'scan', 'check', 'subnets'];
  function route() {
    let v = location.hash.slice(1);
    if (!VIEWS.includes(v)) v = store.get('view', 'lookup');
    if (!VIEWS.includes(v)) v = 'lookup';
    VIEWS.forEach((name) => { $('view-' + name).hidden = name !== v; });
    document.querySelectorAll('.tab').forEach((a) => {
      if (a.dataset.view === v) a.setAttribute('aria-current', 'page');
      else a.removeAttribute('aria-current');
    });
    store.set('view', v);
    if (v === 'subnets') solver.render();
    window.scrollTo(0, 0);
  }
  window.addEventListener('hashchange', route);
  route();

  function setOnline() {
    const on = navigator.onLine;
    $('net-status').hidden = on;
    document.querySelectorAll('[data-online]').forEach((b) => { b.disabled = !on; });
  }
  window.addEventListener('online', setOnline);
  window.addEventListener('offline', setOnline);
  setOnline();

  // Install button (Chrome, Edge, Android) and Add to Home Screen hint (iPhone, iPad).
  let installEvent = null;
  window.addEventListener('beforeinstallprompt', (e) => {
    e.preventDefault();
    installEvent = e;
    $('install').hidden = false;
  });
  $('install').addEventListener('click', async () => {
    if (!installEvent) return;
    installEvent.prompt();
    try { await installEvent.userChoice; } catch (e) { /* ignore */ }
    installEvent = null;
    $('install').hidden = true;
  });
  window.addEventListener('appinstalled', () => {
    $('install').hidden = true;
    toast('IP Field Kit is installed.');
  });

  const standalone = window.matchMedia('(display-mode: standalone)').matches || navigator.standalone === true;
  const isIOS = /iphone|ipad|ipod/i.test(navigator.userAgent) || (navigator.platform === 'MacIntel' && navigator.maxTouchPoints > 1);
  if (isIOS && !standalone && !store.get('iosHintDismissed', false)) $('ios-hint').hidden = false;
  $('ios-hint-x').addEventListener('click', () => {
    $('ios-hint').hidden = true;
    store.set('iosHintDismissed', true);
  });

  // Offline support.
  if ('serviceWorker' in navigator && (location.protocol === 'https:' || location.hostname === 'localhost' || location.hostname === '127.0.0.1')) {
    const hadController = !!navigator.serviceWorker.controller;
    navigator.serviceWorker.addEventListener('controllerchange', () => {
      if (hadController) toast('A new version is ready.', 'Reload', () => location.reload());
    });
    window.addEventListener('load', () => {
      navigator.serviceWorker.register('./sw.js').catch(() => { /* the app still works online */ });
    });
  }
})();
