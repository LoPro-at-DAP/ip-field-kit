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
    const fail = () => toast("Couldn't copy. Select the text and copy it by hand.");
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(done, () => (legacyCopy(text) ? done() : fail()));
    } else if (legacyCopy(text)) done();
    else fail();
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

  function initCheck(onChange) {
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
      if (onChange) onChange();
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
  // The role keyword closest before an address decides its role, so "proto dhcp src 10.0.0.5" labels 10.0.0.5 by "src".
  const ROLE_WORDS = [
    ['dhcp', /dhcp/gi],
    ['dns', /dns|name ?servers?/gi],
    ['gateway', /gateway|default via|\bvia\b|\bgw\b|router|next.?hop/gi],
    ['mask', /mask/gi],
    ['broadcast', /broadcast|\bbrd\b|bcast/gi],
    ['ip', /ipv4|ip address|\binet\b|\baddr(ess)?\b|\bip\b|\bsrc\b/gi],
  ];
  // Dots may have a stray space beside them (OCR). Commas count only with no spaces, so "steps 1, 2, 3, 4" isn't an address.
  const IP_IN_TEXT = /(^|[^\d])(\d{1,3})(?: ?\. ?|,)(\d{1,3})(?: ?\. ?|,)(\d{1,3})(?: ?\. ?|,)(\d{1,3})(?: ?\/ ?(\d{1,2}))?(?!\d)/g;

  function closestRole(text) {
    let best = null, at = -1;
    for (const [role, re] of ROLE_WORDS) {
      re.lastIndex = 0;
      let m;
      while ((m = re.exec(text))) {
        const end = m.index + m[0].length;
        if (end > at) { at = end; best = role; }
      }
    }
    return best;
  }

  // Fix common OCR mix-ups inside runs that look like addresses: O→0, l→1, S→5, B→8, and a dot read as a colon.
  // A colon only counts as a dot when the run already has a real dot, so MAC addresses like 28:11:22:33 stay untouched.
  function fixOcr(line) {
    return line.replace(/[0-9OoIl|SB][0-9OoIl|SB.,:]{6,}/g, (tok) => {
      if ((tok.match(/\d/g) || []).length < 4) return tok;
      const dots = (tok.match(/[.,]/g) || []).length, colons = (tok.match(/:/g) || []).length;
      let t = tok;
      if (colons && dots >= 1 && dots + colons === 3) t = t.replace(/:/g, '.');
      else if (dots < 3) return tok;
      return t.replace(/[Oo]/g, '0').replace(/[Il|]/g, '1').replace(/S/g, '5').replace(/B/g, '8');
    });
  }

  function extractIPs(text) {
    const items = [];
    const seen = new Set();
    let carry = null; // label of the line above, for values continued on the next line (ipconfig gateways, DNS servers)
    text.split(/\r?\n/).forEach((raw, lineNo) => {
      const line = fixOcr(raw);
      if (!line.trim()) { carry = null; return; }
      IP_IN_TEXT.lastIndex = 0;
      let m, prevEnd = 0, inherited = false;
      const hits = [];
      while ((m = IP_IN_TEXT.exec(line))) {
        const start = m.index + m[1].length;
        const before = line.slice(prevEnd, start);
        prevEnd = IP_IN_TEXT.lastIndex;
        const octs = [m[2], m[3], m[4], m[5]].map(Number);
        const prefix = m[6] !== undefined ? Number(m[6]) : null;
        if (octs.some((o) => o > 255) || (prefix !== null && prefix > 32)) continue;
        const n = ((octs[0] * 256 + octs[1]) * 256 + octs[2]) * 256 + octs[3];
        let role = closestRole(before);
        if (!role) {
          const onlyThis = line.replace(m[0].slice(m[1].length), '').replace(/[\s:.,()[\]|-]/g, '') === '';
          if (onlyThis && carry) { role = carry; inherited = true; }
          else if (prefix === null && prefixOfMask(n) >= 8) role = 'mask';
          else role = 'address';
        }
        hits.push({ n, prefix, role, lineNo, line: raw });
      }
      // A labeled line passes its label down even when its own value wasn't IPv4 (for example an IPv6 gateway).
      carry = closestRole(line.replace(IP_IN_TEXT, ' ')) || (inherited ? carry : null);
      hits.forEach((h) => {
        const key = `${h.role}|${h.n}|${h.prefix}`;
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

    // Grayscale, turn light-on-dark screens into dark-on-light text, then even out the lighting:
    // estimate the background brightness tile by tile and divide it out. This works however little of the photo is text.
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
      const n = w * h;
      const g = new Uint8ClampedArray(n);
      const hist = new Uint32Array(256);
      for (let i = 0, j = 0; j < n; i += 4, j++) {
        const y = ((px[i] * 299 + px[i + 1] * 587 + px[i + 2] * 114) / 1000) | 0;
        g[j] = y;
        hist[y]++;
      }
      let acc = 0, median = 0;
      for (let v = 0; v < 256; v++) { acc += hist[v]; if (acc >= n / 2) { median = v; break; } }
      if (median < 110) for (let j = 0; j < n; j++) g[j] = 255 - g[j];

      // Background per tile = its 90th-percentile brightness (the paper or screen, not the text).
      const B = Math.max(16, Math.round(Math.min(w, h) / 20));
      const bw = Math.ceil(w / B), bh = Math.ceil(h / B);
      const bg = new Float32Array(bw * bh);
      const th = new Uint32Array(256);
      for (let by = 0; by < bh; by++) {
        for (let bx = 0; bx < bw; bx++) {
          th.fill(0);
          let cnt = 0;
          const x1 = Math.min(w, (bx + 1) * B), y1 = Math.min(h, (by + 1) * B);
          for (let y = by * B; y < y1; y++) for (let x = bx * B; x < x1; x++) { th[g[y * w + x]]++; cnt++; }
          let a = 0, v = 255;
          for (let k = 255; k >= 0; k--) { a += th[k]; if (a >= cnt * 0.1) { v = k; break; } }
          bg[by * bw + bx] = Math.max(v, 1);
        }
      }
      for (let y = 0; y < h; y++) {
        const fy = Math.min(Math.max((y + 0.5) / B - 0.5, 0), bh - 1);
        const y0 = Math.floor(fy), y1 = Math.min(y0 + 1, bh - 1), ty = fy - y0;
        for (let x = 0; x < w; x++) {
          const fx = Math.min(Math.max((x + 0.5) / B - 0.5, 0), bw - 1);
          const x0 = Math.floor(fx), x1 = Math.min(x0 + 1, bw - 1), tx = fx - x0;
          const b = (bg[y0 * bw + x0] * (1 - tx) + bg[y0 * bw + x1] * tx) * (1 - ty) + (bg[y1 * bw + x0] * (1 - tx) + bg[y1 * bw + x1] * tx) * ty;
          const norm = Math.min(255, (g[y * w + x] * 255) / b);
          const v = 255 - Math.min(255, (255 - norm) * 1.5);
          const i = (y * w + x) * 4;
          px[i] = px[i + 1] = px[i + 2] = v;
        }
      }
      ctx.putImageData(im, 0, 0);

      // Straighten tilted photos. Tesseract copes with small tilts itself, and rotating adds a little blur,
      // so only straighten from 4 degrees up.
      const angle = skewAngle(px, w, h);
      if (Math.abs(angle) < 4) return c;
      const r = document.createElement('canvas');
      r.width = w;
      r.height = h;
      const rc = r.getContext('2d');
      rc.fillStyle = '#fff';
      rc.fillRect(0, 0, w, h);
      rc.translate(w / 2, h / 2);
      rc.rotate((-angle * Math.PI) / 180);
      rc.drawImage(c, -w / 2, -h / 2);
      return r;
    }

    // Find the tilt (−15° to 15°) at which dark pixels stack into the sharpest text lines.
    function skewAngle(px, w, h) {
      const step = Math.max(1, Math.round(Math.sqrt((w * h) / 250000)));
      const xs = [], ys = [];
      for (let y = 0; y < h; y += step) for (let x = 0; x < w; x += step) if (px[(y * w + x) * 4] < 128) { xs.push(x); ys.push(y); }
      if (xs.length < 50) return 0;
      const bins = new Float64Array(Math.ceil((h + 2 * w) / step) + 2);
      const score = (deg) => {
        const tan = Math.tan((deg * Math.PI) / 180);
        bins.fill(0);
        for (let i = 0; i < xs.length; i++) bins[Math.round((ys[i] - xs[i] * tan + w) / step)]++;
        let sum = 0;
        for (let i = 0; i < bins.length; i++) sum += bins[i] * bins[i];
        return sum;
      };
      const flat = score(0);
      let best = 0, bestScore = flat;
      for (let deg = -15; deg <= 15; deg += 0.5) {
        const sc = score(deg);
        if (sc > bestScore) { bestScore = sc; best = deg; }
      }
      return bestScore > flat * 1.1 ? best : 0;
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

  // ---------- Device tests ----------
  // Commands to run on the device. {ip} {gw} {target} {iface} {mtu} {payload} {payload8} are filled in from the form.
  // out: [state, example output, what it means]
  const SHORT_REPLY = "Some servers, including 8.8.8.8, send back a trimmed reply to large pings. Any reply still means the full-size packet got through.";
  const BLACK_HOLE = 'A black hole: a router drops the packet, and its "too big" message is blocked on the way back. Expect web pages and VPNs to hang.';
  const TESTS = {
    windows: {
      reach: [
        { cmd: 'ipconfig /all', what: 'Shows the IP, mask, gateway, DHCP server, and DNS servers. Photograph the output and use Scan to fill in the fields above.',
          out: [['bad', 'IPv4 Address. . . : 169.254.12.34(Preferred)', 'No DHCP lease. Check the cable, the VLAN, and the DHCP server.'],
                ['bad', 'IPv4 Address. . . : {ip}(Duplicate)', 'Another device on the network is using this address.']] },
        { cmd: 'ping -n 4 127.0.0.1', what: "Tests the TCP/IP stack on the device itself. If this fails, the problem is the device, not the network." },
        { cmd: 'ping -n 4 {gw}', what: 'Tests the local link to the gateway.',
          out: [['ok', 'Reply from {gw}: bytes=32 time<1ms TTL=64', 'The link and the gateway are working.'],
                ['bad', 'Reply from {ip}: Destination host unreachable.', 'The gateway never answered ARP. See the ARP tests.'],
                ['warn', 'Request timed out.', 'No reply. The gateway may be down, or it may block ping. The ARP table tells you which.']] },
        { cmd: 'ping -n 4 {target}', what: 'Tests routing past the gateway.',
          out: [['bad', 'Request timed out.', 'The gateway answers but traffic stops beyond it. See the route tests.']] },
        { cmd: 'nslookup example.com', what: 'Tests DNS. If pinging an IP address works but names fail, the problem is DNS.' },
        { cmd: 'ipconfig /release && ipconfig /renew', what: 'Drops the current address and asks DHCP for a new one.' },
      ],
      mtu: [
        { cmd: 'ping -f -l {payload} -n 2 {target}', what: "-f sets Don't Fragment and -l sets the data size. {payload} bytes of data plus 28 bytes of headers makes a {mtu}-byte packet.",
          out: [['ok', 'Reply from {target}: bytes={payload} time=14ms TTL=117', 'Every link on the path carries {mtu}-byte packets.'],
                ['ok', 'Reply from {target}: bytes=68 (sent {payload}) time=14ms TTL=117', SHORT_REPLY],
                ['bad', 'Packet needs to be fragmented but DF set.', "Something has a smaller MTU: a link on the path, or this device's own interface (check it with netsh interface ipv4 show subinterfaces). Lower the MTU until replies come back."],
                ['warn', 'Request timed out.   (while smaller sizes get replies)', BLACK_HOLE]] },
        { cmd: 'netsh interface ipv4 show subinterfaces', what: 'Shows the MTU set on each interface.' },
        { cmd: 'netsh interface ipv4 set subinterface "{iface}" mtu={mtu} store=persistent', tag: 'Run as administrator', what: 'Sets the interface MTU. Use the largest MTU that passed the test.' },
      ],
      route: [
        { cmd: 'route print -4', what: 'Lists the routing table. Rows with network 0.0.0.0 and mask 0.0.0.0 are default routes. When there are two, the one with the lower metric wins.',
          out: [['bad', 'No 0.0.0.0 row under Active Routes', 'No default gateway, so the device can only reach its own subnet.']] },
        { cmd: 'Find-NetRoute -RemoteIPAddress {target}', tag: 'PowerShell', what: 'Shows the route, interface, and source IP that Windows will use to reach {target}.' },
        { cmd: 'tracert -d {target}', what: 'Lists each router on the way. -d skips name lookups so it runs faster. Windows tracert uses ICMP.',
          out: [['bad', '  2     *        *        *     Request timed out.   (on every line after hop 1)', "Traffic dies after the gateway. The gateway isn't forwarding, or has no route onward."],
                ['bad', 'The same few hops repeating', 'A routing loop between those routers.']] },
        { cmd: 'pathping -n {target}', what: 'Measures packet loss at every hop and takes a few minutes. Loss that starts at one hop and continues to the end points to that hop.' },
        { cmd: 'route add <network> mask <mask> {gw}', tag: 'Run as administrator', what: 'Adds a route to another network through the gateway. Add -p to keep it after a restart.' },
      ],
      arp: [
        { cmd: 'arp -a', what: "Lists the IP-to-MAC cache. Look for {gw}: it should be listed as dynamic with the router's MAC.",
          out: [['bad', 'No entry for {gw}', 'The gateway never answered ARP. That points to layer 2: the cable, switch port, VLAN, or Wi-Fi.'],
                ['warn', 'Entries for addresses outside your subnet', 'The mask is too short, so the device ARPs for hosts it should reach through the gateway.']] },
        { cmd: 'Get-NetNeighbor -AddressFamily IPv4 -IPAddress {gw}', tag: 'PowerShell', what: "Shows the gateway's ARP state. Reachable or Stale is fine. Incomplete or Unreachable means it isn't answering." },
        { cmd: 'arp -d *', tag: 'Run as administrator', what: 'Clears the ARP cache, for example after a router swap or after fixing a duplicate IP.' },
      ],
    },
    linux: {
      reach: [
        { cmd: 'ip -4 addr show', what: 'Shows the IPv4 address and prefix on each interface.',
          out: [['bad', 'inet 169.254.12.34/16 ...', 'No DHCP lease. Check the cable, the VLAN, and the DHCP server.'],
                ['bad', 'No inet line under the interface', 'The interface has no IPv4 address at all.']] },
        { cmd: 'ip -4 route show default', what: 'Shows the default gateway.',
          out: [['ok', 'default via {gw} dev {iface} proto dhcp metric 100', 'The gateway is set.'],
                ['bad', '(no output)', 'No default gateway, so the device can only reach its own subnet.']] },
        { cmd: 'ping -c 4 {gw}', what: 'Tests the local link to the gateway.',
          out: [['ok', '64 bytes from {gw}: icmp_seq=1 ttl=64 time=0.6 ms', 'The link and the gateway are working.'],
                ['bad', 'From {ip} icmp_seq=1 Destination Host Unreachable', 'The gateway never answered ARP. See the ARP tests.']] },
        { cmd: 'ping -c 4 {target}', what: 'Tests routing past the gateway.',
          out: [['bad', '4 packets transmitted, 0 received, 100% packet loss', 'The gateway answers but traffic stops beyond it. See the route tests.']] },
        { cmd: 'getent hosts example.com', what: 'Tests name lookups through the system resolver. No output means DNS is failing.' },
        { cmd: 'resolvectl status', what: 'Shows which DNS servers each interface uses, on systems with systemd-resolved.' },
      ],
      mtu: [
        { cmd: 'ping -M do -s {payload} -c 2 {target}', what: "-M do sets Don't Fragment and -s sets the data size. {payload} bytes of data plus 28 bytes of headers makes a {mtu}-byte packet, shown on the first line as {payload}({mtu}). Linux reports {payload8} bytes per reply because it counts the 8-byte ICMP header.",
          out: [['ok', '{payload8} bytes from {target}: icmp_seq=1 ttl=117 time=14 ms', 'Every link on the path carries {mtu}-byte packets.'],
                ['ok', '76 bytes from {target}: icmp_seq=1 ttl=117 (truncated)', SHORT_REPLY],
                ['bad', 'ping: sendmsg: Message too long', "This device's own interface MTU is smaller than the packet, so it never left. Check it with ip link show {iface}."],
                ['bad', 'ping: local error: message too long, mtu=1436', 'Seen on older ping versions, or when the device already learned a smaller path MTU. The number at the end is the limit.'],
                ['bad', 'From 10.0.0.1 icmp_seq=1 Frag needed and DF set (mtu = 1492)', 'A router on the path has a smaller MTU, and it tells you the number.'],
                ['warn', '100% packet loss   (while smaller sizes get replies)', BLACK_HOLE]] },
        { cmd: 'tracepath -n {target}', what: 'Finds the path MTU hop by hop, without root.',
          out: [['ok', 'Resume: pmtu 1500 hops 11 back 11', 'The path MTU to {target} is 1500.']] },
        { cmd: 'ip link show {iface}', what: 'Shows the interface MTU in the "mtu 1500" field.' },
        { cmd: 'sudo ip link set dev {iface} mtu {mtu}', what: 'Sets the interface MTU until the next reboot. Use the largest MTU that passed the test.' },
      ],
      route: [
        { cmd: 'ip -4 route show', what: 'Lists the routing table. "default via" lines are default gateways. When there are two, the one with the lower metric wins.' },
        { cmd: 'ip route get {target}', what: 'Shows the exact route, interface, and source IP the kernel will use for {target}.',
          out: [['ok', '{target} via {gw} dev {iface} src {ip}', 'Traffic leaves through the expected gateway.'],
                ['bad', 'RTNETLINK answers: Network is unreachable', 'No route to {target}, usually because there is no default gateway.']] },
        { cmd: 'traceroute -n {target}', what: 'Lists each router on the way. Linux sends UDP probes by default. Add -I and run it with sudo to use ICMP like Windows tracert.',
          out: [['bad', ' 2  * * *   (on every line after hop 1)', "Traffic dies after the gateway. The gateway isn't forwarding, or has no route onward."]] },
        { cmd: 'mtr -n -r -c 20 {target}', what: 'Measures loss and delay at every hop (install the mtr package). Loss that starts at one hop and continues to the end points to that hop.' },
        { cmd: 'sudo ip route add <network>/<prefix> via {gw}', what: 'Adds a route to another network through the gateway, until the next reboot.' },
      ],
      arp: [
        { cmd: 'ip -4 neigh show', what: 'Lists the ARP cache with a state for each entry.',
          out: [['ok', '{gw} dev {iface} lladdr 00:11:22:33:44:55 REACHABLE', 'The gateway answered recently.'],
                ['ok', '{gw} dev {iface} lladdr 00:11:22:33:44:55 STALE', 'Not confirmed lately. This is normal; Linux checks again the next time it sends there.'],
                ['bad', '{gw} dev {iface} FAILED', 'No ARP reply. INCOMPLETE means it is still waiting. Both point to layer 2: the cable, switch port, VLAN, or Wi-Fi.']] },
        { cmd: 'sudo arping -c 3 -I {iface} {gw}', what: 'Pings at the ARP level, so it works even when the gateway blocks ICMP. Replies from two different MACs mean two devices claim the address. If arping is missing on Debian or Ubuntu, install it with sudo apt install iputils-arping.' },
        { cmd: 'sudo arping -D -c 3 -I {iface} {ip}', what: 'Checks whether another device already uses {ip}.',
          out: [['ok', 'Received 0 response(s)', 'Nobody else is using {ip}.'],
                ['bad', 'Received 1 response(s)', 'Another device already has {ip}.']] },
        { cmd: 'sudo ip neigh flush dev {iface}', what: 'Clears the ARP cache, for example after a router swap or after fixing a duplicate IP.' },
      ],
    },
  };
  const MARKS = { ok: '✓', bad: '✕', warn: '!', info: 'i' };
  const MARK_WORDS = { ok: 'Pass', bad: 'Fail', warn: 'Warning', info: 'Note' };
  const fill = (tpl, v) => tpl.replace(/\{(\w+)\}/g, (all, k) => (v[k] !== undefined ? v[k] : all));

  // A command or filter with a Copy button, a description, and optional example output.
  function cmdHTML(t, v) {
    const c = fill(t.cmd, v);
    const tag = t.tag ? `<span class="badge special">${esc(t.tag)}</span>` : '';
    const outs = (t.out || []).map(([state, line, note]) =>
      `<li><span class="mark ${state}" aria-hidden="true">${MARKS[state]}</span><div><code><span class="sr">${MARK_WORDS[state]}: </span>${esc(fill(line, v))}</code><p>${esc(fill(note, v))}</p></div></li>`
    ).join('');
    return `<div class="cmd"><div class="cmd-line"><code>${esc(c)}</code><button type="button" class="btn small" data-copy="${esc(c)}">Copy</button></div>` +
      `<p class="what">${tag}${esc(fill(t.what, v))}</p>${outs ? `<ul class="outs">${outs}</ul>` : ''}</div>`;
  }

  function initTests() {
    const saved = store.get('tests', {}) || {};
    const st = {
      os: saved.os === 'linux' ? 'linux' : 'windows',
      target: typeof saved.target === 'string' ? saved.target : '8.8.8.8',
      ifaceWin: typeof saved.ifaceWin === 'string' ? saved.ifaceWin : 'Ethernet',
      ifaceLinux: typeof saved.ifaceLinux === 'string' ? saved.ifaceLinux : 'eth0',
      mtu: typeof saved.mtu === 'string' ? saved.mtu : '1500',
    };
    const targetEl = $('ts-target'), ifaceEl = $('ts-iface'), mtuEl = $('ts-mtu');

    function values() {
      const ip = parseIP($('ck-ip').value), gw = parseIP($('ck-gw').value);
      const mtu = Number(st.mtu.trim());
      const okMtu = st.mtu.trim() !== '' && Number.isInteger(mtu) && mtu >= 68 && mtu <= 65535;
      const iface = (st.os === 'windows' ? st.ifaceWin : st.ifaceLinux).trim();
      return {
        ip: ip !== null ? ipStr(ip) : '<device-ip>',
        gw: gw !== null ? ipStr(gw) : '<gateway>',
        target: st.target.trim() || '<target>',
        iface: iface || '<interface>',
        mtu: okMtu ? String(mtu) : '<mtu>',
        payload: okMtu ? String(mtu - 28) : '<size>',
        payload8: okMtu ? String(mtu - 20) : '<size>',
        okMtu,
      };
    }

    function render() {
      const v = values();
      const set = TESTS[st.os];
      $('ts-reach').innerHTML = set.reach.map((t) => cmdHTML(t, v)).join('');
      $('ts-mtu-cmds').innerHTML = set.mtu.map((t) => cmdHTML(t, v)).join('');
      $('ts-route').innerHTML = set.route.map((t) => cmdHTML(t, v)).join('');
      $('ts-arp').innerHTML = set.arp.map((t) => cmdHTML(t, v)).join('');
      $('ts-mtu-calc').innerHTML = v.okMtu
        ? `${v.mtu} MTU − 20 IP header − 8 ICMP header = <b>${v.payload}</b> bytes of ping data`
        : 'Enter an MTU from 68 to 65535.';
      document.querySelectorAll('#ts-mtu-presets [data-mtu]').forEach((b) => b.setAttribute('aria-pressed', String(b.dataset.mtu === st.mtu.trim())));
      store.set('tests', st);
    }

    function syncInputs() {
      $('ts-os-' + st.os).checked = true;
      targetEl.value = st.target;
      ifaceEl.value = st.os === 'windows' ? st.ifaceWin : st.ifaceLinux;
      ifaceEl.placeholder = st.os === 'windows' ? 'Ethernet or Wi-Fi' : 'eth0 or wlan0';
      mtuEl.value = st.mtu;
    }

    document.querySelectorAll('input[name="ts-os"]').forEach((el) => el.addEventListener('change', () => {
      st.os = el.value;
      syncInputs();
      render();
    }));
    targetEl.addEventListener('input', () => { st.target = targetEl.value; render(); });
    ifaceEl.addEventListener('input', () => {
      if (st.os === 'windows') st.ifaceWin = ifaceEl.value; else st.ifaceLinux = ifaceEl.value;
      render();
    });
    mtuEl.addEventListener('input', () => { st.mtu = mtuEl.value; render(); });
    const stepMtu = (d) => {
      const n = Number(st.mtu);
      st.mtu = String(Math.max(68, Math.min(65535, (Number.isInteger(n) ? n : 1500) + d)));
      mtuEl.value = st.mtu;
      render();
    };
    $('ts-mtu-dec').addEventListener('click', () => stepMtu(-1));
    $('ts-mtu-inc').addEventListener('click', () => stepMtu(1));
    document.querySelectorAll('#ts-mtu-presets [data-mtu]').forEach((b) => b.addEventListener('click', () => {
      st.mtu = b.dataset.mtu;
      mtuEl.value = st.mtu;
      render();
    }));
    ['ck-ip', 'ck-gw'].forEach((id) => $(id).addEventListener('input', render));

    syncInputs();
    render();
    return { render };
  }

  // ---------- Tunnel and label overhead ----------
  const ESP = {
    cbc1: { name: 'AES-CBC + SHA-1', iv: 16, icv: 12, pad: 15 },
    cbc256: { name: 'AES-CBC + SHA-256', iv: 16, icv: 16, pad: 15 },
    gcm: { name: 'AES-GCM', iv: 8, icv: 16, pad: 3 },
  };
  // Worst case: outer IP (tunnel mode only) + SPI/sequence + IV + max padding + pad length/next header + integrity check.
  const espBytes = (mode, c) => (mode === 'tunnel' ? 20 : 0) + 8 + ESP[c].iv + ESP[c].pad + 2 + ESP[c].icv;

  // [min, max, cause] for working backward from the largest MTU that passed.
  const OVERHEAD_CAUSES = [
    [4, 4, 'One MPLS label, or a VLAN tag that a device counts against the MTU'],
    [8, 8, 'PPPoE, or two MPLS labels (MPLS VPN) that the core has no room for'],
    [12, 12, 'Three MPLS labels, for example an MPLS VPN with traffic engineering'],
    [16, 16, 'PPPoE plus two MPLS labels, or four MPLS labels'],
    [24, 24, 'GRE'],
    [28, 28, 'GRE with a tunnel key, common on mGRE / DMVPN'],
    [32, 36, 'GRE over PPPoE'],
    [50, 50, 'VXLAN'],
    [54, 77, 'IPsec ESP tunnel mode'],
    [58, 85, 'GRE over IPsec transport mode (DMVPN)'],
    [60, 60, 'WireGuard over IPv4'],
    [62, 85, 'IPsec tunnel mode through NAT (NAT-T)'],
    [78, 105, 'GRE over IPsec tunnel mode'],
    [80, 80, 'WireGuard over IPv6'],
  ];

  const IOS_CHECKS = [
    { cmd: 'ping {target} size {mtu} df-bit', tag: 'Cisco IOS', what: 'On Cisco, size is the whole IP packet with headers, so use the MTU itself, not MTU − 28.' },
    { cmd: 'ping vrf <vrf-name> {target} size {mtu} df-bit', tag: 'Cisco IOS', what: 'The same test inside an MPLS VPN.' },
    { cmd: 'ping mpls ipv4 <remote-loopback>/32 sweep 1400 1520 4', tag: 'Cisco IOS', what: 'Sends labeled pings of growing size along the label-switched path. Where replies stop is the largest packet the MPLS core carries.' },
    { cmd: 'show interfaces Tunnel0 | include MTU', tag: 'Cisco IOS', what: "Shows the tunnel's MTU and its transport MTU, the room left after the GRE headers." },
    { cmd: 'show ip interface Tunnel0 | include MTU', tag: 'Cisco IOS', what: 'Shows the IP MTU applied to packets entering the tunnel.' },
    { cmd: 'show mpls interfaces detail', tag: 'Cisco IOS', what: 'Shows the MPLS MTU on each interface.' },
    { cmd: 'show crypto ipsec sa | include mtu', tag: 'Cisco IOS', what: 'Shows the path MTU and IP MTU each IPsec tunnel is using.' },
  ];

  function initOverhead() {
    const ids = ['base', 'mpls', 'gre', 'ipsec', 'cipher', 'pppoe', 'natt', 'vxlan', 'wg', 'passed'];
    const el = Object.fromEntries(ids.map((k) => [k, $('ovh-' + k)]));
    const saved = store.get('ovh', {}) || {};
    el.base.value = typeof saved.base === 'string' ? saved.base : '1500';
    ['mpls', 'gre', 'ipsec', 'cipher'].forEach((k) => { if (typeof saved[k] === 'string') el[k].value = saved[k]; });
    if (!el.cipher.value) el.cipher.value = 'cbc1';
    ['pppoe', 'natt', 'vxlan', 'wg'].forEach((k) => { el[k].checked = saved[k] === true; });
    el.passed.value = typeof saved.passed === 'string' ? saved.passed : '';

    function render() {
      const base = Number(el.base.value.trim());
      const okBase = el.base.value.trim() !== '' && Number.isInteger(base) && base >= 576 && base <= 65535;
      const mpls = Number(el.mpls.value), gre = Number(el.gre.value), mode = el.ipsec.value, c = el.cipher.value;
      el.cipher.disabled = !mode;
      el.natt.disabled = !mode;
      const parts = [];
      if (el.pppoe.checked) parts.push(['PPPoE', 8]);
      if (mpls) parts.push([`${mpls} MPLS label${mpls > 1 ? 's' : ''}`, 4 * mpls]);
      if (gre) parts.push([gre === 28 ? 'GRE with key' : 'GRE', gre]);
      if (mode) parts.push([`IPsec ${mode} mode, ${ESP[c].name}`, espBytes(mode, c)]);
      if (mode && el.natt.checked) parts.push(['NAT-T', 8]);
      if (el.vxlan.checked) parts.push(['VXLAN', 50]);
      if (el.wg.checked) parts.push(['WireGuard', 60]);
      const total = parts.reduce((a, [, n]) => a + n, 0);
      const mtu = okBase ? base - total : null;

      let html = '';
      if (!okBase) html = '<p class="error">Enter a link MTU from 576 to 65535.</p>';
      else if (!parts.length) html = `<p class="cap">Nothing selected, so the full ${base} bytes are available.</p>`;
      else if (mtu < 576) html = '<p class="error">That stack leaves less than 576 bytes, the smallest MTU IPv4 hosts must accept.</p>';
      else {
        html = `<p class="calc">${base} − ${parts.map(([name, n]) => `${n} (${esc(name)})`).join(' − ')} = <b>${mtu}</b></p>` +
          `<dl class="kv">${kvRows([
            ['IP MTU left', `<b>${mtu}</b>`, String(mtu)],
            ['Ping data size', String(mtu - 28), String(mtu - 28)],
            ['TCP MSS', String(mtu - 40), String(mtu - 40)],
            ['Total overhead', `${total} bytes`, null],
          ])}</dl>`;
        if (gre || mode) {
          html += cmdHTML({ cmd: `interface Tunnel0\n ip mtu ${mtu}\n ip tcp adjust-mss ${mtu - 40}`, tag: 'Cisco IOS',
            what: "Sets the tunnel's IP MTU and clamps TCP so hosts never send more than fits. Cisco's usual DMVPN values, 1400 and 1360, leave a little extra room." }, {});
        }
        if (mpls) {
          html += cmdHTML({ cmd: `mpls mtu ${base + 4 * mpls}`, tag: 'Cisco IOS',
            what: `Labels only cost you MTU when core links have no room for them. On each core interface, allow ${base} + ${4 * mpls} bytes so labeled ${base}-byte packets fit. Some platforms need the interface mtu raised first.` }, {});
        }
      }
      $('ovh-result').innerHTML = html;

      // Work backward
      const passed = Number(el.passed.value.trim());
      let why = '';
      if (el.passed.value.trim() !== '' && okBase) {
        if (!Number.isInteger(passed) || passed < 68) why = '<p class="error">Enter the MTU (not the ping data size) of the largest test that passed.</p>';
        else if (passed > base) why = `<p class="error">That's larger than the link MTU of ${base}.</p>`;
        else {
          const gap = base - passed;
          const hits = OVERHEAD_CAUSES.filter(([lo, hi]) => gap >= lo && gap <= hi);
          why = `<p class="calc">${base} − ${passed} = <b>${gap}</b> bytes missing</p>`;
          if (gap > 0) why += `<p class="cap">First check the device's own interface MTU (netsh interface ipv4 show subinterfaces, or ip link show). If it's already ${passed}, the limit is on the device, not the path.</p>`;
          if (gap === 0) why += '<p class="cap">Nothing is missing. The full MTU gets through.</p>';
          else if (hits.length) why += `<ul class="matches">${hits.map(([lo, hi, cause]) => `<li><b>${lo === hi ? lo : `${lo}–${hi}`}</b><span>${esc(cause)}</span></li>`).join('')}</ul>`;
          else why += '<p class="cap">No single common encapsulation matches. Several layers may be stacked: try combinations in the calculator above.</p>';
        }
      }
      $('ovh-why').innerHTML = why;

      const target = $('ts-target').value.trim() || '<target>';
      const v = { target, mtu: mtu && mtu >= 576 ? String(mtu) : okBase ? String(base) : '1500' };
      $('ovh-ios').innerHTML = IOS_CHECKS.map((t) => cmdHTML(t, v)).join('');

      const out = {};
      ids.forEach((k) => { out[k] = el[k].type === 'checkbox' ? el[k].checked : el[k].value; });
      store.set('ovh', out);
    }

    ids.forEach((k) => el[k].addEventListener(el[k].tagName === 'INPUT' && el[k].type === 'text' ? 'input' : 'change', render));
    $('ts-target').addEventListener('input', render);
    render();
  }

  // ---------- Capture (Wireshark) ----------
  const WS_SIZE = [
    ['icmp && data.len == {size}', "Your Don't Fragment pings with {size} bytes of data, from ping -f -l {size} or ping -M do -s {size}."],
    ['ip.len > 1400', 'Large packets. ip.len counts the IP header plus data, so a full-size packet is 1500.'],
    ['frame.len > 1514', 'Frames bigger than standard Ethernet (a 1500-byte packet plus the 14-byte header): jumbo frames or "baby giants".'],
    ['ip.flags.df == 1', "Packets with Don't Fragment set."],
    ['ip.flags.mf == 1 || ip.frag_offset > 0', 'IP fragments. Something split a packet that was too big.'],
    ['icmp.type == 3 && icmp.code == 4', '"Fragmentation needed" messages. The icmp.mtu field shows the MTU of the next hop.'],
    ['tcp.flags.syn == 1 && tcp.options.mss_val < 1460', 'Connections with a reduced maximum segment size, a sign of PPPoE, a tunnel, or MSS clamping.'],
    ['tcp.analysis.retransmission && tcp.len > 1300', 'Large segments being sent again, a typical sign of an MTU black hole.'],
    ['gre || mpls || esp || vxlan || udp.port == 4500', 'Tunnel and label traffic that adds overhead. UDP 4500 is IPsec through NAT.'],
  ];
  const WS_ARP = [
    ['arp', 'All ARP traffic.'],
    ['arp.opcode == 1', 'Requests: "Who has this IP?"'],
    ['arp.opcode == 2', 'Replies: "This IP is at this MAC."'],
    ['arp.dst.proto_ipv4 == {ip}', 'Who is asking for {ip}.'],
    ['arp.src.proto_ipv4 == {ip}', '{ip} announcing itself or answering. Two different MACs here means a duplicate IP.'],
    ['arp.src.proto_ipv4 == arp.dst.proto_ipv4', 'Gratuitous ARP: a device announcing its own IP, usually right after boot or a failover.'],
    ['arp.src.proto_ipv4 == 0.0.0.0', 'ARP probes: a device checking whether an IP is free before using it. The target IP is the one it wants.'],
    ['arp.duplicate-address-detected', 'Wireshark found two MACs claiming the same IP.'],
    ['arp.opcode == 1 && !(arp.src.proto_ipv4 == {subnet}) && !(arp.src.proto_ipv4 == 0.0.0.0)', 'ARP requests from addresses outside {subnet}: a device set up with the wrong IP or mask for this network.'],
  ];
  const WS_FIND = [
    ['eth.src == {mac}', 'Everything the device sends, using the MAC on its label.'],
    ['arp && eth.src == {mac}', 'Its ARP traffic. The sender IP is its address. The target IP is often its gateway, which hints at the subnet.'],
    ['dhcp.option.dhcp == 1', 'DHCP Discover: a device looking for a DHCP server. dhcp.option.requested_ip_address shows the last IP it had. Wireshark before version 3.0 calls this bootp.'],
    ['ip.addr == 169.254.0.0/16', 'IPv4 link-local (APIPA): a device that gave itself an address because it found no DHCP server.'],
    ['ipv6.src == fe80::/10', 'IPv6 link-local. Nearly every modern device has one, even with no IPv4 set up.'],
    ['icmpv6.type == 135 && ipv6.src == ::', 'IPv6 duplicate-address checks, which show the address a device is about to use.'],
    ['icmpv6.type >= 133 && icmpv6.type <= 136', 'IPv6 neighbor discovery: router and neighbor solicitations and advertisements.'],
    ['lldp || cdp', 'Switches, phones, and access points announcing their name, port, and management IP (lldp.mgn.addr.ip4).'],
    ['mdns || llmnr || nbns || ssdp', 'Devices announcing names and services, such as printers, cameras, and IoT gear.'],
    ['eth.dst == ff:ff:ff:ff:ff:ff', 'All broadcast traffic, where most discovery happens.'],
  ];
  const WS_CAPTURE = [
    ['arp or udp port 67 or udp port 68 or icmp6 or udp port 5353 or ether proto 0x88cc', 'Discovery traffic only: ARP, DHCP, IPv6 neighbor discovery, mDNS, and LLDP (EtherType 0x88cc).'],
    ['ether host {mac}', 'Only frames to or from the device.'],
  ];

  function normMac(str) {
    const hex = String(str).replace(/[^0-9a-f]/gi, '');
    return hex.length === 12 ? hex.toLowerCase().match(/../g).join(':') : null;
  }

  // IPv6 link-local address built from a MAC (EUI-64). Many newer systems use a random one instead.
  function eui64(mac) {
    const b = mac.split(':').map((x) => parseInt(x, 16));
    b[0] ^= 2;
    return 'fe80::' + [(b[0] << 8) | b[1], (b[2] << 8) | 0xff, 0xfe00 | b[3], (b[4] << 8) | b[5]].map((w) => w.toString(16)).join(':');
  }

  function laptopAddress(dev, p) {
    if (p >= 32) return null;
    const net = netOf(dev, p), size = P2(32 - p);
    if (p === 31) return net === dev ? net + 1 : net;
    const first = net + 1, last = net + size - 2;
    const picks = [];
    if (size >= 16) for (let x = last - 4; x >= first && picks.length < 8; x--) picks.push(x);
    for (let x = first; x <= last && picks.length < 24; x++) picks.push(x);
    const pick = picks.find((x) => x !== dev);
    return pick === undefined ? null : pick;
  }

  function initCapture() {
    const saved = store.get('capture', {}) || {};
    const st = {
      os: saved.os === 'linux' ? 'linux' : 'windows',
      ip: typeof saved.ip === 'string' ? saved.ip : '192.168.0.10',
      prefix: typeof saved.prefix === 'string' ? saved.prefix : '/24',
      mac: typeof saved.mac === 'string' ? saved.mac : '00:11:22:33:44:55',
      size: typeof saved.size === 'string' ? saved.size : '1472',
      ifaceWin: typeof saved.ifaceWin === 'string' ? saved.ifaceWin : 'Ethernet',
      ifaceLinux: typeof saved.ifaceLinux === 'string' ? saved.ifaceLinux : 'eth0',
    };
    const f = { ip: $('ws-ip'), prefix: $('ws-prefix'), mac: $('ws-mac'), size: $('ws-size'), iface: $('ws-iface') };

    function values() {
      const errs = [];
      const ipN = parseIP(st.ip);
      if (ipN === null) errs.push(st.ip.trim() ? `"${st.ip.trim()}" isn't a complete IPv4 address.` : 'Enter the device or gateway IP.');
      const mk = parseMask(st.prefix);
      let p = mk.p !== undefined ? mk.p : null;
      if (p === null) errs.push(mk.empty ? 'Enter the prefix, like /24.' : mk.error);
      // Link-local is always a /16. Pick the laptop address near the device, away from the reserved first and last /24.
      const apipa = ipN !== null && netOf(ipN, 16) === parseIP('169.254.0.0');
      if (apipa) p = 16;
      const mac = normMac(st.mac);
      if (!mac) errs.push(st.mac.trim() ? `"${st.mac.trim()}" isn't a MAC address. Use 12 hex digits, like 00:11:22:33:44:55.` : 'Enter the device MAC.');
      const size = Number(st.size.trim());
      const okSize = st.size.trim() !== '' && Number.isInteger(size) && size >= 0 && size <= 65500;
      if (!okSize) errs.push('Enter the ping data size as a whole number from 0 to 65500.');
      const iface = (st.os === 'windows' ? st.ifaceWin : st.ifaceLinux).trim() || (st.os === 'windows' ? 'Ethernet' : 'eth0');
      const laptop = ipN !== null && p !== null ? laptopAddress(ipN, apipa ? 24 : p) : null;
      return {
        errs, devN: ipN, p, mac: mac || '<mac>', iface, laptopN: laptop, apipa,
        ip: ipN !== null ? ipStr(ipN) : '<device-ip>',
        subnet: ipN !== null && p !== null ? `${ipStr(netOf(ipN, p))}/${p}` : '<subnet>',
        size: okSize ? String(size) : '<size>',
        prefix: p !== null ? String(p) : '<prefix>',
        mask: p !== null ? maskStr(p) : '<mask>',
        laptop: laptop !== null ? ipStr(laptop) : '<laptop-ip>',
        ll: mac ? eui64(mac) : 'fe80::<device-id>',
      };
    }

    const list = (rows, v) => rows.map(([cmd, what]) => cmdHTML({ cmd, what }, v)).join('');

    function steps(v) {
      const win = st.os === 'windows';
      const c = (t) => cmdHTML(t, v);
      return [
        ['Start capturing, then power on the device', '<p>Boot is when a device sends gratuitous ARP, DHCP requests, and LLDP. Use the filters under "Find a device\'s address" to spot them.</p>'],
        ['Enter its address above', "<p>Put the IP you found in <b>Device or gateway IP</b>. If you only learned its gateway, a /24 around that gateway is a reasonable first guess.</p>"],
        ["Check that your laptop's address is free", win
          ? c({ cmd: 'ping -n 2 {laptop}', what: 'No reply, and no entry for {laptop} in arp -a afterward, means nothing is using it.' })
          : c({ cmd: 'sudo arping -D -c 3 -I {iface} {laptop}', what: '"Received 0 response(s)" means nothing is using {laptop}. If arping is missing on Debian or Ubuntu, install it with sudo apt install iputils-arping.' })],
        ['Give your laptop the address', win
          ? c({ cmd: 'netsh interface ipv4 set address name="{iface}" static {laptop} {mask}', tag: 'Run as administrator', what: 'No gateway is needed on a direct link.' })
          : c({ cmd: 'sudo ip addr add {laptop}/{prefix} dev {iface}', what: 'Adds the address alongside any you already have. No gateway is needed on a direct link.' })],
        ['Connect', c({ cmd: win ? 'ping -n 4 {ip}' : 'ping -c 4 {ip}', what: 'Then open http://{ip} in a browser, or connect with SSH or the vendor tool.' })],
        ['Put your laptop back afterward', win
          ? c({ cmd: 'netsh interface ipv4 set address name="{iface}" source=dhcp', tag: 'Run as administrator', what: 'Returns the interface to DHCP.' })
          : c({ cmd: 'sudo ip addr del {laptop}/{prefix} dev {iface}', what: 'Removes the temporary address.' })],
      ];
    }

    function render() {
      const v = values();
      $('ws-size-list').innerHTML = list(WS_SIZE, v);
      $('ws-offload').innerHTML = st.os === 'windows'
        ? cmdHTML({ cmd: 'Disable-NetAdapterLso -Name "{iface}"', tag: 'PowerShell as administrator', what: 'Turns off large send offload so captured sizes match the wire. Re-enable it afterward with Enable-NetAdapterLso.' }, v)
        : cmdHTML({ cmd: 'sudo ethtool -K {iface} tso off gso off gro off', what: 'Turns off segmentation offload so captured sizes match the wire. Run it again with "on" afterward.' }, v);
      $('ws-arp-list').innerHTML = list(WS_ARP, v);
      $('ws-find-list').innerHTML = list(WS_FIND, v);
      $('ws-capture').innerHTML = list(WS_CAPTURE, v);

      $('ws-error').hidden = !v.errs.length;
      $('ws-error').textContent = v.errs.join(' ');
      const sug = $('ws-suggest');
      if (v.devN === null || v.p === null) sug.textContent = "Enter the device's IP and prefix above to get a suggested laptop address.";
      else if (v.apipa) sug.innerHTML = `${esc(v.ip)} is a link-local (APIPA) address. Leave your laptop on DHCP with no DHCP server connected and it takes a 169.254 address of its own within about a minute, or set <b>${esc(v.laptop)}/16</b> by hand.`;
      else if (v.laptopN === null) sug.textContent = `A /${v.p} has no room for a second address. Check the prefix.`;
      else sug.innerHTML = `Suggested laptop address: <b>${esc(v.laptop)}/${v.p}</b> (mask ${esc(v.mask)}). It's in the same subnet as ${esc(v.ip)}. Confirm it's free in step 3.`;

      $('ws-steps').innerHTML = steps(v).map(([t, b]) => `<li><h3>${esc(t)}</h3><div class="step-body">${b}</div></li>`).join('');

      const win = st.os === 'windows';
      $('ws-shortcuts').innerHTML =
        `<p class="cap">If the device has a 169.254 address, leave your laptop on DHCP with no DHCP server connected. It gives itself a 169.254 address too, and both land in the same /16.</p>` +
        cmdHTML(win
          ? { cmd: 'ping {ll}%12', what: 'IPv6 link-local needs no setup on either side. Replace 12 with your interface index from netsh interface ipv6 show interfaces. The address shown is built from the MAC (EUI-64); many newer devices use a random one, so read the real one from the capture.' }
          : { cmd: 'ping -c 4 {ll}%{iface}', what: 'IPv6 link-local needs no setup on either side. The address shown is built from the MAC (EUI-64); many newer devices use a random one, so read the real one from the capture.' }, v);
      store.set('capture', st);
    }

    function sync() {
      $('ws-os-' + st.os).checked = true;
      f.ip.value = st.ip;
      f.prefix.value = st.prefix;
      f.mac.value = st.mac;
      f.size.value = st.size;
      f.iface.value = st.os === 'windows' ? st.ifaceWin : st.ifaceLinux;
      f.iface.placeholder = st.os === 'windows' ? 'Ethernet' : 'eth0';
    }

    ['ip', 'prefix', 'mac', 'size'].forEach((k) => f[k].addEventListener('input', () => { st[k] = f[k].value; render(); }));
    f.iface.addEventListener('input', () => {
      if (st.os === 'windows') st.ifaceWin = f.iface.value; else st.ifaceLinux = f.iface.value;
      render();
    });
    document.querySelectorAll('input[name="ws-os"]').forEach((r) => r.addEventListener('change', () => { st.os = r.value; sync(); render(); }));
    sync();
    render();
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
  const tests = initTests();
  const check = initCheck(() => tests.render());
  initScan(lookup, check);
  initOverhead();
  initCapture();

  const VIEWS = ['lookup', 'scan', 'check', 'capture', 'subnets'];
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
