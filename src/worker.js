//  The edge tunnel implementation based on Cloudflare Worker.
//
//  Copyright (C) 2025-2026 - Public Free Software
//
//  This program is free software: you can redistribute it and/or modify
//  it under the terms of the GNU General Public License as published by
//  the Free Software Foundation, either version 3 of the License, or
//  (at your option) any later version.
//
//  This program is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU General Public License for more details.
//
//  You should have received a copy of the GNU General Public License
//  along with this program.  If not, see <https://www.gnu.org/licenses/>.

import { connect } from "cloudflare:sockets";
import { TLS12_Client, HTTP_Reader } from "./tls12_client.js";
import { HTTP_Tunnel, Socks5_Tunnel } from "./tunnel_client.js";

const opt_uuid = "98f475f4-bd96-49f6-98af-9e16103b5ec2";
const opt_dohurl = "https://dns.google/dns-query";
const opt_proxy = "proxyip://172.71.218.190";
const opt_flowu_ctl = "1M";
const opt_flowd_ctl = "1M";

const textencode = (str) => new TextEncoder().encode(str);
const textdecode = (str) => new TextDecoder().decode(str);
const chunkscat_arr8 = (...chunks) => {
  const of_chunks = chunks.filter((chunk) => chunk && chunk.length > 0);
  const length = of_chunks.reduce((total, chunk) => total + chunk.length, 0);
  const buffer = new Uint8Array(length); let offset = 0;
  for (const chunk of of_chunks) {
    buffer.set(chunk, offset); offset += chunk.length;
  } return buffer;
};

function flow_conv(a) { /* convert to bytes */
  if (Number(a)) return parseInt(a); const q = a.match(/^(\d+)\.?(\d+)?(K|M)?$/);
  if (!q) return 65536; let n = parseInt(q[1]), d = parseInt(q[2]), p;
  p = (q[3] == "K") ? 1024 : ((q[3] == "M") ? 1024 * 1024 : 1); n *= p;
  if (d) { n += d * p / Math.pow(10, q[2].length); } return Math.trunc(n);
}

function flow_step(totals) { /* sleep */
  const default_delay = 300, extra_delay = 500, delay_steps = [
    { size:   1 * 1024 * 1024, delay: 320 },
    { size:  50 * 1024 * 1024, delay: 340 },
    { size: 100 * 1024 * 1024, delay: 360 },
    { size: 200 * 1024 * 1024, delay: 400 } ];
  const delay = () => {
    for (let i = delay_steps.length - 1; i >= 0; i--) {
      if (totals >= delay_steps[i].size) return delay_steps[i].delay + default_delay;
    } return default_delay + extra_delay;
  }; return new Promise(resolve => setTimeout(resolve, delay()));
}

async function get_domain_v4(domain) {
  try {
    const resp = await fetch(`https://dns.google/resolve?name=${domain}&type=A`,
      { headers: { "Accept": "applicationdns-json" } });
    const res = await resp.json();
    if (res.Answer && res.Answer.length > 0) {
      const a = res.Answer.find(r => r.type === 1); if (a) return a.data;
    }
  } catch { console.log(`domain query failed: ${domain}`); }
  return null;
}

async function get_proxyip64(prefix64, host, type) { /* nat64 */
  if (!prefix64) return null;
  switch (type) {
    case 2: host = await get_domain_v4(host); if (!host) break;
    case 1: const s = new Uint8Array(host.split('.'));
      const a = Array.from(s).map(byte => byte.toString(16).padStart(2, '0'));
      return `[${prefix64}${a[0]}${a[1]}:${a[2]}${a[3]}]`;
  } return null;
}

function vls_parse(header, uuid) {
  const buf = new Uint8Array(header); if (buf.length < 18) return { more: true };
  let f = 18, y = false, h = null; const v = buf.slice(0, 1)[0]; /* version */
  const u = Array.from(buf.slice(1, 17)).map(byte => /* uuid */
    byte.toString(16).padStart(2, '0')).join('');
  const d = Array.from(uuid).filter(char => char !== '-').join('');
  if (u !== d) return { error: true, message: "invalid userid" }; /* M bytes */
  f += buf.slice(17, 18)[0]; if (buf.length < (f + 5)) return { more: true };
  const c = buf.slice(f, f + 1)[0]; if (c == 2) { y = true } else if (c != 1)
    return { error: true, message: `invalid command: ${c}` }; /* 1:tcp, 2:udp */
  const p = new DataView(buf.slice(f + 1, f + 3).buffer).getUint16(0);
  const t = buf.slice(f + 3, f + 4)[0]; f += 4; if (t == 3) f += 12;
  if ((t == 1 || t == 3) && buf.length < (f + 4)) return { more: true };
  switch (t) { case 1: h = buf.slice(f, f + 4).join('.'); f += 4; break;
    case 2: const l = buf.slice(f, f + 1)[0]; f += 1;
      if (buf.length < (f + l)) return { more: true };
      h = textdecode(buf.slice(f, f + l)); f += l; break;
    case 3: const v6 = new DataView(buf.slice(f - 12, f + 4).buffer); h = [];
      for (let i = 0; i < 8; i++) { h.push(v6.getUint16(i * 2).toString(16)
        .padStart(4, '0')); } h = '[' + h.join(':') + ']'; f += 4; break;
  } if (!h) return { error: true, message: "invalid address" };
  return { error: false, version: v, is_udp: y, type: t, host: h, port: p, offset: f };
}

function get_proxy_params(url) {
  if (url) {
    try { const u = new URL(url);
      const params = new Map(); params.set("type", u.protocol.split(":")[0]);
      params.set("host", u.hostname); params.set("port", u.port);
      for (const k of u.pathname.split("/").slice(1)) {
        if (!k) continue; const p = k.match(/^([^=]*)=(.*$)/);
        if (!p?.[1]) continue; params.set(p?.[1], p?.[2]);
      } return params;
    } catch (error) { console.log("proxy params error", error); }
  } return new Map();
}

async function tcpsocket_connect(obj, host, port, type) {
  const tcpsocket = async (host, port) => {
    console.log(`tcpsocket connect to ${host} ${port}`);
    const socket = connect({ hostname: host, port: port });
    await socket.opened; return socket;
  }
  const params = get_proxy_params(obj.proxy);
  const url_host = params.get("host"), url_port = params.get("port");
  const url_all = params.get("all"), url_prefix64 = params.get("prefix64");
  const proxy_connect = async () => {
    const url_user = params.get("user"), url_pass = params.get("pass");
    switch (params.get("type")) {
      case "http": { console.log("http tunnel connection");
        const socket = await tcpsocket(url_host, url_port);
        return await HTTP_Tunnel(socket, host, port, url_user, url_pass);
      }
      case "socks5": { console.log("socks5 tunnel connection");
        const socket = await tcpsocket(url_host, url_port);
        return await Socks5_Tunnel(socket, host, port, url_user, url_pass);
      }
      case "proxyip": { console.log("proxyip connection");
        const proxyip64 = await get_proxyip64(url_prefix64, host, type);
        host = proxyip64 || url_host || host;
        if (!proxyip64) port = url_port || port;
        return await tcpsocket(host, port);
      }
    } return null;
  };
  if (url_all) { /* proxy all traffic */
    try { return await proxy_connect(); } catch { return null; }
  } try { return await tcpsocket(host, port); } catch { /* retry */
    try { return await proxy_connect(); } catch { return null; }
  }
}

async function remote_pipe(obj, remote_stream, down_writable, data) {
  const writer = remote_stream.socket.writable.getWriter();
  try { await writer.write(data); } finally { writer.releaseLock(); }
  remote_stream.socket.readable.pipeTo(new WritableStream({
    async write(chunk) { await down_writable.write(chunk); },
    close() { console.log("remote pipe stream close"); down_writable.close(); }
  })).catch((error) => {
    console.log("remote pipe stream error", error); down_writable.close();
  });
}

async function dns_handle(obj, remote_stream, down_writable) {
  let buffer = new Uint8Array(0);
  const transform = new TransformStream({
    transform(chunk, controller) {
      buffer = chunkscat_arr8(buffer, new Uint8Array(chunk));
      while (buffer.length >= 2) {
        const length = new DataView(buffer.buffer).getUint16(0);
        if (buffer.length < (2 + length)) break;
        const frame = buffer.slice(2, 2 + length); buffer = buffer.slice(2 + length);
        controller.enqueue(frame.buffer);
      }
    } });
  transform.readable.pipeTo(new WritableStream({
    async write(chunk) {
      const resp = await fetch(obj.dohurl, { method: "POST",
        headers: { "content-type": "application/dns-message" }, body: chunk });
      const result = await resp.arrayBuffer(); const size = result.byteLength;
      const sizebuf = new Uint8Array([ (size >> 8) & 0xff, size & 0xff ]);
      console.log(`dns message length: ${size}`);
      chunk = await new Blob([ sizebuf, result ]).arrayBuffer();
      await down_writable.write(chunk);
    },
    close() {
      console.log("readable dns query close"); down_writable.close();
    } })).catch((error) => { console.log("readable dns query error", error); });
  remote_stream.writer = transform.writable.getWriter();
}

async function stream_pipetwo(obj, readable, writable) {
  let u_threshold = flow_conv(obj.flowu_ctl), u_totals = 0, u_count = 0;
  let d_threshold = flow_conv(obj.flowd_ctl), d_totals = 0, d_count = 0;
  let buffer = new Uint8Array(0), vls = {}, remote_stream = {}, is_dns = false;
  let down_header = null, down_closed = false, remote_closed = false;
  const remote_close = () => {
    if (remote_closed) { console.log("remote stream is closed"); return; }
    if (remote_stream.writer || remote_stream.socket) {
      try {
        console.log("remote stream close"); remote_closed = true;
        remote_stream?.writer?.close(); remote_stream?.socket?.close();
      } catch (error) { console.log("remote stream close error", error); }
    }
  };
  const down_writer = writable.getWriter(); /* download */
  const down_close = async () => {
    if (down_closed) { console.log("writable pipetwo is closed"); return; }
    console.log("writable pipetwo close");
    remote_close(); down_writer.close(); down_closed = true;
  };
  const down_write = async (chunk) => { /* to local */
    try {
      if (down_header) {
        chunk = chunkscat_arr8(down_header, new Uint8Array(chunk)).buffer;
        down_header = null;
      } await down_writer.write(chunk);
      d_totals += chunk.byteLength; if ((d_totals - d_count) > d_threshold) {
        await flow_step(d_totals); d_count = d_totals;
      }
    } catch (error) { console.log("writable pipetwo error", error); down_close(); }
  };
  const down_writable = { close: down_close, write: down_write };
  readable.pipeTo(new WritableStream({ /* upload */
    async write(chunk) {
      if (remote_stream.writer) { /* to remote */
        return remote_stream.writer.write(chunk);
      } else if (remote_stream.socket) {
        const writer = remote_stream.socket.writable.getWriter();
        try { await writer.write(chunk); } finally { writer.releaseLock(); }
        u_totals += chunk.byteLength; if ((u_totals - u_count) > u_threshold) {
          await flow_step(u_totals); u_count = u_totals;
        } return;
      }
      try { /* header parse */
        buffer = chunkscat_arr8(buffer, new Uint8Array(chunk));
        vls = vls_parse(buffer, obj.uuid);
        if (vls.error) throw `VLS error message: ${vls.message}`;
        if (vls.more) return; /* need more */
        console.log("VLS:", vls.host, vls.port, vls.is_udp ? "UDP" : "TCP");
        if (vls.is_udp) {
          if (vls.port !== 53) throw "UDP only support DNS query"; is_dns = true;
        } else { /* tcp socket */
          remote_stream.socket = await tcpsocket_connect(obj, vls.host, vls.port, vls.type);
          if (!remote_stream.socket) throw "tcpsocket connection failed";
        }
      } catch (error) { console.log(error); throw error; }
      buffer = buffer.slice(vls.offset);
      down_header = new Uint8Array([ vls.version, 0 ]);
      if (is_dns) { /* dns */
        dns_handle(obj, remote_stream, down_writable);
        return remote_stream.writer.write(buffer.buffer);
      } /* tcp */
      await remote_pipe(obj, remote_stream, down_writable, buffer.buffer);
    },
    close() { console.log("readable pipetwo close"); remote_close(); },
    abort(reason) { console.log("readable pipetwo abort", reason); }
  })).catch((error) => {
    console.log("readable pipetwo error", error); remote_close(); down_close();
  });
}

function ws_close(ws) {
  try { if (ws.readyState === 1 || ws.readyState === 1) ws.close();
  } catch (error) { console.log("websocket close error", error); }
}

function ws_make_readable(ws, request) {
  return new ReadableStream({
    start(controller) {
      ws.addEventListener("message", (event) => controller.enqueue(event.data));
      ws.addEventListener("close", () => {
        console.log("websocket close"); ws_close(ws); controller.close();
      });
      ws.addEventListener("error", (error) => {
        console.log("websocket error"); controller.error(error);
      });
      const ws_sec = request.headers.get("sec-websocket-protocol");
      if (ws_sec) { try {
          const decode = atob(ws_sec.replace(/-/g, '+').replace(/_/g, '/'));
          const array = Array.from(decode, (c) => c.charCodeAt(0));
          controller.enqueue(new Uint8Array(array).buffer);
        } catch(error) { controller.error(error); }
      }
    },
    cancel(reason) { console.log("readable stream canceled", reason); ws_close(ws); }
  });
}

async function ws_handle(obj, request) {
  const ws_pair = new WebSocketPair(); const [ client, ws ] = Object.values(ws_pair);
  ws.binaryType = "arraybuffer"; ws.accept();
  const readable = ws_make_readable(ws, request);
  const writable = new WritableStream({
    async write(chunk) { if (ws.readyState === 1) ws.send(chunk); },
    close() { console.log("writable stream close"); ws_close(ws); }
  });
  stream_pipetwo(obj, readable, writable);
  return new Response(null, { status: 101, webSocket: client });
}

async function xhttp_handle(obj, request) {
  const bridge = new IdentityTransformStream();
  stream_pipetwo(obj, request.body, bridge.writable);
  return new Response(bridge.readable, { status: 200, headers: {
    "Content-Type": "application/octet-stream",
    "Cache-Control": "no-store",
    "X-Accel-Buffering": "no"
    }});
}

function set_params(env, url) {
  const obj = {}, params = url.searchParams;
  obj.uuid = env.opt_uuid || opt_uuid;
  obj.dohurl = env.opt_dohurl || opt_dohurl;
  obj.proxy = env.opt_proxy || opt_proxy;
  obj.flowu_ctl = env.opt_flowu_ctl || opt_flowu_ctl;
  obj.flowd_ctl = env.opt_flowd_ctl || opt_flowd_ctl;
  const proxy = params.get("proxy"); if (proxy != null) {
    console.log("url param proxy:", proxy); obj.proxy = proxy;
  } const flowu_ctl = params.get("flowu_ctl"); if (flowu_ctl != null) {
    console.log("url param flowu_ctl:", flowu_ctl); obj.flowu_ctl = flowu_ctl;
  } const flowd_ctl = params.get("flowd_ctl"); if (flowd_ctl != null) {
    console.log("url param flowd_ctl:", flowd_ctl); obj.flowd_ctl = flowd_ctl;
  } return obj;
}

export default {
  async fetch(request, env, ctx) {
    try {
      const url = new URL(request.url);
      const obj = set_params(env, url);
      if (request.headers.get("sec-websocket-protocol")) {
        return await ws_handle(obj, request);
      } else if (request.method == "POST") {
        if (!request.body || !url.pathname.startsWith("/xhttp/"))
          return new Response("Not Found", { status: 404 });
        return await xhttp_handle(obj, request);
      }
      const hostname = request.headers.get("Host");
      switch (url.pathname) {
        case `/${obj.uuid}`:
          return new Response(await get_config(obj.uuid, hostname),
            { status: 200, headers: { "Content-Type": "text/html; charset=utf-8" } });
        case "/geoip":
          return new Response(await get_geoip(obj, request),
            { status: 200, headers: { "Content-Type": "application/json; charset=utf-8" } });
        default:
          return new Response(JSON.stringify(request.cf, null, 2),
            { status: 200, headers: { "Content-Type": "application/json; charset=utf-8" } });
      }
    } catch (error) {
      console.log("fetch error", error); return new Response(error.toString());
    }
  }
};

async function get_config(uuid, hostname) {
  return `${uuid} ${hostname}`;
}

async function get_geoip(obj, request) {
  const http_req = "GET /geoip HTTP/1.1\r\n" + "Host: api.ip.sb\r\n"
    + "Accept: application/json\r\n" + "Connection: close\r\n\r\n";
  const socket = await tcpsocket_connect(obj, "api.ip.sb", 443, 3);
  if (!socket) return JSON.stringify({ cf: request.cf, ipinfo: {} }, null, 2);
  const tls = new TLS12_Client(socket, { sni: "api.ip.sb" });
  await tls.handshake(); await tls.write(textencode(http_req));
  const chunks = [], http = new HTTP_Reader();
e:
  while (true) {
    const { value, done } = await tls.read(); if (value) http.put(value);
    while (true) {
      const chunk = http.get(); if (!chunk) break;
      chunks.push(chunk.body); if (chunk.done) break e;
    } if (done) break;
  }
  socket.close(); const body = textdecode(chunkscat_arr8(...chunks));
  return JSON.stringify({ cf: request.cf, ipinfo: JSON.parse(body) }, null, 2);
}
