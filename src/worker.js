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

const opt_uuid = "98f475f4-bd96-49f6-98af-9e16103b5ec2";
const opt_dohurl = "https://dns.google/dns-query";
const opt_prefix64 = "";
const opt_proxyip = "172.71.218.190";
const opt_proxyip_port = "";
const opt_flowu_ctl = "1M";
const opt_flowd_ctl = "1M";

const WS_READY_STATE_OPEN = 1;
const WS_READY_STATE_CLOSING = 2;
const FLOW_CTL_DEFAULT_DELAY = 300;
const FLOW_CTL_EXTRA_DELAY = 500;
const FLOW_CTL_DELAY_STEPS = [
  { size:   1 * 1024 * 1024, delay: 320 },
  { size:  50 * 1024 * 1024, delay: 340 },
  { size: 100 * 1024 * 1024, delay: 360 },
  { size: 200 * 1024 * 1024, delay: 400 }
  ];

function flow_conv(a) { /* convert to bytes */
  if (Number(a)) return parseInt(a); const q = a.match(/^(\d+)\.?(\d+)?(K|M)?$/);
  if (!q) return 65536; let n = parseInt(q[1]), d = parseInt(q[2]), p;
  p = (q[3] == "K") ? 1024 : ((q[3] == "M") ? 1024 * 1024 : 1); n *= p;
  if (d) { n += d * p / Math.pow(10, q[2].length); } return Math.trunc(n);
}

function flow_step(totals) { /* sleep */
  const delay = () => {
    for (let i = FLOW_CTL_DELAY_STEPS.length - 1; i >= 0; i--) {
      const step = FLOW_CTL_DELAY_STEPS[i];
      if (totals >= step.size) return step.delay + FLOW_CTL_EXTRA_DELAY;
    } return FLOW_CTL_DEFAULT_DELAY + FLOW_CTL_EXTRA_DELAY;
  }; return new Promise(resolve => setTimeout(resolve, delay()));
}

function get_proxyip(obj) {
  return obj.proxyip64 || obj.proxyip || null;
}

function get_proxyip_port(obj) {
  if (obj.proxyip64 || !obj.proxyip || !obj.proxyip_port) return null;
  return parseInt(obj.proxyip_port) || null;
}

async function get_domain_ipv4(domain) {
  try {
    const resp = await fetch(`https://1.1.1.1/dns-query?name=${domain}&type=A`,
      { headers: { "Accept": "application/dns-json" } });
    const res = await resp.json();
    if (res.Answer && res.Answer.length > 0) {
      const a = res.Answer.find(record => record.type === 1); if (a) return a.data;
    }
  } catch (error) { console.log("proxyip domain query error", domain, error); }
  return null;
}

async function set_proxyip64(obj, address, address_type) { /* nat64 */
  obj.proxyip64 = null; if (!obj.prefix64) return;
  switch (address_type) {
    case 2: address = await get_domain_ipv4(address); if (!address) break;
    case 1: const s = new Uint8Array(address.split('.'));
      const a = Array.from(s).map(byte => byte.toString(16).padStart(2, '0'));
      obj.proxyip64 = `[${obj.prefix64}${a[0]}${a[1]}:${a[2]}${a[3]}]`;
  }
}

function vls_parser(buf, uuid) {
  if (buf.byteLength < 24) return { error: true, message: "invalid data" };
  let offset = 1, is_udp = false, address = null;
  const version = new Uint8Array(buf.slice(0, 1))[0];
  const arruuid = new Uint8Array(buf.slice(offset, offset + 16)); offset += 16;
  const struuid = Array.from(arruuid) /* user id */
    .map(byte => byte.toString(16).padStart(2, '0')).join('');
  const _uuid = Array.from(uuid).filter(char => char !== '-').join('');
  if (struuid !== _uuid) return { error: true, message: `invalid user: ${struuid}` };
  offset += 1 + new Uint8Array(buf.slice(offset, offset + 1))[0];
  const command = new Uint8Array(buf.slice(offset, offset + 1))[0]; offset += 1;
  switch (command) { /* 1: tcp, 2: udp, 3: mux */
    case 1: is_udp = false; break;
    case 2: is_udp = true; break;
    case 3: return { error: true, message: "invalid command: 3 is not support" };
    default: return { error: true, message: `invalid command: ${command}` };
  }
  const port = new DataView(buf.slice(offset, offset + 2)).getUint16(0); offset += 2;
  const address_type = new Uint8Array(buf.slice(offset, offset + 1))[0]; offset += 1;
  switch (address_type) { /* 1: ipv4, 2: domain, 3: ipv6 */
    case 1: if (buf.byteLength < (offset + 4)) break;
      address = new Uint8Array(buf.slice(offset, offset + 4)).join('.'); offset += 4;
      break;
    case 2: const domain_len = new Uint8Array(buf.slice(offset, offset + 1))[0];
      if (buf.byteLength < (offset + 1 + domain_len)) break;
      address = new TextDecoder().decode(buf.slice(offset + 1, offset + 1 + domain_len));
      offset += 1 + domain_len;
      break;
    case 3: if (buf.byteLength < (offset + 16)) break;
      address = []; const ipv6 = new DataView(buf.slice(offset, offset + 16));
      for (let i = 0; i < 8; i++) {
        address.push(ipv6.getUint16(i * 2).toString(16).padStart(4, '0'));
      } address = '[' + address.join(':') + ']'; offset += 16;
      break;
  } if (!address) return { error: true, message: "invalid address" };
  return { error: false, address_type: address_type, address: address, port: port,
    offset: offset, version: version, is_udp: is_udp };
}

async function dns_handle(obj, remote_stream, ws, header) {
  let is_header = false;
  const tf_stream = new TransformStream({
    transform(chunk, controller) {
      for (let i = 0; i < chunk.byteLength; ) {
        const buffer = chunk.slice(i, i + 2);
        const length = new DataView(buffer).getUint16(0);
        const data = new Uint8Array(chunk.slice(i + 2, i + 2 + length));
        i += 2 + length; controller.enqueue(data);
      }
    } });
  tf_stream.readable.pipeTo(new WritableStream({ /* to ws */
    async write(chunk) {
      const resp = await fetch(obj.dohurl, { method: "POST",
        headers: { "content-type": "application/dns-message" }, body: chunk });
      const result = await resp.arrayBuffer(); const size = result.byteLength;
      const size_buffer = new Uint8Array([ (size >> 8) & 0xff, size & 0xff ]);
      if (ws.readyState === WS_READY_STATE_OPEN) {
        console.log(`dns message length is ${size}`);
        if (is_header) {
          ws.send(await new Blob([ size_buffer, result ]).arrayBuffer());
        } else {
          ws.send(await new Blob([ header, size_buffer, result ]).arrayBuffer());
          is_header = true;
        }
      } else { console.log("websocket is not open (dns)"); }
    } })).catch((error) => { console.log("dns query error", error); });
  remote_stream.writer = tf_stream.writable.getWriter();
}

async function remote_pipe(obj, remote_socket, ws, header, retry) {
  let threshold = flow_conv(obj.flowd_ctl), totals = 0, count = 0, is_header = false;
  await remote_socket.readable.pipeTo(new WritableStream({ /* to ws */
    async write(chunk, controller) {
      if (ws.readyState === WS_READY_STATE_OPEN) {
        if (is_header) { ws.send(chunk); } else {
          ws.send(await new Blob([ header, chunk ]).arrayBuffer()); is_header = true;
        } totals += chunk.byteLength;
        if ((totals - count) > threshold) { await flow_step(totals); count = totals; }
      } else { controller.error("websocket is not open (tcp)"); }
    },
    close() {
      console.log("remote connection readable is close (tcp)"); if (is_header) ws_close(ws);
    },
    abort(reason) { console.log("remote connection readable is abort (tcp)", reason); }
  })).catch((error) => {
    console.log("remote to websocket error (tcp)", error); ws_close(ws);
  });
  if (!is_header && retry) { console.log("retry!"); retry(); }
}

async function tcp_handle(obj, remote_stream, ws, header, remote_address, remote_port, data) {
  if (obj.is_fproxyip) remote_address = get_proxyip(obj) || remote_address;
  const connect_and_write = async (address, port) => {
    console.log(`tcpsocket connect to ${address}:${port}`);
    const tcp_socket = connect({ hostname: address, port: port });
    remote_stream.writer = tcp_socket; const writer = tcp_socket.writable.getWriter();
    await writer.write(data); writer.releaseLock(); return tcp_socket;
  };
  const retry = async () => {
    remote_address = get_proxyip(obj) || remote_address;
    remote_port = get_proxyip_port(obj) || remote_port;
    const tcp_socket = await connect_and_write(remote_address, remote_port);
    tcp_socket.closed.catch((error) => { console.log("retry tcpsocket closed error", error);
    }).finally(() => { ws_close(ws); });
    remote_pipe(obj, tcp_socket, ws, header, null);
  };
  const tcp_socket = await connect_and_write(remote_address, remote_port);
  remote_pipe(obj, tcp_socket, ws, header, retry);
}

function ws_close(ws) {
  try {
    if (ws.readyState === WS_READY_STATE_OPEN || ws.readyState === WS_READY_STATE_CLOSING)
      ws.close();
  } catch (error) { console.log("websocket close error", error); }
}

async function ws_handle(obj, request) {
  const ws_pair = new WebSocketPair(); const [ client, ws ] = Object.values(ws_pair);
  ws.binaryType = "arraybuffer"; ws.accept(); let remote_stream = { writer: null };
  let threshold = flow_conv(obj.flowu_ctl), totals = 0, count = 0, is_dns = false;
  const ws_stream = new ReadableStream({
    start(controller) {
      ws.addEventListener("message", (event) => { controller.enqueue(event.data); });
      ws.addEventListener("close", () => {
        console.log("websocket server close"); ws_close(ws); controller.close();
      });
      ws.addEventListener("error", (error) => {
        console.log("websocket server error"); controller.error(error);
      });
      const ws_sec = request.headers.get("sec-websocket-protocol");
      if (ws_sec) { try {
          const decode = atob(ws_sec.replace(/-/g, '+').replace(/_/g, '/'));
          const array = Array.from(decode, (c) => c.charCodeAt(0));
          controller.enqueue(new Uint8Array(array).buffer);
        } catch(error) { controller.error(error); }
      }
    },
    cancel(reason) { console.log("readable stream is canceled", reason); ws_close(ws); }
  });
  ws_stream.pipeTo(new WritableStream({
    async write(chunk, controller) {
      if (is_dns && remote_stream.writer) { /* to dns */
        return remote_stream.writer.write(chunk);
      } else if (remote_stream.writer) { /* to tcp */
        const writer = remote_stream.writer.writable.getWriter();
        await writer.write(chunk); writer.releaseLock(); totals += chunk.byteLength;
        if ((totals - count) > threshold) { await flow_step(totals); count = totals; }
        return;
      }
      const res = vls_parser(chunk, obj.uuid); /* parser */
      if (res.error) throw new Error(`VLS error message: ${res.message}`);
      console.log("VLS:", res.address, res.port, res.is_udp ? "UDP" : "TCP");
      const header = new Uint8Array([ res.version, 0 ]);
      const data = chunk.slice(res.offset);
      if (res.is_udp) { /* dns */
        if (res.port !== 53) throw new Error("UDP only support DNS query");
        await dns_handle(obj, remote_stream, ws, header);
        remote_stream.writer.write(data); is_dns = true;
      } else { /* tcp */
        await set_proxyip64(obj, res.address, res.address_type);
        tcp_handle(obj, remote_stream, ws, header, res.address, res.port, data);
      }
    },
    close() { console.log("readable websocket stream is close"); },
    abort(reason) { console.log("readable websocket stream is abort", reason); }
  })).catch((error) => { console.log("readable websocket stream pipeto error", error); });
  return new Response(null, { status: 101, webSocket: client });
}

function url_params(obj, params) {
  const prefix64 = params.get("prefix64"); if (prefix64 != null) {
    console.log("url param prefix64:", prefix64); obj.prefix64 = prefix64;
  } const proxyip = params.get("proxyip"); if (proxyip != null) {
    console.log("url param proxyip:", proxyip); obj.proxyip = proxyip;
  } const proxyip_port = params.get("proxyip_port"); if (proxyip_port != null) {
    console.log("url param proxyip_port:", proxyip_port); obj.proxyip_port = proxyip_port;
  } const is_fproxyip = params.get("is_fproxyip"); if (is_fproxyip === "1") {
    console.log("url param is_fproxyip:", is_fproxyip); obj.is_fproxyip = is_fproxyip;
  } const flowu_ctl = params.get("flowu_ctl"); if (flowu_ctl != null) {
    console.log("url param flowu_ctl:", flowu_ctl); obj.flowu_ctl = flowu_ctl;
  } const flowd_ctl = params.get("flowd_ctl"); if (flowd_ctl != null) {
    console.log("url param flowd_ctl:", flowd_ctl); obj.flowd_ctl = flowd_ctl;
  }
}

export default {
  async fetch(request, env, ctx) {
    try {
      let obj = {};
      obj.uuid = env.opt_uuid || opt_uuid;
      obj.dohurl = env.opt_dohurl || opt_dohurl;
      obj.prefix64 = env.opt_prefix64 || opt_prefix64;
      obj.proxyip = env.opt_proxyip || opt_proxyip;
      obj.proxyip_port = env.opt_proxyip_port || opt_proxyip_port;
      obj.flowu_ctl = env.opt_flowu_ctl || opt_flowu_ctl;
      obj.flowd_ctl = env.opt_flowd_ctl || opt_flowd_ctl;
      const url = new URL(request.url);
      url_params(obj, url.searchParams);
      if (request.headers.get("sec-websocket-protocol")) {
        return await ws_handle(obj, request);
      }
      const hostname = request.headers.get("Host");
      switch (url.pathname) {
        case `/${obj.uuid}`:
          return new Response(await get_config(obj.uuid, hostname),
            { status: 200, headers: { "Content-Type": "text/html; charset=utf-8" } });
        case "/geoip":
          return new Response(await get_geoip(request, obj.proxyip),
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

async function get_geoip(request, host) {
  const http_req = "GET /geoip HTTP/1.1\r\n" + "Host: api.ip.sb\r\n"
    + "Accept: application/json\r\n" + "Connection: close\r\n\r\n";
  const socket = connect({ hostname: host || "172.71.218.190", port: 443 });
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
