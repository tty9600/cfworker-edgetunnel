//  The test example implementation of TLSv1.2 client on NodeJS/JavaScript.
//
//  Copyright (C) 2026 - Public Free Software
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

import { createConnection } from "node:net";
import { TLS12_Client, HTTP_Reader } from "./tls12_client.js";

class TCP_Socket {
  static connect(host, port) {
    return new Promise((resolve, reject) => {
      const socket = createConnection({ port, host });
      socket.once("connect", () => { resolve(new TCP_Socket(socket)); });
      socket.once("error", reject);
    });
  }

  constructor(socket) {
    this.socket = socket;
    this.closed = false;
    this.readable_controller = null;
    this.readable = new ReadableStream({
      start: (controller) => {
        this.readable_controller = controller;
        socket.on("data", chunk => {
          console.log("ReadableStream:", new Uint8Array(chunk));
          if (!this.closed) controller.enqueue(new Uint8Array(chunk));
        });
        socket.once("end", () => { this.close_readable(); });
        socket.once("close", () => { this.close_readable(); });
        socket.once("error", (error) => { this.error_readable(error); });
      },
      cancel: () => { socket.destroy(); }
    });
    this.writable = new WritableStream({
      write: (chunk) => {
        return new Promise((resolve, reject) => {
          console.log("WritableStream:", new Uint8Array(chunk));
          socket.write(chunk, (error) => {
            if (error) { reject(error); } else { resolve() };
          });
        });
      },
      close: () => { socket.end(); },
      abort: (reason) => { socket.destroy(reason); }
    });
  }

  close_readable() {
    try { this.readable_controller?.close(); } catch {}
  }

  error_readable(error) {
    try { this.readable_controller?.error(error); } catch {}
  }

  close() {
    if (this.closed) return;
    this.closed = true;
    this.close_readable();
    if (this.socket.writable) this.socket.end();
  }
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

(async () => {
  const http_req = "GET / HTTP/1.1\r\n" + `Host: github.com\r\n`
    + "Accept: text/html\r\n" + "Connection: close\r\n\r\n";
  const socket = await TCP_Socket.connect("github.com", 443);
  const tls = new TLS12_Client(socket, { sni: "github.com" });
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
  socket.close();
  const body = textdecode(chunkscat_arr8(...chunks));
  console.log(tls);
  console.log(http);
  console.log(body);
})();
