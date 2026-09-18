//  A simple proxy tunnel client implementation based on NodeJS/JavaScript.
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

const textencode = (str) => new TextEncoder().encode(str);
const textdecode = (str) => new TextDecoder().decode(str);

export async function HTTP_Tunnel(socket, target_host, target_port, user, pass) {
  const auth = (user && pass) ?
    `Proxy-Authorization: Basic ${btoa(`${user}:${pass}`)}\r\n` : "";
  const req = `CONNECT ${target_host}:${target_port} HTTP/1.1\r\n`
    + `Host: ${target_host}:${target_port}\r\n`
    + `${auth}User-Agent: Mozilla/5.0\r\n` + `Connection: keep-alive\r\n\r\n`;
  const writer = socket.writable.getWriter(), reader = socket.readable.getReader();
  try {
    await writer.write(textencode(req));
    const { done, value } = await reader.read();
    if (done) throw "HTTP connect tunnel close";
    const x = textdecode(new Uint8Array(value));
    const e = x.match(/\r\n\r\n/); if (!e) throw "HTTP response header error";
    const y = x.slice(0, e?.index), s = y.split("\r\n")[0];
    console.log("HTTP response status:", s);
    if (s.split(" ")[1] != "200") throw "HTTP response code != 200 connection failed";
    console.log("HTTP connection OK!"); writer.releaseLock(); reader.releaseLock();
  } catch (error) {
    console.log(error); writer.releaseLock(); reader.releaseLock(); socket.close();
    return null;
  } return socket;
}

export async function Socks5_Tunnel(socket, target_host, target_port, user, pass) {
  const auth_method = (user && pass) ? new Uint8Array([ 0x05, 0x02, 0x00, 0x02 ])
    : new Uint8Array([ 0x05, 0x01, 0x00 ]);
  const writer = socket.writable.getWriter(), reader = socket.readable.getReader();
  const client_request = async () => {
    await writer.write(auth_method);
    const { value, done } = await reader.read();
    if (done) throw "Socks5 connect tunnel close";
    if (value.byteLength < 2) throw "Socks5 response method error";
    return new Uint8Array(value)[1];
  };
  const client_auth = async (method) => {
    if (method == 0x02) {
      if (!user|| !pass) throw "Socks5 requires authentication";
      user = textencode(user); pass = textencode(pass);
      await writer.write(new Uint8Array([ 0x01, user.length, ...user, pass.length, ...pass ]));
      const { value, done } = await reader.read();
      if (done || new Uint8Array(value)[1] !== 0x00) throw "Socks5 authentication failed";
    } else if (method != 0x00) throw `Socks5 authentication method error: ${method}`;
  };
  const client_connect = async () => {
    target_host = textencode(target_host);
    await writer.write(new Uint8Array([ 0x05, 0x01, 0x00, 0x03,
      target_host.length, ...target_host, target_port >> 8, target_port & 0xff ]));
    const { value, done } = await reader.read();
    if (done || new Uint8Array(value)[1] !== 0x00) throw "Socks5 connection failed";
  };
  try {
    await client_auth(await client_request()); await client_connect();
    console.log("Socks5 connection OK!"); writer.releaseLock(); reader.releaseLock();
  } catch (error) {
    console.log(error); writer.releaseLock(); reader.releaseLock(); socket.close();
    return null;
  } return socket;
}
