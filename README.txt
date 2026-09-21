The edge tunnel implementation based on Cloudflare Worker, and using VLESS as the
proxy protocol.

 > Support NAT64/ProxyIP to bypass Cloudflare CDN network restrictions.
 > UDP only support DNS 53 port.
 > Flow control can be used to alleviate CPU time limits.
 > Supported transport stream modes: WebSocket and XHTTP stream-one (grpc).

Intention

 Used to circumvent regulatory restrictions, such as firewall restrictions in China,
 Russia, and Iran, as well as content restrictions.

NAT64

 |NAT64 prefix            |Provider      |       Country / City       |
 |------------------------|--------------|----------------------------|
 |2602:fc59:b0:64::       |ZTVI          | United States / Fremont    |
 |2602:fc59:11:64::       |ZTVI          | United States / Howard     |
 |2602:fc59:20:64::       |ZTVI          | United States / Albuquerque|
 |2a02:898:146:64::       |IPng          |   Netherlands / Amsterdam  |
 |2001:67c:2b0:db32::     |Trex          |       Finland / Helsinki   |
 |2a01:4f9:c010:3f02:64:: |Kasper Dupont |       Finland / Helsinki   |
 |2a00:1098:2b::1:        |Kasper Dupont |   Netherlands / Amsterdam  |
 |2a00:1098:2c::5:        |Kasper Dupont |United Kingdom / Cambridge  |
 |2001:67c:2960:6464::    |level66       |       Germany / Berlin     |

ProxyIP

 From Cloudflare internal Wrap proxyip

  172.71.218.190 162.158.228.87  162.158.189.134 162.158.26.63  162.158.25.86
  162.158.29.216 162.158.218.160 162.158.227.214 172.69.118.198 172.69.119.150

Variable

 |Variable         |Description                               |
 |-----------------|------------------------------------------|
 |opt_uuid         |vless userid                              |
 |opt_dohurl       |used for UDP:53 dns query (DoH)           |
 |opt_proxy        |proxy url parameter                       |
 |opt_flowu_ctl    |flow upload control threshold (byte/K/M)  |
 |opt_flowd_ctl    |flow download control threshold (byte/K/M)|

 opt_proxy < env.opt_proxy < url proxy -- empty disable proxy

 proxyip://[<addr>[:<port>]]/[prefix64=<prefix>]/[all=[1]]
 http://<addr>[:<port>]/[user=username]/[pass=password]/[all=[1]]
 https://<addr>[:<port>]/[user=username]/[pass=password]/[all=[1]]
 socks5://<addr>[:<port>]/[user=username]/[pass=password]/[all=[1]]

 all=1             -- global proxy all traffic
 user=username     -- proxy authentication username
 pass=password     -- proxy authentication password
 prefix64=<prefix> -- nat64 prefix address

 NAT64 conversion failed, auto downgrade: prefix64 -> proxyip -> direct

 opt_flowu_ctl < env.opt_flowu_ctl < url flowu_ctl -- empty value default
 opt_flowd_ctl < env.opt_flowd_ctl < url flowd_ctl -- empty value default

 ws_path config prefix64: /?ed=2048&proxy=proxyip:///prefix64=2602:fc59:11:64::
 ws_path config proxyip: /?ed=2048&proxy=proxyip://172.71.218.190
 xhttp_path: /xhttp/

Tools

 proxy-config.sh -- generate the proxy config for Clash and V2ray for Workers

Src

 ref_worker.js    -- Reference implementation
 worker.js        -- Edge tunnel implementation with speed limit
 tls12_client.js  -- A simple implementation of TLSv1.2 client
 tls12_example.js -- Test example of TLSv1.2 client on NodeJS
 tunnel_client.js -- A simple implementation of Tunnel client

Reference

 EDtunne of 3Kmfi6HP
  ref_worker.js
   https://github.com/3Kmfi6HP/EDtunne

Licenses

 GPLv3

Copyright

 2025-2026 - Public Free Software
