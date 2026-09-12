The edge tunnel implementation based on Cloudflare Worker, and using VLESS as the
proxy protocol.

 > Support NAT64/ProxyIP to bypass Cloudflare CDN network restrictions.
 > UDP only support DNS 53 port.
 > Flow control can be used to alleviate CPU time limits.

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
 |opt_prefix64     |nat64 proxy prefix ip                     |
 |opt_proxyip      |reverse proxy ip                          |
 |opt_proxyip_port |reverse proxy port                        |
 |opt_flowu_ctl    |flow upload control threshold (byte/K/M)  |
 |opt_flowd_ctl    |flow download control threshold (byte/K/M)|

 opt_prefix64 < env.opt_prefix64 < url prefix64 -- empty value disable nat64
 opt_proxyip < env.opt_proxyip < url proxyip < NAT64 -- empty value disable proxyip
 opt_proxyip_port < env.opt_proxyip_port < url proxyip_port -- empty value use remote

 opt_flowu_ctl < env.opt_flowu_ctl < url flowu_ctl -- empty value default
 opt_flowd_ctl < env.opt_flowd_ctl < url flowd_ctl -- empty value default

 is_fproxyip=1 -- force use nat64/proxyip (test use, all traffic is relayed through nat64)

 ws_path config prefix64: /?ed=2048&prefix64=2602:fc59:11:64::
 ws_path config proxyip: /?ed=2048&prefix64=&proxyip=<ProxyIP>&proxyip_port=

Tools

 clash-proxy-yaml.sh -- generate the Clash proxy YAML config

Src

 ref_worker.js    -- Reference implementation
 _worker.js       -- The _worker.js of merged and compressed
 worker.js        -- Edge tunnel implementation with speed limit
 tls12_client.js  -- A simple implementation of TLSv1.2 client
 tls12_example.js -- Test example of TLSv1.2 client on NodeJS

Reference

 EDtunne of 3Kmfi6HP
  ref_worker.js
   https://github.com/3Kmfi6HP/EDtunne

Licenses

 GPLv3

Copyright

 2025-2026 - Public Free Software
