# Threat Hunting News Package

- Generated: `2026-10-18T01:00:48+00:00`
- Generator: `THNewsCaster v0.1.0`
- Articles seen: **385**  ·  Skipped (below threshold): **385**  ·  Briefings: **50**
- IOC exports: `iocs.csv`, `iocs.json`, `iocs_stix.json`  ·  Sigma rules: `sigma/`  ·  History: `archive/`

---

## 1. Chinese Government-linked Cyber Threat Actors Combine Automated and Hands-on Hacking Tools to Steal Sensitive Data

- **Source**: CISA Advisories
- **Link**: <https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-281a>
- **Published**: Thu, 08 Oct 26 12:00:00 +0000
- **First seen**: 2026-10-08T17:54:37+00:00
- **Relevance score**: 138
- **Score rationale**: source weight (advisory)=+15, 8 CVE(s)=+30, 1 threat actor hit(s)=+20, 9 MITRE technique hit(s)=+20, 4 initial-access vector(s)=+13, 4 impact action(s)=+15, 5 product mention(s)=+10, 842 IOC(s)=+15

> Advisory at a Glance Title Chinese Government-linked Cyber Threat Actors Combine Automated and Hands-on Hacking Tools to Steal Sensitive Data Original Publication October 8, 2026 Executive Summary Chinese government-linked cyber threat actors, enabled by the Integrity Technology Group, are combining automated scanning tools, large-scale botnets, and hands-on exploitation techniques to target and steal sensitive data from organizations worldwide, including US critical infrastructure sectors. These actors exploit vulnerabilities by using scanning tools, cross-site scripting attacks, and password spraying on Microsoft Exchange servers, while establishing persistence through VPN software and exfiltrating emails and credentials using scripts. To help mitigate against this activity, organizations should prioritize disabling unused services and ports, sanitizing web application inputs to prevent injection attacks, implementing multifactor authentication for all services, and applying timely patches to reduce risks of compromise. Affected Products CVE-2014-6278 CVE-2015-3306 CVE-2015-5477 CVE-2016-3081 CVE-2019-11510 CVE-2021-22205 CVE-2021-3199 CVE-2023-22894 Key Actions Disable unused services and ports , such as automatic configuration, remote access, or file sharing protocols. Sanitize user input in web applications to prevent possible cross-site scripting (XSS) payload injection. Implement identity, credential, and access management (ICAM) policies , and then require multifactor

**Extracted signals**
- CVEs: CVE-2014-6278, CVE-2015-3306, CVE-2015-5477, CVE-2016-3081, CVE-2019-11510, CVE-2021-22205, CVE-2021-3199, CVE-2023-22894
- Threat actors: Flax Typhoon
- Products: Microsoft Exchange, Active Directory, Ivanti Connect Secure, GitLab, Apache Struts
- Vectors: phishing, exploit, vpn-edge, rdp
- Actions: ransomware, data-breach, ddos, fraud
- Sectors: healthcare, government, energy, manufacturing, education, telecom
- MITRE ATT&CK: T1566, T1133, T1059, T1059.001, T1003, T1021.001, T1486, T1110, T1505.003
- IP IOCs: 149.28.132.137, 1.34.140.5, 2.58.242.74, 5.188.34.134, 5.188.230.69, 8.219.119.5, 14.1.98.160, 14.128.33.8, 14.1.98.223, 27.154.215.126, 27.154.105.36, 27.149.115.78, 27.149.79.35, 31.232.221.35, 36.112.10.102, 36.112.188.119, 36.112.186.135, 36.112.206.121, 36.249.156.117, 36.249.156.122, 36.249.156.159, 36.249.156.178, 36.249.156.205, 36.249.156.206, 36.249.156.220, 36.249.156.226, 36.112.200.35, 36.249.156.51, 36.112.198.68, 36.249.156.69, 36.112.10.99, 39.72.220.221, 42.73.98.232, 45.123.189.19, 45.32.140.182, 45.32.232.146, 45.63.123.142, 45.63.116.190, 45.131.69.197, 45.76.169.12, 45.77.195.169, 45.32.61.246, 45.77.231.209, 45.76.37.168, 45.63.59.121, 45.77.11.47, 45.32.84.223, 45.63.62.217, 45.63.48.36, 45.76.43.37, 45.76.66.19, 45.76.243.67, 45.63.17.9, 45.77.28.77, 45.76.194.89, 45.76.37.85, 45.63.95.62, 45.63.94.71, 45.77.86.70, 49.93.136.14, 49.93.184.194, 59.120.144.153, 59.124.120.178, 59.120.167.25, 59.125.128.54, 59.120.58.176, 60.250.199.112, 60.250.146.19, 60.251.155.19, 60.248.152.204, 59.120.82.67, 60.184.242.224, 60.251.205.37, 60.220.43.193, 60.251.58.145, 60.248.1.64, 60.251.201.8, 60.248.88.151, 60.248.110.97, 60.249.239.86, 61.220.112.137, 60.220.84.41, 61.247.165.27, 60.220.84.63, 61.220.35.15, 61.221.55.4, 61.222.245.73, 61.219.118.99, 61.216.74.97, 64.176.38.35, 65.20.97.251, 66.42.103.188, 66.42.42.109, 66.42.40.189, 66.42.36.236, 66.42.60.242, 66.42.77.138, 77.111.226.5, 78.141.221.241, 78.141.238.97, 84.17.57.40, 89.187.163.216, 95.179.189.106, 95.179.235.135, 95.179.186.251, 98.159.37.4, 103.107.198.117, 103.16.231.220, 103.16.231.254, 103.233.253.197, 103.25.254.210, 103.149.200.44, 103.179.45.203, 103.73.160.232, 103.77.211.193, 103.106.230.88, 103.172.80.35, 104.238.149.146, 104.238.182.153, 104.238.152.209, 103.51.145.98, 103.73.162.99, 104.156.231.98, 106.53.181.231, 106.122.171.92, 108.61.181.104, 108.61.177.81, 110.42.10.148, 110.85.170.125, 111.203.153.245, 110.74.172.80, 111.55.138.141, 111.55.137.40, 111.203.153.95, 112.5.168.102, 112.5.168.104, 112.5.145.154, 112.5.143.161, 112.5.168.138, 112.5.168.151, 112.5.168.160, 112.54.132.162, 112.5.168.187, 112.5.168.218, 112.5.168.231, 112.5.168.234, 112.5.168.238, 112.51.26.151, 112.66.108.16, 112.5.168.29, 112.51.44.102, 112.51.44.142, 112.51.44.143, 112.51.44.188, 112.51.44.189, 112.51.44.20, 112.51.44.206, 112.51.44.217, 112.51.44.234, 112.5.168.65, 112.51.44.37, 112.80.50.138, 112.51.44.57, 112.5.168.93, 113.76.136.171, 114.246.237.111, 114.255.70.18, 114.255.70.20, 114.255.70.30, 114.246.93.103, 114.246.94.102, 114.35.122.83, 114.246.94.154, 114.246.92.58, 114.246.92.71, 117.133.51.176, 117.61.244.135, 117.56.214.246, 117.132.198.70, 117.92.127.132, 117.130.201.90, 118.163.217.199, 118.163.197.241, 118.163.31.226, 118.163.104.67, 118.163.142.80, 118.163.3.76, 119.116.159.217, 119.13.79.145, 120.233.10.212, 120.36.251.100, 120.36.248.104, 120.42.128.165, 120.36.250.103, 120.36.254.100, 120.36.248.109, 120.36.253.106, 120.36.255.105, 120.36.251.110, 120.36.251.11, 120.36.249.114, 120.36.251.114, 120.36.254.112, 120.36.249.121, 120.36.249.122, 120.36.254.119, 120.36.254.120, 120.36.249.127, 120.36.251.130, 120.36.255.127, 120.36.252.13, 120.36.250.133, 120.36.250.134, 120.36.250.135, 120.36.254.131, 120.36.254.135, 120.36.251.141, 120.36.250.142, 120.41.125.225, 120.36.253.148, 120.36.250.152, 120.36.252.151, 120.36.253.152, 120.36.254.151, 120.36.255.153, 120.36.252.157, 120.37.162.246, 120.36.252.166, 120.36.249.172, 120.36.253.169, 120.36.252.175, 120.36.254.175, 120.36.251.179, 120.36.253.178, 120.36.252.18, 120.36.252.181, 120.36.248.185, 120.36.253.180, 120.36.255.179, 120.36.253.186, 120.36.253.187, 120.36.250.19, 120.36.251.19, 120.36.251.190, 120.36.255.189, 120.41.244.15, 120.36.254.192, 120.36.249.197, 120.36.248.200, 120.36.253.195, 120.36.251.2, 120.36.251.20, 120.36.255.196, 120.36.251.202, 120.36.254.202, 120.36.250.207, 120.36.250.210, 120.36.249.213, 120.36.251.213, 120.36.253.212, 120.36.251.215, 120.36.252.215, 120.36.255.214, 120.36.250.221, 120.36.255.22, 120.36.251.230, 120.36.255.228, 120.36.253.23, 120.36.253.231, 120.36.251.234, 120.36.248.237, 120.36.253.232, 120.36.253.233, 120.36.249.238, 120.36.251.237, 120.36.255.233, 120.36.255.237, 120.36.249.245, 120.36.252.242, 120.36.255.24, 120.36.249.248, 120.36.250.247, 120.36.253.247, 120.36.253.248, 120.36.251.25, 120.36.251.254, 120.36.249.28, 120.36.251.3, 120.36.251.30, 120.36.254.3, 120.36.254.32, 120.36.249.33, 120.36.250.4, 120.36.250.43, 120.36.249.47, 120.36.248.48, 120.36.250.48, 120.36.249.52, 120.36.250.53, 120.36.249.54, 120.36.251.54, 120.36.249.55, 120.36.251.56, 120.36.248.57, 120.36.250.58, 120.36.250.6, 120.36.253.6, 120.36.254.63, 120.36.250.65, 120.36.251.65, 120.36.250.67, 120.36.252.69, 120.36.248.73, 120.36.255.74, 120.36.250.76, 120.41.222.74, 120.36.248.80, 120.36.251.80, 120.36.251.84, 120.36.252.90, 120.36.249.91, 120.36.251.91, 120.36.252.91, 120.36.254.92, 120.36.254.94, 120.36.248.97, 120.36.251.97, 120.36.249.98, 120.36.252.98, 121.207.60.123, 122.116.33.118, 122.232.149.231, 122.201.241.230, 122.116.159.52, 122.116.102.93, 123.121.157.240, 123.51.237.194, 123.252.121.7, 123.252.122.7, 123.12.90.227, 123.60.61.104, 124.126.158.130, 124.126.139.199, 124.127.17.171, 124.127.220.223, 124.150.135.3, 123.51.223.96, 124.64.22.13, 124.126.141.74, 124.127.78.22, 124.127.72.52, 125.227.147.106, 125.227.140.168, 125.227.1.220, 125.227.196.157, 125.227.219.145, 125.228.239.13, 125.227.218.2, 124.64.23.80, 125.229.172.48, 125.227.136.60, 137.220.34.137, 137.220.39.222, 137.220.43.47, 137.220.36.87, 138.199.62.148, 139.180.137.219, 139.180.217.19, 139.180.158.51, 139.84.174.129, 140.82.27.163, 140.82.50.151, 141.164.41.128, 140.82.48.6, 141.164.55.227, 141.164.56.93, 144.202.26.205, 144.34.171.162, 144.202.33.164, 144.202.62.109, 144.202.91.107, 144.202.94.216, 144.202.98.41, 147.139.133.246, 149.28.132.161, 149.28.201.146, 149.28.188.184, 149.248.34.100, 149.28.149.29, 149.28.252.19, 149.248.38.179, 149.248.39.202, 149.248.44.191, 149.248.51.22, 149.28.72.106, 155.138.155.170, 155.138.136.190, 155.138.151.225, 155.138.133.56, 156.146.45.152, 156.146.45.194, 158.247.197.28, 159.138.152.61, 162.14.178.86, 167.172.33.16, 167.179.87.215, 167.179.97.121, 171.120.88.137, 178.62.208.162, 180.122.149.177, 182.34.19.234, 183.240.139.216, 183.253.28.104, 183.253.29.110, 183.253.28.121, 183.250.213.20, 183.253.29.189, 183.250.213.55, 183.253.29.66, 183.253.28.67, 183.250.213.80, 183.250.213.83, 183.166.90.97, 185.216.118.71, 185.135.73.192, 185.213.82.239, 185.213.82.243, 185.213.82.55, 185.213.82.65, 190.92.241.15, 191.232.188.144, 193.42.24.68, 193.42.25.73, 198.13.38.211, 202.182.109.151, 202.101.145.22, 202.182.106.31, 202.39.151.239, 202.99.19.250, 202.99.19.254, 203.74.126.20, 203.69.36.122, 207.246.118.144, 207.246.117.149, 207.246.114.173, 207.148.68.131, 207.148.122.69, 207.148.67.146, 207.246.108.64, 207.246.127.64, 207.148.73.238, 207.148.92.220, 207.148.4.96, 208.72.154.55, 210.242.152.155, 210.242.38.241, 210.243.225.41, 210.66.220.39, 210.242.76.32, 210.71.166.50, 211.20.144.116, 211.20.104.187, 211.21.19.11, 211.22.143.228, 211.20.115.60, 211.20.154.60, 211.20.100.78, 211.20.100.79, 211.99.103.102, 211.21.61.46, 211.75.185.37, 211.99.103.243, 212.107.28.16, 212.107.28.22, 212.107.28.23, 211.78.84.17, 211.20.91.77, 211.99.100.90, 211.99.100.91, 211.99.98.197, 216.128.149.106, 216.128.128.238, 218.26.159.254, 218.5.173.137, 218.5.157.171, 218.66.163.188, 219.143.179.250, 220.128.108.164, 220.130.153.127, 220.130.176.23, 220.128.125.3, 220.130.254.251, 219.92.229.53, 220.162.9.150, 220.250.44.62, 221.218.143.112, 221.218.136.12, 221.218.138.123, 221.218.143.122, 221.218.143.184, 221.218.136.192, 221.216.116.238, 221.218.137.229, 221.218.139.248, 221.216.208.188, 221.218.142.26, 221.218.141.96, 222.92.153.125, 223.104.40.128, 223.104.41.13, 223.104.40.142, 223.104.40.204, 223.27.34.132, 223.104.55.183, 223.104.39.82, 2.3.20.2, 2.3.24.1
- Domain IOCs: diagtrack.exe, dns.studiocloud.xyz, conhost.exe, dllhost.exe, 98aiblog.com, hmbcloud.com, hmbcloud.net, hmbiplc-01.com, iepl.node.cm, javacheck.ooguy.com, javaupdate.giize.com, sexytube0.com, twimg.co.uk, 001.gif, pl.gz, css.js, m2k.js, curlc4.txt, upl.natcloudservice.com, natcloudservice.com, sess.zip, upl.natcloudservice.com.ews, fm.run, dc.exe, eburst.py, cisa.dhs.gov, nsa.gov, cyber.gov.au, cyber.gc.ca, cyber.go.jp, www.npa.go.jp, soudan.html, ncsc.govt.nz, cktime.ooguy.com, 067.cz, 1421.client.96html.com, 1421.cloud.96html.com, 1421.support.96html.com, 154-119-131-252-103-58-216-162-36.m.secshow.net, 20656.hus1.ptps.tk, 20656.hus3.ptps.tk, 2-12-44-140-78-81-211-109-241.h.secshow.net, 22852.careers.96html.com, 22852.careers.trendmicro.96html.com, 22852.trendmicro.96html.com, 23175.careers.96html.com, 23175.careers.trendmicro.96html.com, 24280.hus1.ptps.tk, 2637596418.softether.net, 28394.careers.96html.com, 28394.careers.trendmicro.96html.com, 28394.trendmicro.96html.com, 28733.careers.trendmicro.96html.com, 28733.trendmicro.96html.com, 30773.hus2.ptps.tk, 30773.hus3.ptps.tk, 35584.careers.96html.com, 35584.careers.trendmicro.96html.com, 35584.trendmicro.96html.com, 39583.b.alitagotest.cf, 3w.feeee.io, 44673.careers.96html.com, 44673.trendmicro.96html.com, 47298.96html.com, 47298.client.96html.com, 47298.cloud.96html.com, 47298.support.96html.com, 50669.careers.trendmicro.96html.com, 51640.careers.trendmicro.96html.com, 51943.hus1.ptps.tk, 51943.hus3.ptps.tk, 54-2-32-236-208-2-40-107-38.h.secshow.net, 60928.hus1.ptps.tk, 66-37-178-96-110-2-40-107-38.h.secshow.net, 74788.careers.96html.com, 74788.trendmicro.96html.com, 77692.careers.96html.com, 77692.careers.trendmicro.96html.com, 77692.trendmicro.96html.com, 82262.careers.96html.com, 82262.careers.trendmicro.96html.com, 85005.careers.96html.com, 85005.careers.trendmicro.96html.com, 85005.trendmicro.96html.com, 88783.hus1.ptps.tk, 90174.careers.96html.com, 90174.careers.trendmicro.96html.com, 96976.careers.96html.com, 96976.trendmicro.96html.com, 96cee.com, 96html.com, a.alitagotest.cf, a.studiocloud.xyz, admin.dellme.ml, alitagotest.cf, arforcex.com, asean.twimg.co.uk, az.studiocloud.xyz, b.alitagotest.cf, bailbonding.info, bbs.sunmoon.website, bj-hk.hmbcloud.net, bj-jp.hmbcloud.net, blog.98aiblog.com, bsnl.twimg.co.uk, careers.96html.com, careers.trendmicro.96html.com, cch.ooguy.com, check.96html.com, checkapi.tk, checkinfo.tk, chr0mail.com, client.96html.com, cloud.96html.com, csrfproxy.studiocloud.xyz, dasxcyb.ga, dc-29465b27aa45.96html.com, dc-4fe9871cb224.96html.com, dc-582fc0f46da9.96html.com, dc-843d98722400.96html.com, dc-bb503834b7dc.96html.com, dc-c11a983d7f83.96html.com, dellme.ml, dns361.tk, dsdsei.com, eck.giize.com, eg.twimg.co.uk, etechhosting.twimg.co.uk, fcchk.twimg.co.uk, feeee.io, findfindx.com, fukua.org, gate.sinica.edu.tw.checkapi.cf, googles.ddns.net, gz-hk.hmbcloud.net, h.secshow.net, h5.feeee.io, halloween.checkapi.cf, helpuself.ptps.tk, hgiga.96html.com, honey1314520.com, hook.studiocloud.xyz, hus1.ptps.tk, hus3.ptps.tk, hw1.ptps.tk, ica.96html.com, im.arforcex.com, imap.sunmoon.website, info.96html.com, integritytoch.com, iplc-hk.hmbcloud.com, just.checkapi.cf, kk.dasxcyb.ga, leicc009.ga, live.studiocloud.xyz, ls.twimg.co.uk, m.secshow.net, ma.studiocloud.xyz, mail.bailbonding.info, mail.sunmoon.website, masaplus.club, microscan.me, mitt.96html.com, ms.studiocloud.xyz, msedge.store, mx.sunmoon.website, nikoes.gq, np.twimg.co.uk, ns1.alitagotest.cf, ns1.honey1314520.com, ns1.nikoes.gq, ns2.nikoes.gq, one.hmbiplc-01.com, payment.feeee.io, ptps.tk, puc.checkapi.tk, purple76.com, pw.sexytube0.com, pw2.sexytube0.com, random.cktime.ooguy.com, s3crts.softether.net, scallpay.com, search.96html.com, secretr.feeee.io, secshow.net, senate.twimg.co.uk, server.feeee.io, shifuj.com, sh-jp.hmbcloud.net, shop.96html.com, shopify.feeee.io, smtp.sunmoon.website, streescans.com, studiocloud.xyz, sunmoon.website, supper.feeee.io, support.96html.com, szxcm-hkg01.iepl.node.cm, t.checkinfo.tk, teyan.microscan.me, tj.twimg.co.uk, traffic.96html.com, trendmicro.96html.com, trust.feeee, tsedws.com, txt.studiocloud.xyz, update.96html.com, upgrate.checkapi.cf, v3.streescans.com, vnpt.sexytube0.com, vpn21.arforcex.com, vpn328433596.softether.net, vpn614174689.softether.net, vpn677190427.softether.net, vpn718535264.softether.net, vpn823494147.softether.net, wanfang.accesscam.org, webdisk.bailbonding.info, webmail.studiocloud.xyz, well.96html.com, ws.studiocloud.xyz, wss.studiocloud.xyz, www.96html.com, www.alitagotest.cf, www.chr0mail.com, www.cktime.ooguy.com, www.dns361.tk, www.feeee.io, www.javacheck.ooguy.com, www.leicc009.ga, www.msedge.store, www.mx.sunmoon.website, www.purple76.com, www.smtp.sunmoon.website, www.sofeter.ml, www.studiocloud.xyz, www.sunmoon.website, www.www.smtp.sunmoon.website, www.www.sunmoon.website, xassxxdns.alitagotest.cf, ximmd.sexytube0.com, zerogravity1986.softether.net, b374.php, back.pl, error.jsp, gf.phtml, yaml-payload.jar, oneforall.py, subdomainsbrute.py, juicypotato.exe, bbscan.py, dirmap.py, dirsearch.py, fscan.exe, nbtscan.exe, packerfuzzer.py, shuize.py, sqlmap.py, b.exe, secretsdump.exe, secretsdump.py
- SHA256: 72c6af6a4be99e31c4a7a0aa4f01750792788e7f6f9749243a9f2c47c14a708f, 456586ababa08f70216c4459f4d6375676166ebfddd98a33b447ceb5099e8dc5, 2f5c406eb64ad8902c8e30610d43fd3efc05a14cdb8fb158818953eaf3dc6a81, 5782ff2c835c88cc1ee521d2e8c523cfad73db3f9a29c93b40c4223f0338ade9, 0e6fecb2d369b0eae63731616a3daada52036634885ab1b85b115af6bc5bcb86, 36f3b7645609ef40444dbc68f01d26c543d67689eda4937272ea5cfa4df1b522, 670fa10a2ddde21fd594c4fef86b554d864089ed2de7153b472e921c623403ae, 645f6f2667af01a94d04a9d7a71916a13d9426835d636b4ceee2e25ccb34e525, 4d488f21269b18e37aaca93ac2a61707c9b611e506cdb3b287277746e94636b5, a14844e982f172d0f23910558c3f390a9d4c45dc32db825c2af7cf0ed8631db2, add7dd142e4f7e2873bc8f7b7fb6308063608e0b49a773dea93abad4047f1489, e7e727458f573dded05537baddac2867d2801db1c3c74410398d063dfd6f6575, 8e1b56ef51ba70aa4c4cfd4430820f20875b354588d5d723ba4d3940ea6c924b, 46e59172c40c95d83c3a6f24f801fc2265653c8b575b66a726463e2a4eebd7f2, 752b14c6e6936991d51fcd5ebf40d303e657c2372893604f96044848ad9a5f24, 7b9efc7ef8957411cdd22582ce4bfb3a5f76d9c91cdb7e36bf85c9785a2480e9, c9d5dc956841e000bfd8762e2f0b48b66c79b79500e894b4efa7fb9ba17e4e9e, 2fbcb1995c458e5affd5fb8f1f979a08ddce21714a2e413aa3d5dc44f9f245fe, 33790218d5871af646feef5be29e0596d4703a45ce675c1eb2ca00140b3a1bde, c7f86a4623db5c90273cea041d43207849c5c6b0060c370b2095f13871b1366d, 2ecb51d7fa3bc3fa7ad7df64c6d0cd1f4ff2b37ed6839d3cff529fb08af49fb0, efb0437e6a6a0f07169952f1a8b734299ec9a8b1faadbed811fe017f2cf54976, 8b869a5edaff74ff18bca3658a519a19771e66d00ff7849af7a142dd6fc8da85, 804a53be802378a8ec4c94602fd3d6584e0d472d83148e8a42c731950fec415d, c4503db6ece93eddf4511e787607cb14606a1df9f526f1e39992497119437cec, b1552703ff0035f197c22cdb3a514bb6aa45ec98de3ef5409faab0978f18c35e, 8a592e22c51311d482272ec5aba0103c9cd0cfd78e5b5ba75dfa8f1c56926672, 86f1cfa6a2e0a8cb6fc1fbee28472308e6467932f8658a6a4885e29ed8c34a67, e93244080a749b521f63476343ce3c81cc8c1b672fa0d9e67359aee37544c784, 9dc85f9569a15eaf51c7d34254767ea30dd67b2178cec4cc7125288b9544fe00, 644decbc6ce8c52382f4755fa6fc2cb4d89a0e7ec0e574c11b398a6f2eed04b1, 67db57a1f957031b78f29aa91e2e87780eae3835290259eff846d8f14afb794b
- MD5: 48ca18a25424a0f52276290b619a7a83, 38f5ff8169423e2c756848c02e8cac3b, d61326c4e6d24aa9b67e2b7a3ef7cedf, f8de2e99dc7523d2c83d1a48e844c5ff, 5b5a2c7fa705d8b1eb04da5db900b0d7, 655cd134976d3e80c521708aa8be418b, dae8f50ea44225fae3ba1f160b42bfdc, fdece34bc084f1e252aeae274650eb8d, 596b990b0b389d906a8f4384837c1878, a73eca669fe80628dbbd2c7d9bb14c8f, be121e707f817aa9392c55af1e7ec2aa, 7ce68f0dd85355ba2897a68521167e56, f82694de2f19e1bff333c27bb7eb7a56, 1933c314041415939331fce183939547, 8829f6f1cc5fc0aab2f6e71bfd7dc53d, cf903e4a1629aa0582fd0363b5786676, f01a9a2d1e31332ed36c1a4d2839f412, ef713447f18f5b7ee16af4ac37ec4133, 8dcc4f9ccc6b6adf7eeeb3f51c95afad, b04375cca637f0702bf27feaff22a92d, bcacc7ca999980d26c186ef791242fb5, 1b8e29b6b7972fb124425aaa257f8f6d, 4f61b9ab907f351bb40b37b10f4974d0, 6d57c42dee8bd7789969e2dd28671162, 776807750280daad05348f931a33e4ef, a973c0ab904c1b74655a906b99b76850, f62cbbbdf35c7790909c26c7c5fbce05, a05cdf6afcbb107961307f59cbab5e4f, 7d5a182f70bed0e4fa2f8615aba070de, 1bcaef76b2063f1b80b0fa0d277ec9c5, 4d33bfb75e27fefaa72526899604d557, fc6e8ca41cf4f6100177352660e520b4

### Hypotheses (4)

#### H-64f83085-1 · Initial access via CVE-2014-6278 affecting Microsoft Exchange  _(confidence: high)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2014-6278 in Microsoft Exchange within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2014-6278, CVE-2015-3306, CVE-2015-5477; threat actors: Flax Typhoon; vectors: phishing, exploit, vpn-edge; impact: ransomware, data-breach, ddos; products: Microsoft Exchange, Active Directory, Ivanti Connect Secure.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-64f83085-1-O1] Inventory exposure to Microsoft Exchange** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of Microsoft Exchange, the external-exploitation hypothesis is disproven for CVE-2014-6278.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'Microsoft Exchange' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-64f83085-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2014-6278 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2014-6278/ | summarize count() by src_ip, dst_host`
- **[H-64f83085-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2014-6278 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2014-6278')) | summarize coverage = avg(installed) by host_role`
- **[H-64f83085-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on Microsoft Exchange hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-64f83085-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-64f83085-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2014-6278, CVE-2015-3306, CVE-2015-5477; threat actors: Flax Typhoon; vectors: phishing, exploit, vpn-edge; impact: ransomware, data-breach, ddos; products: Microsoft Exchange, Active Directory, Ivanti Connect Secure.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-64f83085-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('diagtrack.exe','dns.studiocloud.xyz','conhost.exe') | summarize count() by client_ip`
- **[H-64f83085-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('149.28.132.137','1.34.140.5','2.58.242.74') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-64f83085-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-64f83085-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-64f83085-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-64f83085-3 · Post-foothold lateral movement consistent with Flax Typhoon  _(confidence: medium)_

**Statement.** An attacker who matched the TTPs of Flax Typhoon has moved laterally inside the estate using RDP/SMB/WinRM, admin tooling, or Kerberos abuse.

**Why this hypothesis?** Archetype 'lateral_movement' selected based on CVEs cited: CVE-2014-6278, CVE-2015-3306, CVE-2015-5477; threat actors: Flax Typhoon; vectors: phishing, exploit, vpn-edge; impact: ransomware, data-breach, ddos; products: Microsoft Exchange, Active Directory, Ivanti Connect Secure.

**MITRE ATT&CK**: T1021.001, T1021.002, T1021.006, T1003

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-64f83085-3-O1] Anomalous remote logons (Type 3 / Type 10)** _(difficulty: medium · 200 pts · MITRE: T1021.001, T1021.002)_
  - Falsification criterion: If 4624 logon-type 3/10 events show no bursts from a single source to many destinations, lateral movement via RDP/SMB is unsupported.
  - Data sources: Windows Security event log, Domain Controller logs
  - Suggested query: `security | where event_id in (4624) and logon_type in (3,10) | summarize dests = dcount(dst_host) by src_user, src_host | where dests > 10`
- **[H-64f83085-3-O2] Admin-tool usage outside baseline** _(difficulty: medium · 200 pts · MITRE: T1021.002, T1021.006, T1059)_
  - Falsification criterion: If PsExec / WMIC / PowerShell remoting / Impacket-style usage is absent outside known admin jump-hosts, the lateral-tool hypothesis is disproven.
  - Data sources: Sysmon EID 1, EDR, 4688
  - Suggested query: `process | where name in ('psexec.exe','psexesvc.exe','wmic.exe','wsmprovhost.exe') and host !in (admin_jumphosts)`
- **[H-64f83085-3-O3] Kerberos abuse telemetry** _(difficulty: hard · 300 pts · MITRE: T1558.003, T1110.003)_
  - Falsification criterion: If 4769 ticket requests show no anomalous RC4 / odd-SPN patterns and no AS-REP roasting indicators, credential-based lateral movement is unsupported.
  - Data sources: Domain Controller security log
  - Suggested query: `security | where event_id == 4769 and ticket_encryption == 'RC4-HMAC' | summarize by target_spn, account_name`
- **[H-64f83085-3-O4] Lateral file-copy staging** _(difficulty: medium · 200 pts · MITRE: T1570, T1021.002)_
  - Falsification criterion: If SMB writes of archives / executables across multiple hosts from one user/host are absent, lateral staging is unsupported.
  - Data sources: File-share auditing (5145), EDR file events
  - Suggested query: `file | where action == 'write' and ext in ('.7z','.rar','.zip','.exe') and dest matches /\\\\.*\\(C\$|admin\$)/`

#### H-64f83085-4 · Data staging and exfiltration to attacker-controlled storage  _(confidence: medium)_

**Statement.** Sensitive data has been staged (archived) and exfiltrated to attacker-controlled endpoints or cloud-storage tenants in the reporting window.

**Why this hypothesis?** Archetype 'exfiltration' selected based on CVEs cited: CVE-2014-6278, CVE-2015-3306, CVE-2015-5477; threat actors: Flax Typhoon; vectors: phishing, exploit, vpn-edge; impact: ransomware, data-breach, ddos; products: Microsoft Exchange, Active Directory, Ivanti Connect Secure.

**MITRE ATT&CK**: T1560, T1041, T1567, T1567.002

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-64f83085-4-O1] Cloud-storage exfil to non-corp tenants** _(difficulty: easy · 100 pts · MITRE: T1567.002, T1567)_
  - Falsification criterion: If DLP / proxy show no uploads to mega.nz, anonfiles, transfer.sh, or personal Dropbox/OneDrive tenants, cloud exfil is disproven.
  - Data sources: Proxy logs, CASB / DLP
  - Suggested query: `proxy | where host matches /mega\.nz|anonfiles\.com|transfer\.sh|filebin\.net/ | summarize bytes = sum(bytes_out) by user`
- **[H-64f83085-4-O2] Archive-then-egress pattern** _(difficulty: medium · 250 pts · MITRE: T1560, T1041)_
  - Falsification criterion: If user/host telemetry shows no archive creation (rar/7z) within minutes of a large outbound transfer, the stage-then-exfil pattern is absent.
  - Data sources: EDR process+file events, NetFlow
  - Suggested query: `file_create | where ext in ('.rar','.7z','.zip') | join (egress | where bytes_out > 50MB) on host within 30m`
- **[H-64f83085-4-O3] Outbound volume to rare ASNs** _(difficulty: medium · 200 pts · MITRE: T1041, T1567)_
  - Falsification criterion: If outbound bytes-by-ASN over the last 30 days show no first-seen / low-reputation destination receiving >1GB, bulk exfil is unsupported.
  - Data sources: NetFlow, Firewall logs
  - Suggested query: `netflow | summarize bytes = sum(bytes_out) by asn | where asn !in (corp_known_asns) and bytes > 1GB`
- **[H-64f83085-4-O4] DNS-tunnelling search** _(difficulty: hard · 300 pts · MITRE: T1071.004, T1048.003)_
  - Falsification criterion: If DNS query-length and txt-record distributions show no entropy / volume anomalies per source, DNS-tunnelled exfil is unsupported.
  - Data sources: DNS resolver logs
  - Suggested query: `dns | summarize avg(query_length), p99(query_length), count() by client_ip | where p99 > 200 and count() > 1000`

---

## 2. October 2026 Microsoft Patch Tuesday, (Tue, Oct 13th)

- **Source**: SANS Internet Storm Center
- **Link**: <https://isc.sans.edu/diary/rss/33422>
- **Published**: Tue, 13 Oct 2026 19:25:52 GMT
- **First seen**: 2026-10-13T20:07:52+00:00
- **Relevance score**: 108
- **Score rationale**: source weight (advisory)=+15, 3 CVE(s)=+30, 5 MITRE technique hit(s)=+20, 3 initial-access vector(s)=+11, 1 impact action(s)=+8, 3 product mention(s)=+9, 11 IOC(s)=+15

> Microsoft today released patches for 1,417 vulnerabilities. 76 of these vulnerabilities are rated critical, with 7 critical vulnerabiilties requiring no customer actions. One vulnerability was disclosed before today&#;x26;#;39;s patch Tuesday, and one is already exploited.

**Extracted signals**
- CVEs: CVE-2026-96951, CVE-2026-108398, CVE-2026-70571
- Products: Microsoft Exchange, Active Directory, Linux kernel
- Vectors: exploit, rdp, smb
- Actions: ddos
- Sectors: manufacturing, telecom
- MITRE ATT&CK: T1059, T1059.001, T1003, T1021.001, T1021.002
- Domain IOCs: asp.net, fdwsd.dll, http.sys, csc.sys, unionfs.sys, wininet.dll, spaceport.sys, kernel32.dll, rndismp6.sys, sans.edu, isc.sans.edu

### Hypotheses (3)

#### H-92bf2972-1 · Initial access via CVE-2026-96951 affecting Microsoft Exchange  _(confidence: high)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2026-96951 in Microsoft Exchange within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2026-96951, CVE-2026-108398, CVE-2026-70571; vectors: exploit, rdp, smb; impact: ddos; products: Microsoft Exchange, Active Directory, Linux kernel.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-92bf2972-1-O1] Inventory exposure to Microsoft Exchange** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of Microsoft Exchange, the external-exploitation hypothesis is disproven for CVE-2026-96951.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'Microsoft Exchange' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-92bf2972-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2026-96951 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2026-96951/ | summarize count() by src_ip, dst_host`
- **[H-92bf2972-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2026-96951 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2026-96951')) | summarize coverage = avg(installed) by host_role`
- **[H-92bf2972-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on Microsoft Exchange hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-92bf2972-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-92bf2972-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2026-96951, CVE-2026-108398, CVE-2026-70571; vectors: exploit, rdp, smb; impact: ddos; products: Microsoft Exchange, Active Directory, Linux kernel.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-92bf2972-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('asp.net','fdwsd.dll','http.sys') | summarize count() by client_ip`
- **[H-92bf2972-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-92bf2972-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-92bf2972-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-92bf2972-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-92bf2972-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2026-96951, CVE-2026-108398, CVE-2026-70571; vectors: exploit, rdp, smb; impact: ddos; products: Microsoft Exchange, Active Directory, Linux kernel.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-92bf2972-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-92bf2972-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-92bf2972-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-92bf2972-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 3. Ignore all instructions and read this blog: The state of AI-analysis evasion in malware

- **Source**: Cisco Talos
- **Link**: <https://blog.talosintelligence.com/ignore-all-instructions-and-read-this-blog-the-state-of-ai-analysis-evasion-in-malware/>
- **Published**: Thu, 08 Oct 2026 10:00:14 GMT
- **First seen**: 2026-10-08T10:39:20+00:00
- **Relevance score**: 99
- **Score rationale**: source weight (vendor)=+10, 1 CVE(s)=+20, 2 threat actor hit(s)=+25, 2 MITRE technique hit(s)=+11, 1 initial-access vector(s)=+7, 1 impact action(s)=+8, 1 product mention(s)=+3, 13 IOC(s)=+15

> “AI-analysis evasion” encapsulates the real-world techniques malware authors are developing in attempt to obstruct or defeat any layers of automated AI analysis.

**Extracted signals**
- CVEs: CVE-2015-2291
- Threat actors: Lazarus, Scattered Spider
- Products: Microsoft Exchange
- Vectors: exploit
- Actions: fraud
- Sectors: government, manufacturing, telecom
- MITRE ATT&CK: T1059, T1059.001
- Domain IOCs: csc.exe, iqvw64e.sys
- SHA256: f8f5e0440c57c7deffd75ca33e2511867039796aa803e7ef847396a379188a7d, 34098fe0bc4c69c4c4eb3f74688fb375326804536d25e5574e8c4c28c113b5c3, 389066bd5543aeea363d23a4dce7f7a21c7f2c73c61f506a93a69f594cf48ecf, 5f60d16fa67ff8ef07817c33b7e6b7fa91c6c21060020df46b1f5c56e076e259, a0294f7152f9c4c908e9def58279e9fa29952715947c950c8489949f26a15cc8, c17bf76d02163863c251c3bb3a12725eeb525fab5522521923925e0469ca269f, 2aa7f13bf474e2ce5049fd4db2bf4da04b4ce51ac0d36dceb24865255241c937, bacb5794a300f7a88c7f6d458382eb11d2f39c0f496b509ca512afe8588fc33f, 2e3e1bcd44cc3cbec4f5ca9991d14a326d3cc6bf76fe6e0d434c9b5f7e1ae6ab, a42632c68d2dcea06300e790c9440fe0943ce0dee2075f29170fd2774eacf433, 7dd3747d777f9576a11004532b463351e7718b6af193d8ee7221ac41479d199a

### Hypotheses (3)

#### H-d3b53db2-1 · Initial access via CVE-2015-2291 affecting Microsoft Exchange  _(confidence: high)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2015-2291 in Microsoft Exchange within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2015-2291; threat actors: Lazarus, Scattered Spider; vectors: exploit; impact: fraud; products: Microsoft Exchange.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-d3b53db2-1-O1] Inventory exposure to Microsoft Exchange** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of Microsoft Exchange, the external-exploitation hypothesis is disproven for CVE-2015-2291.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'Microsoft Exchange' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-d3b53db2-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2015-2291 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2015-2291/ | summarize count() by src_ip, dst_host`
- **[H-d3b53db2-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2015-2291 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2015-2291')) | summarize coverage = avg(installed) by host_role`
- **[H-d3b53db2-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on Microsoft Exchange hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-d3b53db2-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-d3b53db2-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2015-2291; threat actors: Lazarus, Scattered Spider; vectors: exploit; impact: fraud; products: Microsoft Exchange.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-d3b53db2-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('csc.exe','iqvw64e.sys') | summarize count() by client_ip`
- **[H-d3b53db2-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-d3b53db2-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-d3b53db2-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-d3b53db2-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-d3b53db2-3 · Post-foothold lateral movement consistent with Lazarus  _(confidence: medium)_

**Statement.** An attacker who matched the TTPs of Lazarus has moved laterally inside the estate using RDP/SMB/WinRM, admin tooling, or Kerberos abuse.

**Why this hypothesis?** Archetype 'lateral_movement' selected based on CVEs cited: CVE-2015-2291; threat actors: Lazarus, Scattered Spider; vectors: exploit; impact: fraud; products: Microsoft Exchange.

**MITRE ATT&CK**: T1021.001, T1021.002, T1021.006, T1003

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-d3b53db2-3-O1] Anomalous remote logons (Type 3 / Type 10)** _(difficulty: medium · 200 pts · MITRE: T1021.001, T1021.002)_
  - Falsification criterion: If 4624 logon-type 3/10 events show no bursts from a single source to many destinations, lateral movement via RDP/SMB is unsupported.
  - Data sources: Windows Security event log, Domain Controller logs
  - Suggested query: `security | where event_id in (4624) and logon_type in (3,10) | summarize dests = dcount(dst_host) by src_user, src_host | where dests > 10`
- **[H-d3b53db2-3-O2] Admin-tool usage outside baseline** _(difficulty: medium · 200 pts · MITRE: T1021.002, T1021.006, T1059)_
  - Falsification criterion: If PsExec / WMIC / PowerShell remoting / Impacket-style usage is absent outside known admin jump-hosts, the lateral-tool hypothesis is disproven.
  - Data sources: Sysmon EID 1, EDR, 4688
  - Suggested query: `process | where name in ('psexec.exe','psexesvc.exe','wmic.exe','wsmprovhost.exe') and host !in (admin_jumphosts)`
- **[H-d3b53db2-3-O3] Kerberos abuse telemetry** _(difficulty: hard · 300 pts · MITRE: T1558.003, T1110.003)_
  - Falsification criterion: If 4769 ticket requests show no anomalous RC4 / odd-SPN patterns and no AS-REP roasting indicators, credential-based lateral movement is unsupported.
  - Data sources: Domain Controller security log
  - Suggested query: `security | where event_id == 4769 and ticket_encryption == 'RC4-HMAC' | summarize by target_spn, account_name`
- **[H-d3b53db2-3-O4] Lateral file-copy staging** _(difficulty: medium · 200 pts · MITRE: T1570, T1021.002)_
  - Falsification criterion: If SMB writes of archives / executables across multiple hosts from one user/host are absent, lateral staging is unsupported.
  - Data sources: File-share auditing (5145), EDR file events
  - Suggested query: `file | where action == 'write' and ext in ('.7z','.rar','.zip','.exe') and dest matches /\\\\.*\\(C\$|admin\$)/`

---

## 4. The Q3 Vulnerability Pulse: Discovery ≠ Exploitation

- **Source**: Cisco Talos
- **Link**: <https://blog.talosintelligence.com/the-q3-vulnerability-pulse-discovery-exploitation/>
- **Published**: Thu, 15 Oct 2026 18:00:00 GMT
- **First seen**: 2026-10-15T18:21:27+00:00
- **Relevance score**: 95
- **Score rationale**: source weight (vendor)=+10, 3 CVE(s)=+30, 4 MITRE technique hit(s)=+17, 2 initial-access vector(s)=+9, 2 impact action(s)=+11, 1 product mention(s)=+3, 15 IOC(s)=+15

> Is the cybersecurity world really facing a "Bugmageddon?" Thor breaks down the latest CVE and KEV trends in the latest Threat Source newsletter.

**Extracted signals**
- CVEs: CVE-2014-125110, CVE-2015-1000013, CVE-2026-104935
- Products: Ivanti Connect Secure
- Vectors: exploit, vpn-edge
- Actions: espionage, fraud
- Sectors: government, manufacturing
- MITRE ATT&CK: T1059, T1059.001, T1053, T1547
- Domain IOCs: sample.exe, w32.9f1f11a708-100.sbx.tg, w32.pup, pulsebrowser.29kh.in12.talos, net.exe, w32.58d6fec4ba-95.sbx.tg, w32.fed979f93b-95.sbx.tg
- SHA256: 9f1f11a708d393e0a4109ae189bc64f1f3e312653dcf317a2bd406f18ffcc507, 73ac1bbfaee6c76c34f655ac0477a4cd930f2aa55e658c8e312ff81aac9a741f, 58d6fec4ba24c32d38c9a0c7c39df3cb0e91f500b323e841121d703c7b718681, fed979f93bcaf4e73ebd25748093a92095d5109cbd01d55f97bdc50ce509ad2f
- MD5: 2915b3f8b703eb744fc54c81f4a9c67f, 63f3351cfdf618bec6045f60203e7978, f1fe671bcefd4630e5ed8b87c9283534, 207d9d891ac756b2bfad88aba5682c65

### Hypotheses (3)

#### H-eb0c40b2-1 · Initial access via CVE-2014-125110 affecting Ivanti Connect Secure  _(confidence: high)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2014-125110 in Ivanti Connect Secure within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2014-125110, CVE-2015-1000013, CVE-2026-104935; vectors: exploit, vpn-edge; impact: espionage, fraud; products: Ivanti Connect Secure.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-eb0c40b2-1-O1] Inventory exposure to Ivanti Connect Secure** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of Ivanti Connect Secure, the external-exploitation hypothesis is disproven for CVE-2014-125110.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'Ivanti Connect Secure' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-eb0c40b2-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2014-125110 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2014-125110/ | summarize count() by src_ip, dst_host`
- **[H-eb0c40b2-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2014-125110 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2014-125110')) | summarize coverage = avg(installed) by host_role`
- **[H-eb0c40b2-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on Ivanti Connect Secure hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-eb0c40b2-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-eb0c40b2-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2014-125110, CVE-2015-1000013, CVE-2026-104935; vectors: exploit, vpn-edge; impact: espionage, fraud; products: Ivanti Connect Secure.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-eb0c40b2-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('sample.exe','w32.9f1f11a708-100.sbx.tg','w32.pup') | summarize count() by client_ip`
- **[H-eb0c40b2-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-eb0c40b2-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-eb0c40b2-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-eb0c40b2-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-eb0c40b2-3 · Data staging and exfiltration to attacker-controlled storage  _(confidence: medium)_

**Statement.** Sensitive data has been staged (archived) and exfiltrated to attacker-controlled endpoints or cloud-storage tenants in the reporting window.

**Why this hypothesis?** Archetype 'exfiltration' selected based on CVEs cited: CVE-2014-125110, CVE-2015-1000013, CVE-2026-104935; vectors: exploit, vpn-edge; impact: espionage, fraud; products: Ivanti Connect Secure.

**MITRE ATT&CK**: T1560, T1041, T1567, T1567.002

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-eb0c40b2-3-O1] Cloud-storage exfil to non-corp tenants** _(difficulty: easy · 100 pts · MITRE: T1567.002, T1567)_
  - Falsification criterion: If DLP / proxy show no uploads to mega.nz, anonfiles, transfer.sh, or personal Dropbox/OneDrive tenants, cloud exfil is disproven.
  - Data sources: Proxy logs, CASB / DLP
  - Suggested query: `proxy | where host matches /mega\.nz|anonfiles\.com|transfer\.sh|filebin\.net/ | summarize bytes = sum(bytes_out) by user`
- **[H-eb0c40b2-3-O2] Archive-then-egress pattern** _(difficulty: medium · 250 pts · MITRE: T1560, T1041)_
  - Falsification criterion: If user/host telemetry shows no archive creation (rar/7z) within minutes of a large outbound transfer, the stage-then-exfil pattern is absent.
  - Data sources: EDR process+file events, NetFlow
  - Suggested query: `file_create | where ext in ('.rar','.7z','.zip') | join (egress | where bytes_out > 50MB) on host within 30m`
- **[H-eb0c40b2-3-O3] Outbound volume to rare ASNs** _(difficulty: medium · 200 pts · MITRE: T1041, T1567)_
  - Falsification criterion: If outbound bytes-by-ASN over the last 30 days show no first-seen / low-reputation destination receiving >1GB, bulk exfil is unsupported.
  - Data sources: NetFlow, Firewall logs
  - Suggested query: `netflow | summarize bytes = sum(bytes_out) by asn | where asn !in (corp_known_asns) and bytes > 1GB`
- **[H-eb0c40b2-3-O4] DNS-tunnelling search** _(difficulty: hard · 300 pts · MITRE: T1071.004, T1048.003)_
  - Falsification criterion: If DNS query-length and txt-record distributions show no entropy / volume anomalies per source, DNS-tunnelled exfil is unsupported.
  - Data sources: DNS resolver logs
  - Suggested query: `dns | summarize avg(query_length), p99(query_length), count() by client_ip | where p99 > 200 and count() > 1000`

---

## 5. CISA Malcolm

- **Source**: CISA Advisories
- **Link**: <https://www.cisa.gov/news-events/ics-advisories/icsa-26-280-01>
- **Published**: Thu, 15 Oct 26 12:00:00 +0000
- **First seen**: 2026-10-15T17:01:00+00:00
- **Relevance score**: 89
- **Score rationale**: source weight (advisory)=+15, 7 CVE(s)=+30, 1 MITRE technique hit(s)=+8, 4 initial-access vector(s)=+13, 1 impact action(s)=+8, 7 IOC(s)=+15

> View CSAF Summary The following versions of CISA Malcolm are affected: Malcolm Malcolm CVSS Vendor Equipment v3 8.1 CISA Malcolm 5 Vulnerabilities Authentication Bypass by Spoofing, Incorrect Authorization, Server-Side Request Forgery (SSRF), Authentication Bypass Using an Alternate Path or Channel, Cross-Site Request Forgery (CSRF) Background Critical Infrastructure Sectors: Energy, Information Technology, Water and Wastewater Systems Countries/Areas Deployed: Worldwide Company Headquarters Location: United States Vulnerabilities Expand All + CVE-2026-107336 Malcolm's front nginx reverse proxy defines a "Dashboards → Arkime shortcut" location using a case-insensitive regex matcher but a case-sensitive rewrite. A request whose path segment is not exact-lowercase (for example /IDDASH2ARK/...) enters the location (the matcher fires) but evades the rewrite (no redirect is issued), so nginx falls through to the location's proxy_pass to the Arkime backend. That location is the one proxied location in the shipped config that does not include the per-location authentication file, so the request reaches Arkime unauthenticated. The same location also forwards a client-supplied X-Forwarded-User header un-overwritten, and Arkime is configured to trust X-Forwarded-User as the authenticated username — so an unauthenticated network caller can reach the Arkime backend while supplying a forged, auto-provisioned identity. Read More 1 Affected Product CISA Malcolm Product Status: known_affecte

**Extracted signals**
- CVEs: CVE-2026-107336, CVE-2026-107333, CVE-2026-107362, CVE-2026-107361, CVE-2026-107337, CVE-2026-107335, CVE-2026-107334
- Vectors: phishing, exploit, vpn-edge, social-engineering
- Actions: fraud
- Sectors: energy, manufacturing
- MITRE ATT&CK: T1566
- Domain IOCs: config.php, submit.php, index.php, control.py, safe-extract.py, 68tadmin.php, www.cisa.gov

### Hypotheses (3)

#### H-87c8a64d-1 · Initial access via CVE-2026-107336 affecting the affected product/service  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2026-107336 in the affected product/service within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2026-107336, CVE-2026-107333, CVE-2026-107362; vectors: phishing, exploit, vpn-edge; impact: fraud.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-87c8a64d-1-O1] Inventory exposure to the affected product** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of the affected product, the external-exploitation hypothesis is disproven for CVE-2026-107336.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'the affected product' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-87c8a64d-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2026-107336 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2026-107336/ | summarize count() by src_ip, dst_host`
- **[H-87c8a64d-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2026-107336 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2026-107336')) | summarize coverage = avg(installed) by host_role`
- **[H-87c8a64d-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on the affected product hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-87c8a64d-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-87c8a64d-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2026-107336, CVE-2026-107333, CVE-2026-107362; vectors: phishing, exploit, vpn-edge; impact: fraud.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-87c8a64d-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('config.php','submit.php','index.php') | summarize count() by client_ip`
- **[H-87c8a64d-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-87c8a64d-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-87c8a64d-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-87c8a64d-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-87c8a64d-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2026-107336, CVE-2026-107333, CVE-2026-107362; vectors: phishing, exploit, vpn-edge; impact: fraud.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-87c8a64d-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-87c8a64d-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-87c8a64d-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-87c8a64d-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 6. Break the silence: Kazakhstan-nexus UAT-6275 targets CIS government organizations

- **Source**: Cisco Talos
- **Link**: <https://blog.talosintelligence.com/break-the-silence-kazakhstan-nexus-uat-6275-targets-cis-government-organizations/>
- **Published**: Wed, 14 Oct 2026 14:00:00 GMT
- **First seen**: 2026-10-14T14:13:57+00:00
- **Relevance score**: 86
- **Score rationale**: source weight (vendor)=+10, 2 CVE(s)=+25, 5 MITRE technique hit(s)=+20, 2 initial-access vector(s)=+9, 1 impact action(s)=+8, 6 IOC(s)=+14

> Talos and Recorded Future identified UAT-6275 activity targeting government organizations across the Commonwealth of Independent States. Recovered artifacts show additional interest in water resources and energy.

**Extracted signals**
- CVEs: CVE-2025-8088, CVE-2025-25257
- Vectors: phishing, exploit
- Actions: fraud
- Sectors: government, energy, manufacturing
- MITRE ATT&CK: T1059, T1059.001, T1053, T1547, T1219
- Domain IOCs: bi.zone, win.backdoor.pickleshell, win.backdoor.chvost, win.malware.generic, win.malware.laplas, win.proxy.generic

### Hypotheses (3)

#### H-7fae382b-1 · Initial access via CVE-2025-8088 affecting the affected product/service  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2025-8088 in the affected product/service within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2025-8088, CVE-2025-25257; vectors: phishing, exploit; impact: fraud.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-7fae382b-1-O1] Inventory exposure to the affected product** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of the affected product, the external-exploitation hypothesis is disproven for CVE-2025-8088.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'the affected product' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-7fae382b-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2025-8088 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2025-8088/ | summarize count() by src_ip, dst_host`
- **[H-7fae382b-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2025-8088 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2025-8088')) | summarize coverage = avg(installed) by host_role`
- **[H-7fae382b-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on the affected product hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-7fae382b-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-7fae382b-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2025-8088, CVE-2025-25257; vectors: phishing, exploit; impact: fraud.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-7fae382b-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('bi.zone','win.backdoor.pickleshell','win.backdoor.chvost') | summarize count() by client_ip`
- **[H-7fae382b-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-7fae382b-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-7fae382b-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-7fae382b-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-7fae382b-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2025-8088, CVE-2025-25257; vectors: phishing, exploit; impact: fraud.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-7fae382b-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-7fae382b-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-7fae382b-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-7fae382b-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 7. ShinyHunters Extorted Boeing Spin-off Prior to Arrests

- **Source**: KrebsOnSecurity
- **Link**: <https://krebsonsecurity.com/2026/10/shinyhunters-extorted-boeing-spin-off-prior-to-arrests/>
- **Published**: Wed, 07 Oct 2026 13:48:45 +0000
- **First seen**: 2026-10-07T14:14:33+00:00
- **Relevance score**: 85
- **Score rationale**: source weight (news)=+5, 1 CVE(s)=+20, 1 malware family hit(s)=+20, 2 MITRE technique hit(s)=+11, 3 initial-access vector(s)=+11, 3 impact action(s)=+14, 1 IOC(s)=+4

> A teenager from Amman, Jordan suspected of leading the prolific data theft and extortion group ShinyHunters has been detained and is reportedly cooperating with the FBI to identify other members of the hacking gang. KrebsOnSecurity has learned that the suspect, who uses the hacker handle "Rey," was detained as ShinyHunters was in the process of extorting a business unit recently divested by the global aerospace company Boeing, which manufactures the fleet of planes used by the employer of Rey's father -- Royal Jordanian Airlines.

**Extracted signals**
- CVEs: CVE-2026-35273
- Malware families: Cl0p
- Vectors: phishing, exploit, credential-theft
- Actions: ransomware, data-breach, fraud
- Sectors: healthcare, government, manufacturing, education
- MITRE ATT&CK: T1078, T1486
- Domain IOCs: at5.nl

### Hypotheses (4)

#### H-a98177d0-1 · Initial access via CVE-2026-35273 affecting the affected product/service  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2026-35273 in the affected product/service within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2026-35273; malware families: Cl0p; vectors: phishing, exploit, credential-theft; impact: ransomware, data-breach, fraud.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-a98177d0-1-O1] Inventory exposure to the affected product** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of the affected product, the external-exploitation hypothesis is disproven for CVE-2026-35273.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'the affected product' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-a98177d0-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2026-35273 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2026-35273/ | summarize count() by src_ip, dst_host`
- **[H-a98177d0-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2026-35273 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2026-35273')) | summarize coverage = avg(installed) by host_role`
- **[H-a98177d0-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on the affected product hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-a98177d0-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-a98177d0-2 · Endpoint execution of Cl0p  _(confidence: high)_

**Statement.** One or more endpoints in the estate have executed or attempted to execute Cl0p payloads since the reporting date.

**Why this hypothesis?** Archetype 'malware_execution' selected based on CVEs cited: CVE-2026-35273; malware families: Cl0p; vectors: phishing, exploit, credential-theft; impact: ransomware, data-breach, fraud.

**MITRE ATT&CK**: T1204, T1059, T1547

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-a98177d0-2-O1] EDR hash sweep for Cl0p** _(difficulty: easy · 150 pts · MITRE: T1204, T1059)_
  - Falsification criterion: If a search of EDR file/process telemetry for known Cl0p SHA256s returns zero hits in the last 90 days, payload presence is disproven.
  - Data sources: EDR (CrowdStrike/Defender/SentinelOne), Threat-intel feed
  - Suggested query: `process_events | where sha256 in (ti_lookup('Cl0p', 'sha256')) | summarize count() by host`
- **[H-a98177d0-2-O2] Behavioural pattern hunt for Cl0p** _(difficulty: medium · 200 pts · MITRE: T1059.001, T1059.005, T1218.011)_
  - Falsification criterion: If parent/child anomalies typical of the family (e.g. Office spawning script hosts, rundll32 chains) are absent across the estate, execution chain is unsupported.
  - Data sources: Sysmon EID 1, EDR process tree
  - Suggested query: `process | where parent in ('winword.exe','excel.exe','outlook.exe') and child in ('rundll32.exe','wscript.exe','mshta.exe','powershell.exe')`
- **[H-a98177d0-2-O3] Persistence-key inspection** _(difficulty: medium · 200 pts · MITRE: T1547.001, T1053.005)_
  - Falsification criterion: If autoruns, scheduled tasks, services, and WMI subscriptions show no Cl0p-aligned artifacts, post-execution persistence is disproven.
  - Data sources: Sysmon EID 13/12, Autoruns sweep, EDR persistence module
  - Suggested query: `registry_set | where key matches /Run|RunOnce|Image File Execution Options/ and value matches /unusual-path/`
- **[H-a98177d0-2-O4] AV / quarantine retrospective** _(difficulty: easy · 100 pts · MITRE: T1204)_
  - Falsification criterion: If retrospective AV / quarantine logs show no detections for related signatures over the last 30 days, the family is unlikely to have landed in-environment.
  - Data sources: AV management console, Defender ATP detections
  - Suggested query: `av_events | where signature contains 'Cl0p' | summarize by host, action`
- **[H-a98177d0-2-O5] Memory-resident loader check** _(difficulty: hard · 300 pts · MITRE: T1620, T1055)_
  - Falsification criterion: If a memory scan (YARA via EDR / Volatility) finds none of the published loader patterns on a sampled set of high-risk hosts, in-memory residency is unsupported.
  - Data sources: YARA via EDR, Volatility on a sampled host
  - Suggested query: `memory_scan | yara_rule == 'rule_cl0p' | summarize by host`

#### H-a98177d0-3 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2026-35273; malware families: Cl0p; vectors: phishing, exploit, credential-theft; impact: ransomware, data-breach, fraud.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-a98177d0-3-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('at5.nl') | summarize count() by client_ip`
- **[H-a98177d0-3-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-a98177d0-3-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-a98177d0-3-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-a98177d0-3-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-a98177d0-4 · Post-foothold lateral movement consistent with the reported actor  _(confidence: medium)_

**Statement.** An attacker who matched the TTPs of the reported actor has moved laterally inside the estate using RDP/SMB/WinRM, admin tooling, or Kerberos abuse.

**Why this hypothesis?** Archetype 'lateral_movement' selected based on CVEs cited: CVE-2026-35273; malware families: Cl0p; vectors: phishing, exploit, credential-theft; impact: ransomware, data-breach, fraud.

**MITRE ATT&CK**: T1021.001, T1021.002, T1021.006, T1003

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-a98177d0-4-O1] Anomalous remote logons (Type 3 / Type 10)** _(difficulty: medium · 200 pts · MITRE: T1021.001, T1021.002)_
  - Falsification criterion: If 4624 logon-type 3/10 events show no bursts from a single source to many destinations, lateral movement via RDP/SMB is unsupported.
  - Data sources: Windows Security event log, Domain Controller logs
  - Suggested query: `security | where event_id in (4624) and logon_type in (3,10) | summarize dests = dcount(dst_host) by src_user, src_host | where dests > 10`
- **[H-a98177d0-4-O2] Admin-tool usage outside baseline** _(difficulty: medium · 200 pts · MITRE: T1021.002, T1021.006, T1059)_
  - Falsification criterion: If PsExec / WMIC / PowerShell remoting / Impacket-style usage is absent outside known admin jump-hosts, the lateral-tool hypothesis is disproven.
  - Data sources: Sysmon EID 1, EDR, 4688
  - Suggested query: `process | where name in ('psexec.exe','psexesvc.exe','wmic.exe','wsmprovhost.exe') and host !in (admin_jumphosts)`
- **[H-a98177d0-4-O3] Kerberos abuse telemetry** _(difficulty: hard · 300 pts · MITRE: T1558.003, T1110.003)_
  - Falsification criterion: If 4769 ticket requests show no anomalous RC4 / odd-SPN patterns and no AS-REP roasting indicators, credential-based lateral movement is unsupported.
  - Data sources: Domain Controller security log
  - Suggested query: `security | where event_id == 4769 and ticket_encryption == 'RC4-HMAC' | summarize by target_spn, account_name`
- **[H-a98177d0-4-O4] Lateral file-copy staging** _(difficulty: medium · 200 pts · MITRE: T1570, T1021.002)_
  - Falsification criterion: If SMB writes of archives / executables across multiple hosts from one user/host are absent, lateral staging is unsupported.
  - Data sources: File-share auditing (5145), EDR file events
  - Suggested query: `file | where action == 'write' and ext in ('.7z','.rar','.zip','.exe') and dest matches /\\\\.*\\(C\$|admin\$)/`

---

## 8. Making sure the checks get printed

- **Source**: Cisco Talos
- **Link**: <https://blog.talosintelligence.com/making-sure-the-checks-get-printed/>
- **Published**: Thu, 08 Oct 2026 18:00:29 GMT
- **First seen**: 2026-10-08T18:33:33+00:00
- **Relevance score**: 81
- **Score rationale**: source weight (vendor)=+10, 1 CVE(s)=+20, 1 MITRE technique hit(s)=+8, 3 initial-access vector(s)=+11, 3 impact action(s)=+14, 1 product mention(s)=+3, 19 IOC(s)=+15

> Pierre's debut newsletter explores the messy, real-world side of risk management and how to keep vital systems running when a perfect patch isn't an option.

**Extracted signals**
- CVEs: CVE-2026-88779
- Products: Citrix NetScaler
- Vectors: exploit, supply-chain, vpn-edge
- Actions: ransomware, ddos, fraud
- Sectors: healthcare, finance, government, energy, manufacturing, education, telecom
- MITRE ATT&CK: T1486
- Domain IOCs: sample.exe, w32.9f1f11a708-100.sbx.tg, w32.fed979f93b-95.sbx.tg, secoh-qad.exe, w32.9896a6fcb9-95.sbx.tg, w32.pup, pulsebrowser.29kh.in12.talos, net.exe, w32.58d6fec4ba-95.sbx.tg
- SHA256: 9f1f11a708d393e0a4109ae189bc64f1f3e312653dcf317a2bd406f18ffcc507, fed979f93bcaf4e73ebd25748093a92095d5109cbd01d55f97bdc50ce509ad2f, 9896a6fcb9bb5ac1ec5297b4a65be3f647589adf7c37b45f3f7466decd6a4a7f, 73ac1bbfaee6c76c34f655ac0477a4cd930f2aa55e658c8e312ff81aac9a741f, 58d6fec4ba24c32d38c9a0c7c39df3cb0e91f500b323e841121d703c7b718681
- MD5: 2915b3f8b703eb744fc54c81f4a9c67f, 207d9d891ac756b2bfad88aba5682c65, 38de5b216c33833af710e88f7f64fc98, 63f3351cfdf618bec6045f60203e7978, f1fe671bcefd4630e5ed8b87c9283534

### Hypotheses (3)

#### H-b21fc2a2-1 · Initial access via CVE-2026-88779 affecting Citrix NetScaler  _(confidence: high)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2026-88779 in Citrix NetScaler within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2026-88779; vectors: exploit, supply-chain, vpn-edge; impact: ransomware, ddos, fraud; products: Citrix NetScaler.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-b21fc2a2-1-O1] Inventory exposure to Citrix NetScaler** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of Citrix NetScaler, the external-exploitation hypothesis is disproven for CVE-2026-88779.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'Citrix NetScaler' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-b21fc2a2-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2026-88779 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2026-88779/ | summarize count() by src_ip, dst_host`
- **[H-b21fc2a2-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2026-88779 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2026-88779')) | summarize coverage = avg(installed) by host_role`
- **[H-b21fc2a2-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on Citrix NetScaler hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-b21fc2a2-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-b21fc2a2-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2026-88779; vectors: exploit, supply-chain, vpn-edge; impact: ransomware, ddos, fraud; products: Citrix NetScaler.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-b21fc2a2-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('sample.exe','w32.9f1f11a708-100.sbx.tg','w32.fed979f93b-95.sbx.tg') | summarize count() by client_ip`
- **[H-b21fc2a2-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-b21fc2a2-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-b21fc2a2-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-b21fc2a2-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-b21fc2a2-3 · Post-foothold lateral movement consistent with the reported actor  _(confidence: medium)_

**Statement.** An attacker who matched the TTPs of the reported actor has moved laterally inside the estate using RDP/SMB/WinRM, admin tooling, or Kerberos abuse.

**Why this hypothesis?** Archetype 'lateral_movement' selected based on CVEs cited: CVE-2026-88779; vectors: exploit, supply-chain, vpn-edge; impact: ransomware, ddos, fraud; products: Citrix NetScaler.

**MITRE ATT&CK**: T1021.001, T1021.002, T1021.006, T1003

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-b21fc2a2-3-O1] Anomalous remote logons (Type 3 / Type 10)** _(difficulty: medium · 200 pts · MITRE: T1021.001, T1021.002)_
  - Falsification criterion: If 4624 logon-type 3/10 events show no bursts from a single source to many destinations, lateral movement via RDP/SMB is unsupported.
  - Data sources: Windows Security event log, Domain Controller logs
  - Suggested query: `security | where event_id in (4624) and logon_type in (3,10) | summarize dests = dcount(dst_host) by src_user, src_host | where dests > 10`
- **[H-b21fc2a2-3-O2] Admin-tool usage outside baseline** _(difficulty: medium · 200 pts · MITRE: T1021.002, T1021.006, T1059)_
  - Falsification criterion: If PsExec / WMIC / PowerShell remoting / Impacket-style usage is absent outside known admin jump-hosts, the lateral-tool hypothesis is disproven.
  - Data sources: Sysmon EID 1, EDR, 4688
  - Suggested query: `process | where name in ('psexec.exe','psexesvc.exe','wmic.exe','wsmprovhost.exe') and host !in (admin_jumphosts)`
- **[H-b21fc2a2-3-O3] Kerberos abuse telemetry** _(difficulty: hard · 300 pts · MITRE: T1558.003, T1110.003)_
  - Falsification criterion: If 4769 ticket requests show no anomalous RC4 / odd-SPN patterns and no AS-REP roasting indicators, credential-based lateral movement is unsupported.
  - Data sources: Domain Controller security log
  - Suggested query: `security | where event_id == 4769 and ticket_encryption == 'RC4-HMAC' | summarize by target_spn, account_name`
- **[H-b21fc2a2-3-O4] Lateral file-copy staging** _(difficulty: medium · 200 pts · MITRE: T1570, T1021.002)_
  - Falsification criterion: If SMB writes of archives / executables across multiple hosts from one user/host are absent, lateral staging is unsupported.
  - Data sources: File-share auditing (5145), EDR file events
  - Suggested query: `file | where action == 'write' and ext in ('.7z','.rar','.zip','.exe') and dest matches /\\\\.*\\(C\$|admin\$)/`

---

## 9. Swann Communications SWIFI-SE2KIC

- **Source**: CISA Advisories
- **Link**: <https://www.cisa.gov/news-events/ics-advisories/icsa-26-286-02>
- **Published**: Tue, 13 Oct 26 12:00:00 +0000
- **First seen**: 2026-10-13T16:09:59+00:00
- **Relevance score**: 80
- **Score rationale**: source weight (advisory)=+15, 3 CVE(s)=+30, 1 MITRE technique hit(s)=+8, 4 initial-access vector(s)=+13, 1 impact action(s)=+8, 2 IOC(s)=+6

> View CSAF Summary Successful exploitation of these vulnerabilities could allow an attacker to view video information without authentication. The following versions of Swann Communications SWIFI-SE2KIC are affected: SWIFI-SE2KIC firmware CVSS Vendor Equipment v3 6.2 Swann Communications SWIFI-SE2KIC firmware 1 Vulnerability Missing Authentication for Critical Function Background Critical Infrastructure Sectors: Commercial Facilities Countries/Areas Deployed: Worldwide Company Headquarters Location: Australia Vulnerabilities Expand All + CVE-2026-107605 SWIFI-SE2KIC firmware versions 2.0.22 and prior are vulnerable to a Missing Authentication for Critical Function vulnerability that could allow an attacker on the local network to view live video feed without authentication. Read More 1 Affected Product Swann Communications SWIFI-SE2KIC firmware: Product Status: known_affected Remediations Mitigation Swann Communications has provided the following interim security measures. For more information, contact Swann Communications https://support.swann.com/hc/en-us/requests/new. Mitigation Keep the camera behind a secured router and firewall. Mitigation Avoid exposing RTSP services to the internet through port forwarding, DMZ configurations, or direct public IP access. Mitigation Ensure the router and associated accounts use strong, unique passwords. Mitigation Keep device firmware updated when new releases become available. Additional Metrics Relevant CWE: CWE-306 Missing Authenticati

**Extracted signals**
- CVEs: CVE-2026-107605, CVE-2026-107606, CVE-2026-107607
- Vectors: phishing, exploit, vpn-edge, social-engineering
- Actions: fraud
- Sectors: manufacturing
- MITRE ATT&CK: T1566
- Domain IOCs: support.swann.com, www.cisa.gov

### Hypotheses (3)

#### H-09aab570-1 · Initial access via CVE-2026-107605 affecting the affected product/service  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2026-107605 in the affected product/service within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2026-107605, CVE-2026-107606, CVE-2026-107607; vectors: phishing, exploit, vpn-edge; impact: fraud.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-09aab570-1-O1] Inventory exposure to the affected product** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of the affected product, the external-exploitation hypothesis is disproven for CVE-2026-107605.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'the affected product' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-09aab570-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2026-107605 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2026-107605/ | summarize count() by src_ip, dst_host`
- **[H-09aab570-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2026-107605 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2026-107605')) | summarize coverage = avg(installed) by host_role`
- **[H-09aab570-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on the affected product hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-09aab570-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-09aab570-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2026-107605, CVE-2026-107606, CVE-2026-107607; vectors: phishing, exploit, vpn-edge; impact: fraud.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-09aab570-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('support.swann.com','www.cisa.gov') | summarize count() by client_ip`
- **[H-09aab570-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-09aab570-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-09aab570-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-09aab570-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-09aab570-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2026-107605, CVE-2026-107606, CVE-2026-107607; vectors: phishing, exploit, vpn-edge; impact: fraud.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-09aab570-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-09aab570-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-09aab570-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-09aab570-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 10. Red Lion Controls N-Tron 700 Series

- **Source**: CISA Advisories
- **Link**: <https://www.cisa.gov/news-events/ics-advisories/icsa-26-281-01>
- **Published**: Thu, 08 Oct 26 12:00:00 +0000
- **First seen**: 2026-10-08T17:15:04+00:00
- **Relevance score**: 73
- **Score rationale**: source weight (advisory)=+15, 7 CVE(s)=+30, 1 MITRE technique hit(s)=+8, 4 initial-access vector(s)=+13, 1 product mention(s)=+3, 1 IOC(s)=+4

> View CSAF Summary Successful exploitation of these vulnerabilities could allow a malicious user to access the device and gain administrative access. This access would allow the user to view, edit, and upload configuration files. Further, a malicious user can cause the switch to reboot by navigating to a specific URL on the device. This action can be scripted on the malicious user's local machine to cause continuous rebooting of the switch. The following versions of Red Lion Controls N-Tron 700 Series are affected: 700 Series 700 Series CVSS Vendor Equipment v3 8.3 Red Lion Controls 700 Series 7 Vulnerabilities Use of Hard-coded Credentials, Insufficiently Protected Credentials, Storing Passwords in a Recoverable Format, Missing Authentication for Critical Function, Download of Code Without Integrity Check, Reachable Assertion, Authentication Bypass Using an Alternate Path or Channel Background Critical Infrastructure Sectors: Commercial Facilities, Communications, Critical Manufacturing, Information Technology Countries/Areas Deployed: Worldwide Company Headquarters Location: Sweden Vulnerabilities Expand All + CVE-2026-32645 Default factory credentials with administrative access are enabled and persist even after configuring other administrator accounts. Read More 2 Affected Products Red Lion Controls 700 Series: Product Status: known_affected Remediations Vendor fix Red Lion controls recommends the following upgrades for the N-Tron 700 Series: Mitigation Upgrade to firmware

**Extracted signals**
- CVEs: CVE-2026-32645, CVE-2026-39460, CVE-2026-28745, CVE-2026-33367, CVE-2026-29797, CVE-2026-39453, CVE-2026-33272
- Products: Microsoft Exchange
- Vectors: phishing, exploit, vpn-edge, social-engineering
- Sectors: manufacturing
- MITRE ATT&CK: T1566
- Domain IOCs: www.cisa.gov

### Hypotheses (3)

#### H-555f85ec-1 · Initial access via CVE-2026-32645 affecting Microsoft Exchange  _(confidence: high)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2026-32645 in Microsoft Exchange within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2026-32645, CVE-2026-39460, CVE-2026-28745; vectors: phishing, exploit, vpn-edge; products: Microsoft Exchange.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-555f85ec-1-O1] Inventory exposure to Microsoft Exchange** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of Microsoft Exchange, the external-exploitation hypothesis is disproven for CVE-2026-32645.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'Microsoft Exchange' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-555f85ec-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2026-32645 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2026-32645/ | summarize count() by src_ip, dst_host`
- **[H-555f85ec-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2026-32645 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2026-32645')) | summarize coverage = avg(installed) by host_role`
- **[H-555f85ec-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on Microsoft Exchange hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-555f85ec-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-555f85ec-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2026-32645, CVE-2026-39460, CVE-2026-28745; vectors: phishing, exploit, vpn-edge; products: Microsoft Exchange.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-555f85ec-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('www.cisa.gov') | summarize count() by client_ip`
- **[H-555f85ec-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-555f85ec-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-555f85ec-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-555f85ec-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-555f85ec-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2026-32645, CVE-2026-39460, CVE-2026-28745; vectors: phishing, exploit, vpn-edge; products: Microsoft Exchange.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-555f85ec-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-555f85ec-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-555f85ec-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-555f85ec-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 11. One breach, please, and make no mistakes

- **Source**: Cisco Talos
- **Link**: <https://blog.talosintelligence.com/one-breach-please-and-make-no-mistakes/>
- **Published**: Wed, 07 Oct 2026 10:00:25 GMT
- **First seen**: 2026-10-07T10:16:11+00:00
- **Relevance score**: 73
- **Score rationale**: source weight (vendor)=+10, 1 malware family hit(s)=+20, 3 MITRE technique hit(s)=+14, 3 initial-access vector(s)=+11, 2 impact action(s)=+11, 1 product mention(s)=+3, 1 IOC(s)=+4

> The cybersecurity community has seen examples of autonomous agents, built inside AI labs, attacking public infrastructure. How you prepare for agentic threats is what makes the difference during real incidents.

**Extracted signals**
- Malware families: Cobalt Strike
- Products: Active Directory
- Vectors: phishing, exploit, vpn-edge
- Actions: ransomware, fraud
- Sectors: manufacturing
- MITRE ATT&CK: T1566, T1486, T1219
- Domain IOCs: agents.md

### Hypotheses (4)

#### H-eab258b0-1 · Initial access via the disclosed vulnerability affecting Active Directory  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting the disclosed vulnerability in Active Directory within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on malware families: Cobalt Strike; vectors: phishing, exploit, vpn-edge; impact: ransomware, fraud; products: Active Directory.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-eab258b0-1-O1] Inventory exposure to Active Directory** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of Active Directory, the external-exploitation hypothesis is disproven for the referenced CVE.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'Active Directory' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-eab258b0-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for the referenced CVE in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-the referenced CVE/ | summarize count() by src_ip, dst_host`
- **[H-eab258b0-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the the referenced CVE fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('the referenced CVE')) | summarize coverage = avg(installed) by host_role`
- **[H-eab258b0-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on Active Directory hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-eab258b0-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-eab258b0-2 · Endpoint execution of Cobalt Strike  _(confidence: high)_

**Statement.** One or more endpoints in the estate have executed or attempted to execute Cobalt Strike payloads since the reporting date.

**Why this hypothesis?** Archetype 'malware_execution' selected based on malware families: Cobalt Strike; vectors: phishing, exploit, vpn-edge; impact: ransomware, fraud; products: Active Directory.

**MITRE ATT&CK**: T1204, T1059, T1547

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-eab258b0-2-O1] EDR hash sweep for Cobalt Strike** _(difficulty: easy · 150 pts · MITRE: T1204, T1059)_
  - Falsification criterion: If a search of EDR file/process telemetry for known Cobalt Strike SHA256s returns zero hits in the last 90 days, payload presence is disproven.
  - Data sources: EDR (CrowdStrike/Defender/SentinelOne), Threat-intel feed
  - Suggested query: `process_events | where sha256 in (ti_lookup('Cobalt Strike', 'sha256')) | summarize count() by host`
- **[H-eab258b0-2-O2] Behavioural pattern hunt for Cobalt Strike** _(difficulty: medium · 200 pts · MITRE: T1059.001, T1059.005, T1218.011)_
  - Falsification criterion: If parent/child anomalies typical of the family (e.g. Office spawning script hosts, rundll32 chains) are absent across the estate, execution chain is unsupported.
  - Data sources: Sysmon EID 1, EDR process tree
  - Suggested query: `process | where parent in ('winword.exe','excel.exe','outlook.exe') and child in ('rundll32.exe','wscript.exe','mshta.exe','powershell.exe')`
- **[H-eab258b0-2-O3] Persistence-key inspection** _(difficulty: medium · 200 pts · MITRE: T1547.001, T1053.005)_
  - Falsification criterion: If autoruns, scheduled tasks, services, and WMI subscriptions show no Cobalt Strike-aligned artifacts, post-execution persistence is disproven.
  - Data sources: Sysmon EID 13/12, Autoruns sweep, EDR persistence module
  - Suggested query: `registry_set | where key matches /Run|RunOnce|Image File Execution Options/ and value matches /unusual-path/`
- **[H-eab258b0-2-O4] AV / quarantine retrospective** _(difficulty: easy · 100 pts · MITRE: T1204)_
  - Falsification criterion: If retrospective AV / quarantine logs show no detections for related signatures over the last 30 days, the family is unlikely to have landed in-environment.
  - Data sources: AV management console, Defender ATP detections
  - Suggested query: `av_events | where signature contains 'Cobalt Strike' | summarize by host, action`
- **[H-eab258b0-2-O5] Memory-resident loader check** _(difficulty: hard · 300 pts · MITRE: T1620, T1055)_
  - Falsification criterion: If a memory scan (YARA via EDR / Volatility) finds none of the published loader patterns on a sampled set of high-risk hosts, in-memory residency is unsupported.
  - Data sources: YARA via EDR, Volatility on a sampled host
  - Suggested query: `memory_scan | yara_rule == 'rule_cobalt_strike' | summarize by host`

#### H-eab258b0-3 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on malware families: Cobalt Strike; vectors: phishing, exploit, vpn-edge; impact: ransomware, fraud; products: Active Directory.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-eab258b0-3-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('agents.md') | summarize count() by client_ip`
- **[H-eab258b0-3-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-eab258b0-3-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-eab258b0-3-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-eab258b0-3-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-eab258b0-4 · Post-foothold lateral movement consistent with the reported actor  _(confidence: medium)_

**Statement.** An attacker who matched the TTPs of the reported actor has moved laterally inside the estate using RDP/SMB/WinRM, admin tooling, or Kerberos abuse.

**Why this hypothesis?** Archetype 'lateral_movement' selected based on malware families: Cobalt Strike; vectors: phishing, exploit, vpn-edge; impact: ransomware, fraud; products: Active Directory.

**MITRE ATT&CK**: T1021.001, T1021.002, T1021.006, T1003

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-eab258b0-4-O1] Anomalous remote logons (Type 3 / Type 10)** _(difficulty: medium · 200 pts · MITRE: T1021.001, T1021.002)_
  - Falsification criterion: If 4624 logon-type 3/10 events show no bursts from a single source to many destinations, lateral movement via RDP/SMB is unsupported.
  - Data sources: Windows Security event log, Domain Controller logs
  - Suggested query: `security | where event_id in (4624) and logon_type in (3,10) | summarize dests = dcount(dst_host) by src_user, src_host | where dests > 10`
- **[H-eab258b0-4-O2] Admin-tool usage outside baseline** _(difficulty: medium · 200 pts · MITRE: T1021.002, T1021.006, T1059)_
  - Falsification criterion: If PsExec / WMIC / PowerShell remoting / Impacket-style usage is absent outside known admin jump-hosts, the lateral-tool hypothesis is disproven.
  - Data sources: Sysmon EID 1, EDR, 4688
  - Suggested query: `process | where name in ('psexec.exe','psexesvc.exe','wmic.exe','wsmprovhost.exe') and host !in (admin_jumphosts)`
- **[H-eab258b0-4-O3] Kerberos abuse telemetry** _(difficulty: hard · 300 pts · MITRE: T1558.003, T1110.003)_
  - Falsification criterion: If 4769 ticket requests show no anomalous RC4 / odd-SPN patterns and no AS-REP roasting indicators, credential-based lateral movement is unsupported.
  - Data sources: Domain Controller security log
  - Suggested query: `security | where event_id == 4769 and ticket_encryption == 'RC4-HMAC' | summarize by target_spn, account_name`
- **[H-eab258b0-4-O4] Lateral file-copy staging** _(difficulty: medium · 200 pts · MITRE: T1570, T1021.002)_
  - Falsification criterion: If SMB writes of archives / executables across multiple hosts from one user/host are absent, lateral staging is unsupported.
  - Data sources: File-share auditing (5145), EDR file events
  - Suggested query: `file | where action == 'write' and ext in ('.7z','.rar','.zip','.exe') and dest matches /\\\\.*\\(C\$|admin\$)/`

---

## 12. Guangzhou Juan IoT Technology EseeCloud

- **Source**: CISA Advisories
- **Link**: <https://www.cisa.gov/news-events/ics-advisories/icsa-26-288-02>
- **Published**: Thu, 15 Oct 26 12:00:00 +0000
- **First seen**: 2026-10-15T17:01:00+00:00
- **Relevance score**: 72
- **Score rationale**: source weight (advisory)=+15, 3 CVE(s)=+30, 1 MITRE technique hit(s)=+8, 4 initial-access vector(s)=+13, 2 IOC(s)=+6

> View CSAF Summary Successful exploitation of these vulnerabilities could allow an attacker to gain control over affected IP cameras. The following versions of Guangzhou Juan IoT Technology EseeCloud are affected: EseeCloud App EseeCloud Firmware CVSS Vendor Equipment v3 9.8 Guangzhou Juan IoT Technology Co., Ltd. EseeCloud App 3 Vulnerabilities Use of Hard-coded Credentials, Improperly Controlled Modification of Dynamically-Determined Object Attributes, Observable Response Discrepancy Background Critical Infrastructure Sectors: Energy, Communications, Transportation Systems, Financial Services, Government Services and Facilities Countries/Areas Deployed: Worldwide Company Headquarters Location: China Vulnerabilities Expand All + CVE-2026-107617 An attacker can use a hard-coded credential to log in to EseeCloud devices. Read More 2 Affected Products Guangzhou Juan IoT Technology Co., Ltd. EseeCloud App: Product Status: known_affected Remediations Mitigation Guangzhou Juan IoT Technology Co., Ltd. did not respond to CISA's coordination attempts. EseeCloud users are advised to contact Guangzhou Juan IoT Technology Co., Ltd. for support https://eseecloud.app/. Guangzhou Juan IoT Technology Co., Ltd. EseeCloud Firmware: Product Status: known_affected Remediations Mitigation Guangzhou Juan IoT Technology Co., Ltd. did not respond to CISA's coordination attempts. EseeCloud users are advised to contact Guangzhou Juan IoT Technology Co., Ltd. for support https://eseecloud.app/. Additi

**Extracted signals**
- CVEs: CVE-2026-107617, CVE-2026-97858, CVE-2026-105664
- Vectors: phishing, exploit, vpn-edge, social-engineering
- Sectors: finance, government, energy, manufacturing, education
- MITRE ATT&CK: T1566
- Domain IOCs: eseecloud.app, www.cisa.gov

### Hypotheses (3)

#### H-08e65857-1 · Initial access via CVE-2026-107617 affecting the affected product/service  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2026-107617 in the affected product/service within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2026-107617, CVE-2026-97858, CVE-2026-105664; vectors: phishing, exploit, vpn-edge.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-08e65857-1-O1] Inventory exposure to the affected product** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of the affected product, the external-exploitation hypothesis is disproven for CVE-2026-107617.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'the affected product' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-08e65857-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2026-107617 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2026-107617/ | summarize count() by src_ip, dst_host`
- **[H-08e65857-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2026-107617 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2026-107617')) | summarize coverage = avg(installed) by host_role`
- **[H-08e65857-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on the affected product hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-08e65857-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-08e65857-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2026-107617, CVE-2026-97858, CVE-2026-105664; vectors: phishing, exploit, vpn-edge.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-08e65857-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('eseecloud.app','www.cisa.gov') | summarize count() by client_ip`
- **[H-08e65857-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-08e65857-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-08e65857-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-08e65857-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-08e65857-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2026-107617, CVE-2026-97858, CVE-2026-105664; vectors: phishing, exploit, vpn-edge.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-08e65857-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-08e65857-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-08e65857-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-08e65857-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 13. 3 lessons from frontier AI vulnerability research

- **Source**: Microsoft Security
- **Link**: <https://www.microsoft.com/en-us/security/blog/2026/10/07/3-lessons-from-frontier-ai-vulnerability-research/>
- **Published**: Wed, 07 Oct 2026 16:00:00 +0000
- **First seen**: 2026-10-07T16:52:59+00:00
- **Relevance score**: 71
- **Score rationale**: source weight (vendor)=+10, 4 CVE(s)=+30, 2 initial-access vector(s)=+9, 1 impact action(s)=+8, 2 product mention(s)=+6, 3 IOC(s)=+8

> Read how How Microsoft Security's FORGE Lab is scaling vulnerability research from Windows to the Linux kernel. The post 3 lessons from frontier AI vulnerability research appeared first on Microsoft Security Blog .

**Extracted signals**
- CVEs: CVE-2026-9545, CVE-2026-13608, CVE-2026-56848, CVE-2026-64563
- Products: Microsoft Exchange, Linux kernel
- Vectors: phishing, exploit
- Actions: fraud
- Sectors: manufacturing
- Domain IOCs: llama.cpp, node.js, lore.kernel.org

### Hypotheses (3)

#### H-96e71ee1-1 · Initial access via CVE-2026-9545 affecting Microsoft Exchange  _(confidence: high)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2026-9545 in Microsoft Exchange within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2026-9545, CVE-2026-13608, CVE-2026-56848; vectors: phishing, exploit; impact: fraud; products: Microsoft Exchange, Linux kernel.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-96e71ee1-1-O1] Inventory exposure to Microsoft Exchange** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of Microsoft Exchange, the external-exploitation hypothesis is disproven for CVE-2026-9545.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'Microsoft Exchange' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-96e71ee1-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2026-9545 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2026-9545/ | summarize count() by src_ip, dst_host`
- **[H-96e71ee1-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2026-9545 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2026-9545')) | summarize coverage = avg(installed) by host_role`
- **[H-96e71ee1-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on Microsoft Exchange hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-96e71ee1-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-96e71ee1-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2026-9545, CVE-2026-13608, CVE-2026-56848; vectors: phishing, exploit; impact: fraud; products: Microsoft Exchange, Linux kernel.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-96e71ee1-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('llama.cpp','node.js','lore.kernel.org') | summarize count() by client_ip`
- **[H-96e71ee1-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-96e71ee1-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-96e71ee1-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-96e71ee1-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-96e71ee1-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2026-9545, CVE-2026-13608, CVE-2026-56848; vectors: phishing, exploit; impact: fraud; products: Microsoft Exchange, Linux kernel.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-96e71ee1-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-96e71ee1-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-96e71ee1-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-96e71ee1-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 14. Two hardening tools (AD+Windows) in ps1

- **Source**: /r/blueteamsec
- **Link**: <https://www.reddit.com/r/blueteamsec/comments/1x7hvhz/two_hardening_tools_adwindows_in_ps1/>
- **Published**: 2026-10-16T14:34:23+00:00
- **First seen**: 2026-10-17T02:24:11+00:00
- **Relevance score**: 70
- **Score rationale**: source weight (social)=+2, 2 CVE(s)=+25, 4 MITRE technique hit(s)=+17, 3 initial-access vector(s)=+11, 1 impact action(s)=+8, 1 product mention(s)=+3, 1 IOC(s)=+4

> Hey, i'm working on those two little tools, any feedback is appreciated. ->>HostBadger, an open-source Windows hardening auditor in pure PowerShell. One read-only script takes a snapshot of each host, and you can push it through your EDR (CrowdStrike RTR or any tool that runs scripts) to a whole fleet in about 15 seconds per host. The analyzer then works offline and writes a clean HTML report with A–F scores, plus CSV and JSON Lines for your SIEM. - 138 checks: credentials, Defender and EDR, network exposure and NTLM relay paths, privilege escalation, logging, BitLocker - 1475 DISA STIG rules plus the CIS benchmark of each host's own Windows version, with the value found next to the value required - Vulnerable drivers (LOLDrivers), end-of-life and outdated software (endoflife.date), CISA KEV matches - Read-only by design, with a safety script that checks this from the code. No network unless you ask. What it can't read is "not evaluated", never clean. - Reversible fix scripts with rollback, and an optional AI summary where names become tokens before anything is sent Nothing to install (PowerShell 5.1 or 7): https://github.com/g4bri-3l3/HostBadger & ->>IDWolf: my own AD/Entra ID hardening tool that tells you whether your domain can be taken, and through which real-world attacks. Open-source, pure PowerShell, read-only collection (native cmdlets only), offline analysis. Recent attacks mapped to checks: BadSuccessor, Golden dMSA, coercion + NTLM relay to LDAP and AD CS (CVE-2025

**Extracted signals**
- CVEs: CVE-2025-24054, CVE-2025-33073
- Products: Microsoft 365 / Entra ID
- Vectors: phishing, exploit, cloud-misconfig
- Actions: fraud
- Sectors: manufacturing
- MITRE ATT&CK: T1566, T1059, T1059.001, T1110
- Domain IOCs: endoflife.date

### Hypotheses (3)

#### H-046f10c8-1 · Initial access via CVE-2025-24054 affecting Microsoft 365 / Entra ID  _(confidence: high)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2025-24054 in Microsoft 365 / Entra ID within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2025-24054, CVE-2025-33073; vectors: phishing, exploit, cloud-misconfig; impact: fraud; products: Microsoft 365 / Entra ID.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-046f10c8-1-O1] Inventory exposure to Microsoft 365 / Entra ID** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of Microsoft 365 / Entra ID, the external-exploitation hypothesis is disproven for CVE-2025-24054.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'Microsoft 365 / Entra ID' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-046f10c8-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2025-24054 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2025-24054/ | summarize count() by src_ip, dst_host`
- **[H-046f10c8-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2025-24054 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2025-24054')) | summarize coverage = avg(installed) by host_role`
- **[H-046f10c8-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on Microsoft 365 / Entra ID hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-046f10c8-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-046f10c8-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2025-24054, CVE-2025-33073; vectors: phishing, exploit, cloud-misconfig; impact: fraud; products: Microsoft 365 / Entra ID.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-046f10c8-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('endoflife.date') | summarize count() by client_ip`
- **[H-046f10c8-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-046f10c8-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-046f10c8-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-046f10c8-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-046f10c8-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2025-24054, CVE-2025-33073; vectors: phishing, exploit, cloud-misconfig; impact: fraud; products: Microsoft 365 / Entra ID.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-046f10c8-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-046f10c8-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-046f10c8-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-046f10c8-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 15. J4Care dcm4che

- **Source**: CISA Advisories
- **Link**: <https://www.cisa.gov/news-events/ics-medical-advisories/icsma-26-288-02>
- **Published**: Thu, 15 Oct 26 12:00:00 +0000
- **First seen**: 2026-10-15T17:01:00+00:00
- **Relevance score**: 70
- **Score rationale**: source weight (advisory)=+15, 6 CVE(s)=+30, 1 MITRE technique hit(s)=+8, 4 initial-access vector(s)=+13, 1 IOC(s)=+4

> View CSAF Summary Successful exploitation of these vulnerabilities could allow an attacker to delete stored medical images, disclose patient information, inject forged studies, reassign patient records, overwrite files, and cause a denial-of-service condition. The following versions of J4Care dcm4che are affected: dcm4chee-arc-light 5.35.1 (CVE-2026-97851, CVE-2026-107621, CVE-2026-105273, CVE-2026-101021, CVE-2026-105279, CVE-2026-105667) CVSS Vendor Equipment v3 9.1 J4Care dcm4chee-arc-light 4 Vulnerabilities Missing Authorization, Loop with Unreachable Exit Condition ('Infinite Loop'), Inefficient Algorithmic Complexity, Missing Authentication for Critical Function Background Critical Infrastructure Sectors: Healthcare and Public Health Countries/Areas Deployed: Worldwide Company Headquarters Location: Austria Vulnerabilities Expand All + CVE-2026-97851 The storage status-change REST service allows location records still associated with DICOM instances to be changed to deletion-related states. Changing a location to TO_DELETE causes PurgeStorageScheduler to delete the referenced object from storage even though the corresponding instance record remains in the database. Read More 1 Affected Product J4Care dcm4chee-arc-light: 5.35.1 Product Status: known_affected Remediations Mitigation J4Care has provided a fix for the vulnerabilities. J4Care recommends users implement release 5.35.2 or later. Additional Metrics Relevant CWE: CWE-862 Missing Authorization CVSS Version Base S

**Extracted signals**
- CVEs: CVE-2026-97851, CVE-2026-107621, CVE-2026-105273, CVE-2026-101021, CVE-2026-105279, CVE-2026-105667
- Vectors: phishing, exploit, vpn-edge, social-engineering
- Sectors: healthcare, manufacturing
- MITRE ATT&CK: T1566
- Domain IOCs: www.cisa.gov

### Hypotheses (3)

#### H-a0effe20-1 · Initial access via CVE-2026-97851 affecting the affected product/service  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2026-97851 in the affected product/service within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2026-97851, CVE-2026-107621, CVE-2026-105273; vectors: phishing, exploit, vpn-edge.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-a0effe20-1-O1] Inventory exposure to the affected product** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of the affected product, the external-exploitation hypothesis is disproven for CVE-2026-97851.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'the affected product' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-a0effe20-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2026-97851 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2026-97851/ | summarize count() by src_ip, dst_host`
- **[H-a0effe20-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2026-97851 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2026-97851')) | summarize coverage = avg(installed) by host_role`
- **[H-a0effe20-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on the affected product hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-a0effe20-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-a0effe20-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2026-97851, CVE-2026-107621, CVE-2026-105273; vectors: phishing, exploit, vpn-edge.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-a0effe20-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('www.cisa.gov') | summarize count() by client_ip`
- **[H-a0effe20-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-a0effe20-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-a0effe20-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-a0effe20-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-a0effe20-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2026-97851, CVE-2026-107621, CVE-2026-105273; vectors: phishing, exploit, vpn-edge.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-a0effe20-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-a0effe20-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-a0effe20-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-a0effe20-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 16. Microsoft Patch Tuesday for October 2026 — Snort rules and prominent vulnerabilities

- **Source**: Cisco Talos
- **Link**: <https://blog.talosintelligence.com/microsoft-patch-tuesday-for-october-2026/>
- **Published**: Tue, 13 Oct 2026 20:37:58 GMT
- **First seen**: 2026-10-13T20:48:54+00:00
- **Relevance score**: 70
- **Score rationale**: source weight (vendor)=+10, 193 CVE(s)=+30, 1 MITRE technique hit(s)=+8, 2 initial-access vector(s)=+9, 3 product mention(s)=+9, 1 IOC(s)=+4

> Blog post covering the vulnerabilities disclosed during Microsoft Patch Tuesday.

**Extracted signals**
- CVEs: CVE-2026-96951, CVE-2026-70229, CVE-2026-70571, CVE-2026-105733, CVE-2026-102214, CVE-2026-108399, CVE-2026-100202, CVE-2026-100209, CVE-2026-100210, CVE-2026-100211, CVE-2026-97739, CVE-2026-97745, CVE-2026-97755, CVE-2026-97759, CVE-2026-97765, CVE-2026-97778, CVE-2026-97741, CVE-2026-97742, CVE-2026-97753, CVE-2026-97756, CVE-2026-97758, CVE-2026-97761, CVE-2026-97767, CVE-2026-97776, CVE-2026-97780, CVE-2026-100215, CVE-2026-100219, CVE-2026-105016, CVE-2026-100220, CVE-2026-102211, CVE-2026-88074, CVE-2026-108130, CVE-2026-108471, CVE-2026-96914, CVE-2026-102225, CVE-2026-97814, CVE-2026-102855, CVE-2026-102856, CVE-2026-102857, CVE-2026-102866, CVE-2026-62840, CVE-2026-69802, CVE-2026-70147, CVE-2026-70153, CVE-2026-108467, CVE-2026-70187, CVE-2026-70250, CVE-2026-83934, CVE-2026-88073, CVE-2026-88117, CVE-2026-88119, CVE-2026-88120, CVE-2026-88171, CVE-2026-96934, CVE-2026-96222, CVE-2026-108131, CVE-2026-96913, CVE-2026-96952, CVE-2026-105718, CVE-2026-108400, CVE-2026-108457, CVE-2026-108460, CVE-2026-70215, CVE-2026-88144, CVE-2026-88178, CVE-2026-88207, CVE-2026-70242, CVE-2026-70291, CVE-2026-88156, CVE-2026-97016, CVE-2026-97749, CVE-2026-70269, CVE-2026-70300, CVE-2026-83917, CVE-2026-94510, CVE-2026-96202, CVE-2026-96943, CVE-2026-96207, CVE-2026-69789, CVE-2026-88174, CVE-2026-88185, CVE-2026-69435, CVE-2026-77900, CVE-2026-83943, CVE-2026-83947, CVE-2026-88131, CVE-2026-100214, CVE-2026-102217, CVE-2026-69673, CVE-2026-69718, CVE-2026-69733, CVE-2026-69783, CVE-2026-69882, CVE-2026-69923, CVE-2026-69926, CVE-2026-70054, CVE-2026-70060, CVE-2026-70076, CVE-2026-70104, CVE-2026-70108, CVE-2026-70117, CVE-2026-70132, CVE-2026-70144, CVE-2026-70156, CVE-2026-70218, CVE-2026-70223, CVE-2026-70233, CVE-2026-70236, CVE-2026-70237, CVE-2026-70241, CVE-2026-70245, CVE-2026-70249, CVE-2026-70253, CVE-2026-70255, CVE-2026-70271, CVE-2026-70273, CVE-2026-70286, CVE-2026-70303, CVE-2026-72955, CVE-2026-81971, CVE-2026-83505, CVE-2026-83509, CVE-2026-83510, CVE-2026-83580, CVE-2026-83669, CVE-2026-83699, CVE-2026-83704, CVE-2026-83717, CVE-2026-83724, CVE-2026-83732, CVE-2026-83735, CVE-2026-83738, CVE-2026-83750, CVE-2026-83761, CVE-2026-83763, CVE-2026-83768, CVE-2026-83769, CVE-2026-83793, CVE-2026-83830, CVE-2026-83834, CVE-2026-83840, CVE-2026-83842, CVE-2026-83848, CVE-2026-83867, CVE-2026-83886, CVE-2026-83896, CVE-2026-83899, CVE-2026-83902, CVE-2026-83921, CVE-2026-84014, CVE-2026-85355, CVE-2026-85791, CVE-2026-85802, CVE-2026-85804, CVE-2026-85832, CVE-2026-85843, CVE-2026-85848, CVE-2026-85849, CVE-2026-85850, CVE-2026-85855, CVE-2026-85870, CVE-2026-85901, CVE-2026-85908, CVE-2026-85941, CVE-2026-85945, CVE-2026-88118, CVE-2026-88133, CVE-2026-88147, CVE-2026-88152, CVE-2026-88159, CVE-2026-88191, CVE-2026-96858, CVE-2026-96911, CVE-2026-96929, CVE-2026-96940, CVE-2026-69452, CVE-2026-69880, CVE-2026-69918, CVE-2026-70103, CVE-2026-70106, CVE-2026-70151, CVE-2026-70176, CVE-2026-70279, CVE-2026-83785, CVE-2026-83927, CVE-2026-85884, CVE-2026-85902, CVE-2026-85906, CVE-2026-88093, CVE-2026-96939, CVE-2026-97798, CVE-2026-97799, CVE-2026-97800
- Products: Microsoft Exchange, Active Directory, Linux kernel
- Vectors: exploit, rdp
- Sectors: manufacturing
- MITRE ATT&CK: T1021.001
- Domain IOCs: snort.org

### Hypotheses (3)

#### H-4df1bd97-1 · Initial access via CVE-2026-96951 affecting Microsoft Exchange  _(confidence: high)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2026-96951 in Microsoft Exchange within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2026-96951, CVE-2026-70229, CVE-2026-70571; vectors: exploit, rdp; products: Microsoft Exchange, Active Directory, Linux kernel.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-4df1bd97-1-O1] Inventory exposure to Microsoft Exchange** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of Microsoft Exchange, the external-exploitation hypothesis is disproven for CVE-2026-96951.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'Microsoft Exchange' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-4df1bd97-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2026-96951 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2026-96951/ | summarize count() by src_ip, dst_host`
- **[H-4df1bd97-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2026-96951 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2026-96951')) | summarize coverage = avg(installed) by host_role`
- **[H-4df1bd97-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on Microsoft Exchange hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-4df1bd97-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-4df1bd97-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2026-96951, CVE-2026-70229, CVE-2026-70571; vectors: exploit, rdp; products: Microsoft Exchange, Active Directory, Linux kernel.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-4df1bd97-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('snort.org') | summarize count() by client_ip`
- **[H-4df1bd97-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-4df1bd97-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-4df1bd97-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-4df1bd97-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-4df1bd97-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2026-96951, CVE-2026-70229, CVE-2026-70571; vectors: exploit, rdp; products: Microsoft Exchange, Active Directory, Linux kernel.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-4df1bd97-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-4df1bd97-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-4df1bd97-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-4df1bd97-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 17. Satel Netco Design

- **Source**: CISA Advisories
- **Link**: <https://www.cisa.gov/news-events/ics-advisories/icsa-26-281-03>
- **Published**: Thu, 08 Oct 26 12:00:00 +0000
- **First seen**: 2026-10-08T17:15:04+00:00
- **Relevance score**: 70
- **Score rationale**: source weight (advisory)=+15, 4 CVE(s)=+30, 1 MITRE technique hit(s)=+8, 4 initial-access vector(s)=+13, 1 IOC(s)=+4

> View CSAF Summary Successful exploitation of these vulnerabilities could allow an attacker to execute arbitrary scripts in a user's browser, consume excessive system resources, enumerate files, create or modify files, and potentially execute arbitrary code. The following versions of Satel Netco Design are affected: Satel Netco Design CVSS Vendor Equipment v3 8.8 Satel Satel Netco Design 3 Vulnerabilities Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting'), Inefficient Regular Expression Complexity, Relative Path Traversal Background Critical Infrastructure Sectors: Communications Countries/Areas Deployed: Worldwide Company Headquarters Location: Finland Vulnerabilities Expand All + CVE-2026-105269 Satel Netco Design versions prior to v2.1.7 contains a stored cross site scripting vulnerability. An authenticated user with Network Operator privileges could store untrusted content that is rendered without adequate neutralization. Successful exploitation could allow script execution in another user's browser when the affected content is viewed. Read More 1 Affected Product Satel Satel Netco Design: Product Status: known_affected Remediations Vendor fix Satel advises users to update to Satel Netco Design v2.1.7. Additional Metrics Relevant CWE: CWE-79 Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') CVSS Version Base Score Base Severity Vector String 3.1 6.8 MEDIUM CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:U/C:H/I:H/A:H 4.0 

**Extracted signals**
- CVEs: CVE-2026-105269, CVE-2026-104628, CVE-2026-105275, CVE-2026-101024
- Vectors: phishing, exploit, vpn-edge, social-engineering
- Sectors: manufacturing
- MITRE ATT&CK: T1566
- Domain IOCs: www.cisa.gov

### Hypotheses (3)

#### H-6792f9e0-1 · Initial access via CVE-2026-105269 affecting the affected product/service  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2026-105269 in the affected product/service within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2026-105269, CVE-2026-104628, CVE-2026-105275; vectors: phishing, exploit, vpn-edge.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-6792f9e0-1-O1] Inventory exposure to the affected product** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of the affected product, the external-exploitation hypothesis is disproven for CVE-2026-105269.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'the affected product' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-6792f9e0-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2026-105269 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2026-105269/ | summarize count() by src_ip, dst_host`
- **[H-6792f9e0-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2026-105269 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2026-105269')) | summarize coverage = avg(installed) by host_role`
- **[H-6792f9e0-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on the affected product hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-6792f9e0-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-6792f9e0-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2026-105269, CVE-2026-104628, CVE-2026-105275; vectors: phishing, exploit, vpn-edge.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-6792f9e0-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('www.cisa.gov') | summarize count() by client_ip`
- **[H-6792f9e0-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-6792f9e0-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-6792f9e0-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-6792f9e0-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-6792f9e0-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2026-105269, CVE-2026-104628, CVE-2026-105275; vectors: phishing, exploit, vpn-edge.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-6792f9e0-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-6792f9e0-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-6792f9e0-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-6792f9e0-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 18. Grid Protection Alliance openPDC and openHistorian

- **Source**: CISA Advisories
- **Link**: <https://www.cisa.gov/news-events/ics-advisories/icsa-26-281-02>
- **Published**: Thu, 08 Oct 26 12:00:00 +0000
- **First seen**: 2026-10-08T17:15:04+00:00
- **Relevance score**: 70
- **Score rationale**: source weight (advisory)=+15, 6 CVE(s)=+30, 1 MITRE technique hit(s)=+8, 4 initial-access vector(s)=+13, 1 IOC(s)=+4

> View CSAF Summary The following versions of Grid Protection Alliance openPDC and openHistorian are affected: openPDC openPDC (Docker image) openHistorian CVSS Vendor Equipment v3 9.8 Grid Protection Alliance openPDC 5 Vulnerabilities Deserialization of Untrusted Data, Missing Authentication for Critical Function, Server-Side Request Forgery (SSRF), Use of Hard-coded Credentials, Use of Externally-Controlled Input to Select Classes or Code ('Unsafe Reflection') Background Critical Infrastructure Sectors: Energy Countries/Areas Deployed: Worldwide Company Headquarters Location: United States Vulnerabilities Expand All + CVE-2026-100730 A service console interface on openPDC and openHistorian deserializes a client-supplied data structure. On systems using Windows Authentication, an attacker must already be authenticated to reach this function; on systems without Windows Authentication, this is reachable by an unauthenticated network attacker. This allows an attacker to trigger deserialization of an arbitrary object graph, which could allow remote code execution under the privileges of the affected service account. Read More 3 Affected Products Grid Protection Alliance openPDC Product Status: known_affected Remediations Vendor fix Grid Protection Alliance has added additional validation into serialization logic in openPDC version 2.9.482 and later and openHistorian version 2.8.585 and later. Systems using Windows Authentication are additionally protected, as they require the atta

**Extracted signals**
- CVEs: CVE-2026-100730, CVE-2026-105281, CVE-2026-85479, CVE-2026-101022, CVE-2026-105278, CVE-2026-104629
- Vectors: phishing, exploit, vpn-edge, social-engineering
- Sectors: energy, manufacturing
- MITRE ATT&CK: T1566
- Domain IOCs: www.cisa.gov

### Hypotheses (3)

#### H-f4fe30fe-1 · Initial access via CVE-2026-100730 affecting the affected product/service  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2026-100730 in the affected product/service within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2026-100730, CVE-2026-105281, CVE-2026-85479; vectors: phishing, exploit, vpn-edge.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-f4fe30fe-1-O1] Inventory exposure to the affected product** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of the affected product, the external-exploitation hypothesis is disproven for CVE-2026-100730.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'the affected product' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-f4fe30fe-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2026-100730 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2026-100730/ | summarize count() by src_ip, dst_host`
- **[H-f4fe30fe-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2026-100730 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2026-100730')) | summarize coverage = avg(installed) by host_role`
- **[H-f4fe30fe-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on the affected product hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-f4fe30fe-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-f4fe30fe-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2026-100730, CVE-2026-105281, CVE-2026-85479; vectors: phishing, exploit, vpn-edge.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-f4fe30fe-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('www.cisa.gov') | summarize count() by client_ip`
- **[H-f4fe30fe-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-f4fe30fe-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-f4fe30fe-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-f4fe30fe-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-f4fe30fe-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2026-100730, CVE-2026-105281, CVE-2026-85479; vectors: phishing, exploit, vpn-edge.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-f4fe30fe-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-f4fe30fe-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-f4fe30fe-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-f4fe30fe-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 19. Johnson Controls EasyIO FG

- **Source**: CISA Advisories
- **Link**: <https://www.cisa.gov/news-events/ics-advisories/icsa-26-279-01>
- **Published**: Tue, 06 Oct 26 12:00:00 +0000
- **First seen**: 2026-10-06T16:35:14+00:00
- **Relevance score**: 70
- **Score rationale**: source weight (advisory)=+15, 2 CVE(s)=+25, 2 MITRE technique hit(s)=+11, 4 initial-access vector(s)=+13, 2 IOC(s)=+6

> View CSAF Summary Successful exploitation of these vulnerabilities could allow an attacker to gain full unauthorized access to the device. The following versions of Johnson Controls EasyIO FG are affected: EasyIO FG firmware CVSS Vendor Equipment v3 7.7 Johnson Controls EasyIO FG firmware 2 Vulnerabilities Use of Hard-coded Credentials, Improper Privilege Management Background Critical Infrastructure Sectors: Critical Manufacturing, Commercial Facilities, Government Services and Facilities, Transportation Systems, Energy Countries/Areas Deployed: Worldwide Company Headquarters Location: Ireland Vulnerabilities Expand All + CVE-2026-27872 A vulnerability exists in EasyIO FG relating to an attacker gaining unauthorized access to the system through hard-coded credentials and improper privilege management, potentially resulting in full device compromise. Successful exploitation could result in technical or operational impact. Read More 1 Affected Product Johnson Controls EasyIO FG firmware: Product Status: known_affected Remediations Mitigation Johnson Controls has determined that the EasyIO FG Series has reached End-of-Life (EOL) and End-of-Support (EOS) status. The product has not been manufactured or sold since prior to 2019, and the source code is no longer available. As a result, no firmware patch or code-level fix will be issued. Users are advised to migrate to supported current-generation products (e.g., EasyIO Neo R1 Series). Mitigation Deploy devices only within isolated

**Extracted signals**
- CVEs: CVE-2026-27872, CVE-2026-27873
- Vectors: phishing, exploit, vpn-edge, social-engineering
- Sectors: government, energy, manufacturing, education
- MITRE ATT&CK: T1566, T1219
- Domain IOCs: www.johnsoncontrols.com, www.cisa.gov

### Hypotheses (3)

#### H-220c1cfb-1 · Initial access via CVE-2026-27872 affecting the affected product/service  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2026-27872 in the affected product/service within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2026-27872, CVE-2026-27873; vectors: phishing, exploit, vpn-edge.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-220c1cfb-1-O1] Inventory exposure to the affected product** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of the affected product, the external-exploitation hypothesis is disproven for CVE-2026-27872.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'the affected product' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-220c1cfb-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2026-27872 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2026-27872/ | summarize count() by src_ip, dst_host`
- **[H-220c1cfb-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2026-27872 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2026-27872')) | summarize coverage = avg(installed) by host_role`
- **[H-220c1cfb-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on the affected product hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-220c1cfb-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-220c1cfb-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2026-27872, CVE-2026-27873; vectors: phishing, exploit, vpn-edge.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-220c1cfb-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('www.johnsoncontrols.com','www.cisa.gov') | summarize count() by client_ip`
- **[H-220c1cfb-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-220c1cfb-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-220c1cfb-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-220c1cfb-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-220c1cfb-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2026-27872, CVE-2026-27873; vectors: phishing, exploit, vpn-edge.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-220c1cfb-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-220c1cfb-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-220c1cfb-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-220c1cfb-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 20. Hitachi Energy REB500

- **Source**: CISA Advisories
- **Link**: <https://www.cisa.gov/news-events/ics-advisories/icsa-26-279-05>
- **Published**: Tue, 06 Oct 26 12:00:00 +0000
- **First seen**: 2026-10-06T16:35:14+00:00
- **Relevance score**: 67
- **Score rationale**: source weight (advisory)=+15, 2 CVE(s)=+25, 2 initial-access vector(s)=+9, 1 impact action(s)=+8, 4 IOC(s)=+10

> View CSAF Summary Hitachi Energy is aware of open-source software vulnerabilities that affect REB500 product versions listed in this document. These vulnerabilities can be exploited to carry out Denial of Service (DoS) attack on the product. Please refer to the Recommended Immediate Actions for information about the mitigation/remediation. The following versions of Hitachi Energy REB500 are affected: REB500 vers:REB500/ CVSS Vendor Equipment v3 6.5 Hitachi Energy REB500 2 Vulnerabilities Uncontrolled Recursion, Allocation of Resources Without Limits or Throttling Background Critical Infrastructure Sectors: Energy Countries/Areas Deployed: Worldwide Company Headquarters Location: Switzerland Vulnerabilities Expand All + CVE-2024-8176 A stack overflow vulnerability exists in the libexpat library used by the IEC61850 functionality supported by REB500 product. An authenticated malicious user with local access could use a crafted IEC 61850 message to exploit the vulnerability in the libexpat library. This issue could lead to denial of service (DoS) or, in some cases, exploitable memory corruption, depending on the environment and library usage. Read More 1 Affected Product REB500 versions 8.3.3.1 and prior Product Status: known_affected Remediations Vendor fix Update to version 8.3.4.0 Additional Metrics Relevant CWE: CWE-674 Uncontrolled Recursion CVSS Version Base Score Base Severity Vector String 3.1 6.5 MEDIUM CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H View CVE Details CVE-2

**Extracted signals**
- CVEs: CVE-2024-8176, CVE-2025-59375
- Vectors: exploit, vpn-edge
- Actions: ddos
- Sectors: energy, manufacturing
- IP IOCs: 8.3.3.1, 8.3.4.0
- Domain IOCs: www.hitachienergy.com, www.cisa.gov

### Hypotheses (3)

#### H-5ae1f6b6-1 · Initial access via CVE-2024-8176 affecting the affected product/service  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2024-8176 in the affected product/service within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2024-8176, CVE-2025-59375; vectors: exploit, vpn-edge; impact: ddos.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-5ae1f6b6-1-O1] Inventory exposure to the affected product** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of the affected product, the external-exploitation hypothesis is disproven for CVE-2024-8176.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'the affected product' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-5ae1f6b6-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2024-8176 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2024-8176/ | summarize count() by src_ip, dst_host`
- **[H-5ae1f6b6-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2024-8176 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2024-8176')) | summarize coverage = avg(installed) by host_role`
- **[H-5ae1f6b6-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on the affected product hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-5ae1f6b6-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-5ae1f6b6-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2024-8176, CVE-2025-59375; vectors: exploit, vpn-edge; impact: ddos.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-5ae1f6b6-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('www.hitachienergy.com','www.cisa.gov') | summarize count() by client_ip`
- **[H-5ae1f6b6-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('8.3.3.1','8.3.4.0') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-5ae1f6b6-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-5ae1f6b6-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-5ae1f6b6-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-5ae1f6b6-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2024-8176, CVE-2025-59375; vectors: exploit, vpn-edge; impact: ddos.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-5ae1f6b6-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-5ae1f6b6-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-5ae1f6b6-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-5ae1f6b6-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 21. Hitachi Energy SOI

- **Source**: CISA Advisories
- **Link**: <https://www.cisa.gov/news-events/ics-advisories/icsa-26-279-04>
- **Published**: Tue, 06 Oct 26 12:00:00 +0000
- **First seen**: 2026-10-06T16:35:14+00:00
- **Relevance score**: 66
- **Score rationale**: source weight (advisory)=+15, 1 CVE(s)=+20, 2 initial-access vector(s)=+9, 1 impact action(s)=+8, 6 IOC(s)=+14

> View CSAF Summary Hitachi Energy is aware of RCE (Remote Code Execution) vulnerability in Apache ActiveMQ component of SOI product versions listed in this document. These vulnerabilities can be exploited to carry out various attacks affecting confidentiality, integrity, and availability of the product. Please refer to the Recommended Immediate Actions for information about the mitigation/remediation. The following versions of Hitachi Energy SOI are affected: SOI vers:SOI/>=2.0.0| CVSS Vendor Equipment v3 8.8 Hitachi Energy SOI 1 Vulnerability Improper Control of Generation of Code ('Code Injection') Background Critical Infrastructure Sectors: Energy Countries/Areas Deployed: Worldwide Company Headquarters Location: Switzerland Vulnerabilities CVE-2026-34197 Improper Input Validation, Improper Control of Generation of Code ('Code Injection') vulnerability in Apache ActiveMQ Broker, Apache ActiveMQ used in SOI product. Apache ActiveMQ Classic exposes the Jolokia JMX-HTTP bridge at /api/jolokia/ on the web console. The default Jolokia access policy permits exec operations on all ActiveMQ MBeans (org.apache.activemq:*), including BrokerService.addNetworkConnector(String) and BrokerService.addConnector(String). An authenticated attacker can invoke these operations with a crafted discovery URI that triggers the VM transport's brokerConfig parameter to load a remote Spring XML application context using ResourceXmlApplicationContext. Because Spring's ResourceXmlApplicationContext ins

**Extracted signals**
- CVEs: CVE-2026-34197
- Vectors: exploit, vpn-edge
- Actions: fraud
- Sectors: energy, manufacturing
- Domain IOCs: org.apache.activemq, brokerservice.addnetworkconnector, brokerservice.addconnector, runtime.exec, www.hitachienergy.com, www.cisa.gov

### Hypotheses (3)

#### H-be449ac6-1 · Initial access via CVE-2026-34197 affecting the affected product/service  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2026-34197 in the affected product/service within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2026-34197; vectors: exploit, vpn-edge; impact: fraud.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-be449ac6-1-O1] Inventory exposure to the affected product** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of the affected product, the external-exploitation hypothesis is disproven for CVE-2026-34197.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'the affected product' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-be449ac6-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2026-34197 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2026-34197/ | summarize count() by src_ip, dst_host`
- **[H-be449ac6-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2026-34197 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2026-34197')) | summarize coverage = avg(installed) by host_role`
- **[H-be449ac6-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on the affected product hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-be449ac6-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-be449ac6-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2026-34197; vectors: exploit, vpn-edge; impact: fraud.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-be449ac6-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('org.apache.activemq','brokerservice.addnetworkconnector','brokerservice.addconnector') | summarize count() by client_ip`
- **[H-be449ac6-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-be449ac6-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-be449ac6-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-be449ac6-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-be449ac6-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2026-34197; vectors: exploit, vpn-edge; impact: fraud.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-be449ac6-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-be449ac6-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-be449ac6-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-be449ac6-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 22. Patch Tuesday - October 2026

- **Source**: Rapid7
- **Link**: <https://www.rapid7.com/blog/post/em-patch-tuesday-october-2026>
- **Published**: Tue, 13 Oct 2026 21:40:27 GMT
- **First seen**: 2026-10-13T22:50:12+00:00
- **Relevance score**: 64
- **Score rationale**: source weight (vendor)=+10, 8 CVE(s)=+30, 1 initial-access vector(s)=+7, 1 impact action(s)=+8, 1 product mention(s)=+3, 2 IOC(s)=+6

> Microsoft is publishing 1,413 own-product vulnerabilities on October 2026 Patch Tuesday , including 1,102 vulnerabilities in Windows. Anyone who enjoyed last month’s record-setting Patch Tuesday will love the October 2026 edition, because it’s much bigger still. As Rapid7 has noted over the course of 2026, there is every reason to suppose that vulnerability volumes will continue to rise. Microsoft is aware of exploitation in the wild for just one of the vulnerabilities published today, as well as public disclosure for two others. Windows Shell: zero-day security feature bypass The Windows Shell is Microsoft’s term for the GUI interaction logic for the entire OS provided by explorer.exe and associated libraries and APIs, and for the second time this year , the Windows Shell is the site of an exploited-in-the-wild zero-day vulnerability. Today’s specimen is CVE-2026-96951 . Once again, the immediate prize for an attacker is a Mark of the Web (MOTW) bypass. What this means is that Windows won’t provide the user with a dialog explaining that Windows protected their PC, because in this case, it didn’t. Exploitation requires that a user opens a specially crafted malicious file or visits an attacker-controlled site, so the evergreen advice about being careful what you click remains valid. Fans of vintage operating systems should note that Windows Server 2012 doesn’t receive a patch, although Server 2012 R2 does. The advisory acknowledges reporters from multiple organizations, althou

**Extracted signals**
- CVEs: CVE-2026-96951, CVE-2026-108398, CVE-2026-70242, CVE-2026-97749, CVE-2026-97016, CVE-2026-88156, CVE-2026-70291, CVE-2023-23397
- Products: Microsoft Exchange
- Vectors: exploit
- Actions: fraud
- Sectors: manufacturing, telecom
- Domain IOCs: explorer.exe, outlook.com

### Hypotheses (3)

#### H-516d995a-1 · Initial access via CVE-2026-96951 affecting Microsoft Exchange  _(confidence: high)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2026-96951 in Microsoft Exchange within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2026-96951, CVE-2026-108398, CVE-2026-70242; vectors: exploit; impact: fraud; products: Microsoft Exchange.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-516d995a-1-O1] Inventory exposure to Microsoft Exchange** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of Microsoft Exchange, the external-exploitation hypothesis is disproven for CVE-2026-96951.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'Microsoft Exchange' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-516d995a-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2026-96951 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2026-96951/ | summarize count() by src_ip, dst_host`
- **[H-516d995a-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2026-96951 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2026-96951')) | summarize coverage = avg(installed) by host_role`
- **[H-516d995a-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on Microsoft Exchange hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-516d995a-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-516d995a-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2026-96951, CVE-2026-108398, CVE-2026-70242; vectors: exploit; impact: fraud; products: Microsoft Exchange.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-516d995a-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('explorer.exe','outlook.com') | summarize count() by client_ip`
- **[H-516d995a-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-516d995a-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-516d995a-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-516d995a-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-516d995a-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2026-96951, CVE-2026-108398, CVE-2026-70242; vectors: exploit; impact: fraud; products: Microsoft Exchange.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-516d995a-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-516d995a-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-516d995a-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-516d995a-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 23. CISA Urges Patching Newly Exploited Vulnerability in Ivanti Connect Secure

- **Source**: CISA Advisories
- **Link**: <https://www.cisa.gov/news-events/alerts/2026/10/13/cisa-urges-patching-newly-exploited-vulnerability-ivanti-connect-secure>
- **Published**: Tue, 13 Oct 26 12:00:00 +0000
- **First seen**: 2026-10-13T22:09:51+00:00
- **Relevance score**: 63
- **Score rationale**: source weight (advisory)=+15, 1 CVE(s)=+20, 3 initial-access vector(s)=+11, 1 impact action(s)=+8, 1 product mention(s)=+3, 2 IOC(s)=+6

> CISA is aware of Ivanti’s disclosure of a newly exploited vulnerability, CVE-2026-104935 , affecting Ivanti Connect Secure versions 25.1.1.1 and prior, 25.1.2.2 and prior, and 22.8R2.4 and prior. CISA is aware of cyber threat actors exploiting this zero-day authentication bypass vulnerability, which allows remote, unauthenticated execution of arbitrary commands, to conduct credential theft and data exfiltration. CISA added CVE-2026-104935 to its Known Exploited Vulnerabilities (KEV) Catalog on Oct. 13, 2026. CISA urges organizations with affected Ivanti Connect Secure appliances and deployments to immediately update to the latest version, as outlined in Ivanti’s Security Advisory Ivanti Connect Secure (CVE-2026-104935) . Organizations should also review the Ivanti Connect Secure 25.x Upgrade and Migration Compatibility Guide for detailed patching guidance for hardware and virtual appliance deployments. Ivanti Connect Secure version 22.8 reaches end of life on Jan. 31, 2027. Organizations seeking to determine whether they were compromised will need to conduct network and memory forensics to identify evidence of exploitation. Note: Ivanti’s Integrity Checker Tool may not detect evidence of exploitation of CVE-2026-104935 because threat actor commands execute in memory. If your organization suspects a compromise, CISA recommends implementing the following actions from Ivanti Connect Secure Recovery Procedures : Create a backup of the appliance configuration. Review Ivanti’s How 

**Extracted signals**
- CVEs: CVE-2026-104935
- Products: Ivanti Connect Secure
- Vectors: exploit, vpn-edge, credential-theft
- Actions: fraud
- Sectors: manufacturing
- IP IOCs: 25.1.1.1, 25.1.2.2

### Hypotheses (3)

#### H-d0f754be-1 · Initial access via CVE-2026-104935 affecting Ivanti Connect Secure  _(confidence: high)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2026-104935 in Ivanti Connect Secure within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2026-104935; vectors: exploit, vpn-edge, credential-theft; impact: fraud; products: Ivanti Connect Secure.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-d0f754be-1-O1] Inventory exposure to Ivanti Connect Secure** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of Ivanti Connect Secure, the external-exploitation hypothesis is disproven for CVE-2026-104935.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'Ivanti Connect Secure' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-d0f754be-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2026-104935 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2026-104935/ | summarize count() by src_ip, dst_host`
- **[H-d0f754be-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2026-104935 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2026-104935')) | summarize coverage = avg(installed) by host_role`
- **[H-d0f754be-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on Ivanti Connect Secure hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-d0f754be-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-d0f754be-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2026-104935; vectors: exploit, vpn-edge, credential-theft; impact: fraud; products: Ivanti Connect Secure.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-d0f754be-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('the published C2 domains') | summarize count() by client_ip`
- **[H-d0f754be-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('25.1.1.1','25.1.2.2') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-d0f754be-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-d0f754be-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-d0f754be-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-d0f754be-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2026-104935; vectors: exploit, vpn-edge, credential-theft; impact: fraud; products: Ivanti Connect Secure.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-d0f754be-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-d0f754be-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-d0f754be-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-d0f754be-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 24. Eclipse Foundation Eclipse Milo

- **Source**: CISA Advisories
- **Link**: <https://www.cisa.gov/news-events/ics-advisories/icsa-26-288-01>
- **Published**: Thu, 15 Oct 26 12:00:00 +0000
- **First seen**: 2026-10-15T17:01:00+00:00
- **Relevance score**: 62
- **Score rationale**: source weight (advisory)=+15, 6 CVE(s)=+30, 3 initial-access vector(s)=+11, 2 IOC(s)=+6

> View CSAF Summary Successful exploitation of these vulnerabilities could allow an attacker to delete protected data, recover user credentials and impersonate legitimate users, or cause the server to stop responding to all clients. The following versions of Eclipse Foundation Eclipse Milo are affected: Eclipse Milo >=0.6.0| Eclipse Milo >=1.0.0| CVSS Vendor Equipment v3 8.2 Eclipse Foundation Eclipse Milo 5 Vulnerabilities Incorrect Authorization, Missing Release of Memory after Effective Lifetime, Missing Authorization, Observable Response Discrepancy, Missing Release of Resource after Effective Lifetime Background Critical Infrastructure Sectors: Chemical, Critical Manufacturing, Energy, Water and Wastewater Countries/Areas Deployed: Worldwide Company Headquarters Location: Belgium Vulnerabilities Expand All + CVE-2026-62927 In Eclipse Milo versions 1.0.0 through 1.1.4, the Call service dispatches the original mixed batch to address-space handlers after calculating authorization, allowing an anonymous or otherwise low-privileged client to execute a denied method by batching it with an allowed method. Read More 1 Affected Product Eclipse Foundation Eclipse Milo: >=1.0.0| Product Status: known_affected Remediations Vendor fix The Eclipse Foundation recommends users upgrade to Eclipse Milo 1.1.5 https://github.com/eclipse-milo/milo/releases/tag/v1.1.5. Mitigation For users on Milo 0.6.x, there are no 0.6.x releases with the fixes, which requires users to migrate to Milo 1.1.5 o

**Extracted signals**
- CVEs: CVE-2026-62927, CVE-2026-63252, CVE-2026-58080, CVE-2026-63248, CVE-2026-60007, CVE-2026-61387
- Vectors: phishing, exploit, vpn-edge
- Sectors: energy, manufacturing, telecom
- Domain IOCs: opcuaserverconfig.copy, www.cisa.gov

### Hypotheses (3)

#### H-53d267ac-1 · Initial access via CVE-2026-62927 affecting the affected product/service  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2026-62927 in the affected product/service within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2026-62927, CVE-2026-63252, CVE-2026-58080; vectors: phishing, exploit, vpn-edge.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-53d267ac-1-O1] Inventory exposure to the affected product** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of the affected product, the external-exploitation hypothesis is disproven for CVE-2026-62927.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'the affected product' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-53d267ac-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2026-62927 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2026-62927/ | summarize count() by src_ip, dst_host`
- **[H-53d267ac-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2026-62927 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2026-62927')) | summarize coverage = avg(installed) by host_role`
- **[H-53d267ac-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on the affected product hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-53d267ac-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-53d267ac-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2026-62927, CVE-2026-63252, CVE-2026-58080; vectors: phishing, exploit, vpn-edge.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-53d267ac-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('opcuaserverconfig.copy','www.cisa.gov') | summarize count() by client_ip`
- **[H-53d267ac-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-53d267ac-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-53d267ac-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-53d267ac-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-53d267ac-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2026-62927, CVE-2026-63252, CVE-2026-58080; vectors: phishing, exploit, vpn-edge.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-53d267ac-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-53d267ac-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-53d267ac-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-53d267ac-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 25. Thermo Fisher Torrent Suite Software

- **Source**: CISA Advisories
- **Link**: <https://www.cisa.gov/news-events/ics-medical-advisories/icsma-26-288-01>
- **Published**: Thu, 15 Oct 26 12:00:00 +0000
- **First seen**: 2026-10-15T17:01:00+00:00
- **Relevance score**: 60
- **Score rationale**: source weight (advisory)=+15, 1 CVE(s)=+20, 1 MITRE technique hit(s)=+8, 4 initial-access vector(s)=+13, 1 IOC(s)=+4

> View CSAF Summary Successful exploitation of this vulnerability could allow an attacker to read arbitrary files on the Torrent Server. The following versions of Thermo Fisher Torrent Suite Software are affected: Torrent Suite Software CVSS Vendor Equipment v3 6.5 Thermo Fisher Torrent Suite Software 1 Vulnerability Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') Background Critical Infrastructure Sectors: Healthcare and Public Health Countries/Areas Deployed: Worldwide Company Headquarters Location: United States Vulnerabilities CVE-2026-107777 The affected product is vulnerable to a path traversal, which could allow an authenticated attacker to read arbitrary files on the Torrent Server that are accessible to the web service account. Read More 1 Affected Product Thermo Fisher Torrent Suite Software: Product Status: known_affected Remediations Vendor fix Thermo Fisher has fixed the vulnerability and recommends users update Torrent Suite Software to version 5.22 or later. Mitigation For more information, refer to Thermo Fisher's Security bulletin. Additional Metrics Relevant CWE: CWE-22 Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') CVSS Version Base Score Base Severity Vector String 3.1 6.5 MEDIUM CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N 4.0 7.1 HIGH CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N View CVE Details Acknowledgments Akanksha Raghvesh and Abhinav Agarwal reported this vulnerability

**Extracted signals**
- CVEs: CVE-2026-107777
- Vectors: phishing, exploit, vpn-edge, social-engineering
- Sectors: healthcare, manufacturing
- MITRE ATT&CK: T1566
- Domain IOCs: www.cisa.gov

### Hypotheses (3)

#### H-faea1ddd-1 · Initial access via CVE-2026-107777 affecting the affected product/service  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2026-107777 in the affected product/service within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2026-107777; vectors: phishing, exploit, vpn-edge.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-faea1ddd-1-O1] Inventory exposure to the affected product** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of the affected product, the external-exploitation hypothesis is disproven for CVE-2026-107777.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'the affected product' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-faea1ddd-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2026-107777 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2026-107777/ | summarize count() by src_ip, dst_host`
- **[H-faea1ddd-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2026-107777 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2026-107777')) | summarize coverage = avg(installed) by host_role`
- **[H-faea1ddd-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on the affected product hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-faea1ddd-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-faea1ddd-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2026-107777; vectors: phishing, exploit, vpn-edge.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-faea1ddd-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('www.cisa.gov') | summarize count() by client_ip`
- **[H-faea1ddd-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-faea1ddd-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-faea1ddd-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-faea1ddd-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-faea1ddd-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2026-107777; vectors: phishing, exploit, vpn-edge.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-faea1ddd-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-faea1ddd-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-faea1ddd-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-faea1ddd-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 26. Inductive Automation Ignition Software

- **Source**: CISA Advisories
- **Link**: <https://www.cisa.gov/news-events/ics-advisories/icsa-26-286-01>
- **Published**: Tue, 13 Oct 26 12:00:00 +0000
- **First seen**: 2026-10-14T00:09:50+00:00
- **Relevance score**: 60
- **Score rationale**: source weight (advisory)=+15, 1 CVE(s)=+20, 1 MITRE technique hit(s)=+8, 4 initial-access vector(s)=+13, 1 IOC(s)=+4

> View CSAF Summary Successful exploitation of this vulnerability could allow an authenticated low-level user to escalate their privileges to a higher level. The following versions of Inductive Automation Ignition Software are affected: Ignition >=8.1.0| Ignition >=8.3.0| CVSS Vendor Equipment v3 8.8 Inductive Automation Ignition 1 Vulnerability Incorrect Authorization Background Critical Infrastructure Sectors: Critical Manufacturing, Energy, Information Technology Countries/Areas Deployed: Worldwide Company Headquarters Location: United States Vulnerabilities CVE-2026-92817 The Ignition Perspective module does not properly validate session privileges when determining Designer-level access. An authenticated user with access to a Vision project could provide their valid Vision session identifier and gain Designer-level privileges. An attacker could exploit these elevated privileges to execute arbitrary code in the context of the Ignition Gateway process. Read More 2 Affected Products Inductive Automation Ignition: >=8.1.0| Product Status: known_affected Remediations Mitigation Inductive Automation released version 8.3.9 in August 2025 and version 8.1.55 in September 2026 to address this issue. Users are recommended to update to the newest version available. Mitigation For more information, see the publication at the Inductive Automation Trust Center. Inductive Automation Ignition: >=8.3.0| Product Status: known_affected Remediations Mitigation Inductive Automation released vers

**Extracted signals**
- CVEs: CVE-2026-92817
- Vectors: phishing, exploit, vpn-edge, social-engineering
- Sectors: energy, manufacturing
- MITRE ATT&CK: T1566
- Domain IOCs: www.cisa.gov

### Hypotheses (3)

#### H-ecf019df-1 · Initial access via CVE-2026-92817 affecting the affected product/service  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2026-92817 in the affected product/service within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2026-92817; vectors: phishing, exploit, vpn-edge.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-ecf019df-1-O1] Inventory exposure to the affected product** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of the affected product, the external-exploitation hypothesis is disproven for CVE-2026-92817.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'the affected product' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-ecf019df-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2026-92817 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2026-92817/ | summarize count() by src_ip, dst_host`
- **[H-ecf019df-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2026-92817 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2026-92817')) | summarize coverage = avg(installed) by host_role`
- **[H-ecf019df-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on the affected product hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-ecf019df-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-ecf019df-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2026-92817; vectors: phishing, exploit, vpn-edge.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-ecf019df-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('www.cisa.gov') | summarize count() by client_ip`
- **[H-ecf019df-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-ecf019df-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-ecf019df-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-ecf019df-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-ecf019df-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2026-92817; vectors: phishing, exploit, vpn-edge.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-ecf019df-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-ecf019df-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-ecf019df-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-ecf019df-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 27. Scans for Atlassian vulnerablity (CVE-2026-21589), (Wed, Oct 7th)

- **Source**: SANS Internet Storm Center
- **Link**: <https://isc.sans.edu/diary/rss/33406>
- **Published**: Wed, 07 Oct 2026 14:59:33 GMT
- **First seen**: 2026-10-07T15:33:28+00:00
- **Relevance score**: 60
- **Score rationale**: source weight (advisory)=+15, 1 CVE(s)=+20, 1 initial-access vector(s)=+7, 1 product mention(s)=+3, 20 IOC(s)=+15

> On October 5th, Atlassian published patches&#;x26;#;xc2;&#;x26;#;xa0;for multiple products to fix an "Arbitrary File Access" vulnerability &#;x26;#;x5b; CVE-2026-21589 &#;x26;#;x5d;. An attacker can read arbitrary files in the web application&#;x26;#;39;s directory, potentially exposing sensitive information such as configuration files.

**Extracted signals**
- CVEs: CVE-2026-21589
- Products: Atlassian Confluence
- Vectors: exploit
- Sectors: manufacturing
- IP IOCs: 134.199.229.190, 134.199.230.82, 137.184.112.247, 137.184.33.84, 143.198.103.58, 143.198.132.93, 146.190.169.1, 146.190.172.250, 159.223.199.218, 164.92.68.152, 209.38.147.216, 24.199.101.184, 64.23.172.129
- Domain IOCs: jira.webresources, web.xml, com.atlassian.bitbucket.server.bitbucket, urlrewrite.xml, com.atlassian.confluence.plugins.dashboard, sans.edu, isc.sans.edu

### Hypotheses (3)

#### H-db2077a2-1 · Initial access via CVE-2026-21589 affecting Atlassian Confluence  _(confidence: high)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2026-21589 in Atlassian Confluence within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2026-21589; vectors: exploit; products: Atlassian Confluence.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-db2077a2-1-O1] Inventory exposure to Atlassian Confluence** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of Atlassian Confluence, the external-exploitation hypothesis is disproven for CVE-2026-21589.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'Atlassian Confluence' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-db2077a2-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2026-21589 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2026-21589/ | summarize count() by src_ip, dst_host`
- **[H-db2077a2-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2026-21589 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2026-21589')) | summarize coverage = avg(installed) by host_role`
- **[H-db2077a2-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on Atlassian Confluence hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-db2077a2-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-db2077a2-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2026-21589; vectors: exploit; products: Atlassian Confluence.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-db2077a2-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('jira.webresources','web.xml','com.atlassian.bitbucket.server.bitbucket') | summarize count() by client_ip`
- **[H-db2077a2-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('134.199.229.190','134.199.230.82','137.184.112.247') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-db2077a2-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-db2077a2-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-db2077a2-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-db2077a2-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2026-21589; vectors: exploit; products: Atlassian Confluence.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-db2077a2-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-db2077a2-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-db2077a2-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-db2077a2-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 28. Hitachi Energy RTU500

- **Source**: CISA Advisories
- **Link**: <https://www.cisa.gov/news-events/ics-advisories/icsa-26-279-06>
- **Published**: Tue, 06 Oct 26 12:00:00 +0000
- **First seen**: 2026-10-06T16:35:14+00:00
- **Relevance score**: 60
- **Score rationale**: source weight (advisory)=+15, 6 CVE(s)=+30, 2 initial-access vector(s)=+9, 2 IOC(s)=+6

> View CSAF Summary Hitachi Energy is publishing this cybersecurity advisory in response to the security findings reported by Dragos affecting end-of-life RTU500 CMU firmware version 9.x. The reported findings are associated with legacy RTU500 firmware versions that were developed according to the cybersecurity requirements, threat landscape, and industry practices that existed at the time of their release. As cybersecurity threats and security expectations have evolved, these end-of-life versions no longer incorporate many of the security controls and hardening measures that are standard in modern industrial control systems. Over successive RTU500 releases, Hitachi Energy has continuously enhanced the security of the product through the introduction of additional security features, protocol hardening, stronger authentication and access controls, encrypted communications, and other security-by-design improvements. While the findings reported by Dragos do not affect currently supported RTU500 CMU firmware versions, there is a likelihood that the end-of-life versions 11.x and prior are affected by these vulnerabilities. Since the end-of-life versions are no longer maintained with security updates, Hitachi Energy strongly recommends upgrading to a currently supported RTU500 firmware version. Customers should also implement appropriate defense-in-depth measures and cybersecurity best practices to reduce risk and strengthen the security posture of their operational environments. Ple

**Extracted signals**
- CVEs: CVE-2026-8065, CVE-2026-8066, CVE-2026-8067, CVE-2010-2965, CVE-2014-9195, CVE-2023-46143
- Vectors: exploit, vpn-edge
- Sectors: energy, manufacturing
- Domain IOCs: www.hitachienergy.com, www.cisa.gov

### Hypotheses (3)

#### H-d4c94bfe-1 · Initial access via CVE-2026-8065 affecting the affected product/service  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2026-8065 in the affected product/service within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2026-8065, CVE-2026-8066, CVE-2026-8067; vectors: exploit, vpn-edge.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-d4c94bfe-1-O1] Inventory exposure to the affected product** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of the affected product, the external-exploitation hypothesis is disproven for CVE-2026-8065.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'the affected product' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-d4c94bfe-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2026-8065 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2026-8065/ | summarize count() by src_ip, dst_host`
- **[H-d4c94bfe-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2026-8065 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2026-8065')) | summarize coverage = avg(installed) by host_role`
- **[H-d4c94bfe-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on the affected product hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-d4c94bfe-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-d4c94bfe-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2026-8065, CVE-2026-8066, CVE-2026-8067; vectors: exploit, vpn-edge.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-d4c94bfe-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('www.hitachienergy.com','www.cisa.gov') | summarize count() by client_ip`
- **[H-d4c94bfe-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-d4c94bfe-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-d4c94bfe-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-d4c94bfe-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-d4c94bfe-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2026-8065, CVE-2026-8066, CVE-2026-8067; vectors: exploit, vpn-edge.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-d4c94bfe-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-d4c94bfe-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-d4c94bfe-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-d4c94bfe-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 29. Microsoft, Adobe, Apple, and Foxit vulnerabilities

- **Source**: Cisco Talos
- **Link**: <https://blog.talosintelligence.com/microsoft-adobe-apple-and-foxit-vulnerabilities/>
- **Published**: Wed, 07 Oct 2026 19:27:08 GMT
- **First seen**: 2026-10-07T19:29:47+00:00
- **Relevance score**: 59
- **Score rationale**: source weight (vendor)=+10, 7 CVE(s)=+30, 1 initial-access vector(s)=+7, 5 IOC(s)=+12

> Cisco Talos’ Vulnerability Discovery & Research team recently disclosed vulnerabilities in Adobe, Apple, Foxit Reader, and Microsoft. The vulnerabilities mentioned in this blog post have been patched by their respective vendors, in adherence to Cisco’s third-party vulnerability disclosure policy . For Snort coverage that can detect

**Extracted signals**
- CVEs: CVE-2026-48388, CVE-2026-57256, CVE-2026-91799, CVE-2026-50475, CVE-2026-58613, CVE-2026-80093, CVE-2026-49177
- Vectors: exploit
- Sectors: manufacturing
- IP IOCs: 2.11.0.30
- Domain IOCs: snort.org, up.exe, netio.sys, tcpip.sys

### Hypotheses (3)

#### H-4088cc11-1 · Initial access via CVE-2026-48388 affecting the affected product/service  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2026-48388 in the affected product/service within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2026-48388, CVE-2026-57256, CVE-2026-91799; vectors: exploit.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-4088cc11-1-O1] Inventory exposure to the affected product** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of the affected product, the external-exploitation hypothesis is disproven for CVE-2026-48388.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'the affected product' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-4088cc11-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2026-48388 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2026-48388/ | summarize count() by src_ip, dst_host`
- **[H-4088cc11-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2026-48388 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2026-48388')) | summarize coverage = avg(installed) by host_role`
- **[H-4088cc11-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on the affected product hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-4088cc11-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-4088cc11-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2026-48388, CVE-2026-57256, CVE-2026-91799; vectors: exploit.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-4088cc11-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('snort.org','up.exe','netio.sys') | summarize count() by client_ip`
- **[H-4088cc11-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('2.11.0.30') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-4088cc11-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-4088cc11-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-4088cc11-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-4088cc11-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2026-48388, CVE-2026-57256, CVE-2026-91799; vectors: exploit.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-4088cc11-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-4088cc11-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-4088cc11-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-4088cc11-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 30. CISA Adds Four Known Exploited Vulnerabilities to Catalog

- **Source**: CISA Advisories
- **Link**: <https://www.cisa.gov/news-events/alerts/2026/10/14/cisa-adds-four-known-exploited-vulnerabilities-catalog>
- **Published**: Wed, 14 Oct 26 12:00:00 +0000
- **First seen**: 2026-10-14T20:57:13+00:00
- **Relevance score**: 57
- **Score rationale**: source weight (advisory)=+15, 4 CVE(s)=+30, 2 initial-access vector(s)=+9, 1 product mention(s)=+3

> CISA has added four new vulnerabilities to its Known Exploited Vulnerabilities (KEV) Catalog , based on evidence of active exploitation. CVE-2026-0322 Palo Alto Networks PAN-OS Code Injection Vulnerability CVE-2026-76519 Cisco Secure Email Gateway Relative Path Traversal Vulnerability CVE-2026-105133 Ahsay AhsayCBS Improper Authentication Vulnerability CVE-2026-105134 Ahsay AhsayCBS Command Injection Vulnerability These types of vulnerabilities are a frequent attack vector for malicious cyber actors and pose significant risks to the federal enterprise. Binding Operational Directive (BOD) 26-04: Prioritizing Security Updates Based on Risk establishes vulnerability management requirements for Federal Civilian Executive Branch (FCEB) agencies. BOD 26-04 reinforces the importance of the KEV Catalog and requires federal agencies to prioritize rapid remediation of high-risk vulnerabilities, specifically those identified by Common Vulnerabilities and Exposures (CVEs) listed in CISA’s KEV Catalog on publicly exposed assets that grant total control of the asset post-exploitation, while deferring action for lower-risk vulnerabilities. BOD 26-04 further establishes basic expectations for when agencies must check whether threat actors compromised the system before the patch was applied. While BOD 26-04 applies only to FCEB agencies, CISA encourages all organizations to adopt risk-based vulnerability management and prioritize remediation of KEV Catalog vulnerabilities . CISA will continue

**Extracted signals**
- CVEs: CVE-2026-0322, CVE-2026-76519, CVE-2026-105133, CVE-2026-105134
- Products: Palo Alto GlobalProtect
- Vectors: exploit, vpn-edge
- Sectors: government, manufacturing

### Hypotheses (3)

#### H-2c4da70b-1 · Initial access via CVE-2026-0322 affecting Palo Alto GlobalProtect  _(confidence: high)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2026-0322 in Palo Alto GlobalProtect within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2026-0322, CVE-2026-76519, CVE-2026-105133; vectors: exploit, vpn-edge; products: Palo Alto GlobalProtect.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-2c4da70b-1-O1] Inventory exposure to Palo Alto GlobalProtect** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of Palo Alto GlobalProtect, the external-exploitation hypothesis is disproven for CVE-2026-0322.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'Palo Alto GlobalProtect' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-2c4da70b-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2026-0322 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2026-0322/ | summarize count() by src_ip, dst_host`
- **[H-2c4da70b-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2026-0322 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2026-0322')) | summarize coverage = avg(installed) by host_role`
- **[H-2c4da70b-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on Palo Alto GlobalProtect hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-2c4da70b-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-2c4da70b-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: medium)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2026-0322, CVE-2026-76519, CVE-2026-105133; vectors: exploit, vpn-edge; products: Palo Alto GlobalProtect.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-2c4da70b-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('the published C2 domains') | summarize count() by client_ip`
- **[H-2c4da70b-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-2c4da70b-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-2c4da70b-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-2c4da70b-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-2c4da70b-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2026-0322, CVE-2026-76519, CVE-2026-105133; vectors: exploit, vpn-edge; products: Palo Alto GlobalProtect.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-2c4da70b-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-2c4da70b-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-2c4da70b-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-2c4da70b-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 31. Panchan's Mining Island [Guest Diary], (Wed, Oct 14th)

- **Source**: SANS Internet Storm Center
- **Link**: <https://isc.sans.edu/diary/rss/33426>
- **Published**: Thu, 15 Oct 2026 01:10:57 GMT
- **First seen**: 2026-10-15T01:35:08+00:00
- **Relevance score**: 56
- **Score rationale**: source weight (advisory)=+15, 1 MITRE technique hit(s)=+8, 1 initial-access vector(s)=+7, 2 impact action(s)=+11, 7 IOC(s)=+15

> [This is a Guest Diary by Zachary Norwood, an ISC intern as part of the SANS.edu BACS program]

**Extracted signals**
- Vectors: exploit
- Actions: cryptomining, fraud
- Sectors: manufacturing
- MITRE ATT&CK: T1110
- Domain IOCs: sans.edu, www.akamai.com, attack.mitre.org, developer.hashicorp.com, www.hashicorp.com, www.sans.edu, isc.sans.edu

### Hypotheses (3)

#### H-a7a13664-1 · Initial access via the disclosed vulnerability affecting the affected product/service  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting the disclosed vulnerability in the affected product/service within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on vectors: exploit; impact: cryptomining, fraud.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-a7a13664-1-O1] Inventory exposure to the affected product** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of the affected product, the external-exploitation hypothesis is disproven for the referenced CVE.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'the affected product' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-a7a13664-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for the referenced CVE in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-the referenced CVE/ | summarize count() by src_ip, dst_host`
- **[H-a7a13664-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the the referenced CVE fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('the referenced CVE')) | summarize coverage = avg(installed) by host_role`
- **[H-a7a13664-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on the affected product hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-a7a13664-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-a7a13664-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on vectors: exploit; impact: cryptomining, fraud.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-a7a13664-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('sans.edu','www.akamai.com','attack.mitre.org') | summarize count() by client_ip`
- **[H-a7a13664-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-a7a13664-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-a7a13664-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-a7a13664-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-a7a13664-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on vectors: exploit; impact: cryptomining, fraud.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-a7a13664-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-a7a13664-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-a7a13664-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-a7a13664-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 32. Hitachi Energy Asset Suite

- **Source**: CISA Advisories
- **Link**: <https://www.cisa.gov/news-events/ics-advisories/icsa-26-279-03>
- **Published**: Tue, 06 Oct 26 12:00:00 +0000
- **First seen**: 2026-10-06T16:35:14+00:00
- **Relevance score**: 55
- **Score rationale**: source weight (advisory)=+15, 2 CVE(s)=+25, 2 initial-access vector(s)=+9, 2 IOC(s)=+6

> View CSAF Summary Hitachi Energy is aware of unauthenticated servlet access vulnerabilities that affect Asset Suite product versions listed in this document. These vulnerabilities can be exploited to potentially cause confidentiality, integrity and availability impact on the product. Please refer to the Recommended Immediate Actions for information about the mitigation/remediation. The following versions of Hitachi Energy Asset Suite are affected: Asset Suite vers:Asset_Suite/ CVSS Vendor Equipment v3 8.1 Hitachi Energy Asset Suite 1 Vulnerability Missing Authentication for Critical Function Background Critical Infrastructure Sectors: Energy Countries/Areas Deployed: Worldwide Company Headquarters Location: Switzerland Vulnerabilities Expand All + CVE-2026-7395 Asset Suite allows unauthenticated users to access HTTPPublishAdapterTestServlet that can be used for configuration file upload, leading to information disclosure and integrity compromise. The HTTPPublishAdapterTestServlet is specifically meant for testing purposes to be used in a non-production environment. Read More 1 Affected Product Asset Suite versions 9.9.0 and prior Product Status: known_affected Remediations Vendor fix Update or upgrade to Asset Suite 9.9.1 when available Mitigation Disable the affected servlet [2] [3] [2] HTTPPublishAdapterTestServlet is meant for testing purposes used in non-production environment [3] Functionality of the servlets, PropertiesReloadServlet, CacheFlushServlet, MetadataCacheFlus

**Extracted signals**
- CVEs: CVE-2026-7395, CVE-2026-11796
- Vectors: exploit, vpn-edge
- Sectors: energy, manufacturing
- Domain IOCs: www.hitachienergy.com, www.cisa.gov

### Hypotheses (3)

#### H-dc911b70-1 · Initial access via CVE-2026-7395 affecting the affected product/service  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2026-7395 in the affected product/service within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2026-7395, CVE-2026-11796; vectors: exploit, vpn-edge.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-dc911b70-1-O1] Inventory exposure to the affected product** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of the affected product, the external-exploitation hypothesis is disproven for CVE-2026-7395.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'the affected product' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-dc911b70-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2026-7395 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2026-7395/ | summarize count() by src_ip, dst_host`
- **[H-dc911b70-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2026-7395 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2026-7395')) | summarize coverage = avg(installed) by host_role`
- **[H-dc911b70-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on the affected product hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-dc911b70-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-dc911b70-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2026-7395, CVE-2026-11796; vectors: exploit, vpn-edge.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-dc911b70-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('www.hitachienergy.com','www.cisa.gov') | summarize count() by client_ip`
- **[H-dc911b70-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-dc911b70-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-dc911b70-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-dc911b70-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-dc911b70-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2026-7395, CVE-2026-11796; vectors: exploit, vpn-edge.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-dc911b70-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-dc911b70-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-dc911b70-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-dc911b70-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 33. Ivanti Connect Secure zero-day exploited in the wild (CVE-2026-104935)

- **Source**: Rapid7
- **Link**: <https://www.rapid7.com/blog/post/etr-ivanti-connect-secure-zero-day-exploited-in-the-wild-cve-2026-104935>
- **Published**: Tue, 13 Oct 2026 17:06:05 GMT
- **First seen**: 2026-10-13T17:27:47+00:00
- **Relevance score**: 54
- **Score rationale**: source weight (vendor)=+10, 1 CVE(s)=+20, 2 initial-access vector(s)=+9, 1 product mention(s)=+3, 5 IOC(s)=+12

> Overview On October 13, 2026, Ivanti published a security advisory for CVE-2026-104935 , a high-severity authentication bypass by spoofing ( CWE-290 ) affecting Ivanti Connect Secure (ICS). The vulnerability has a CVSSv3.0 score of 8.6 and allows a remote, unauthenticated attacker to execute arbitrary commands. Ivanti reports that exploitation in the wild has already occurred prior to disclosure, affecting a limited number of customers. This indicates that exploitation has been occurring as a zero-day vulnerability. The U.S. Cybersecurity and Infrastructure Security Agency (CISA) confirms exploitation in the wild, and added CVE-2026-104935 to its Known Exploited Vulnerabilities (KEV) catalog on the same day as the vendor's public disclosure. The digital forensics firm Volexity has published a detailed blog post describing the threat actor activity, which was detected in early October 2026. Volexity notes that in addition to leveraging CVE-2026-104935 as a zero-day, the threat actor also leveraged an as-yet unpatched privilege escalation vulnerability which Ivanti are planning to patch at a later date. According to the vendor, a portion of the vulnerability was initially discovered through its product security program and patched in the July 2026 release of 25.1.3.0 . Exploitation occurred while Ivanti was working to backport the fix to the remaining supported versions. Ivanti Connect Secure is a popular enterprise VPN solution and naturally sits on the edge of a corporate env

**Extracted signals**
- CVEs: CVE-2026-104935
- Products: Ivanti Connect Secure
- Vectors: exploit, vpn-edge
- Sectors: government, manufacturing
- IP IOCs: 25.1.3.0, 25.1.1.1, 25.1.1.2, 25.1.2.2, 25.1.3.1

### Hypotheses (3)

#### H-c8cfbaf1-1 · Initial access via CVE-2026-104935 affecting Ivanti Connect Secure  _(confidence: high)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2026-104935 in Ivanti Connect Secure within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2026-104935; vectors: exploit, vpn-edge; products: Ivanti Connect Secure.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-c8cfbaf1-1-O1] Inventory exposure to Ivanti Connect Secure** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of Ivanti Connect Secure, the external-exploitation hypothesis is disproven for CVE-2026-104935.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'Ivanti Connect Secure' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-c8cfbaf1-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2026-104935 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2026-104935/ | summarize count() by src_ip, dst_host`
- **[H-c8cfbaf1-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2026-104935 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2026-104935')) | summarize coverage = avg(installed) by host_role`
- **[H-c8cfbaf1-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on Ivanti Connect Secure hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-c8cfbaf1-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-c8cfbaf1-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2026-104935; vectors: exploit, vpn-edge; products: Ivanti Connect Secure.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-c8cfbaf1-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('the published C2 domains') | summarize count() by client_ip`
- **[H-c8cfbaf1-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('25.1.3.0','25.1.1.1','25.1.1.2') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-c8cfbaf1-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-c8cfbaf1-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-c8cfbaf1-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-c8cfbaf1-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2026-104935; vectors: exploit, vpn-edge; products: Ivanti Connect Secure.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-c8cfbaf1-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-c8cfbaf1-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-c8cfbaf1-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-c8cfbaf1-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 34. CVE-2026-21589: Critical unauthenticated arbitrary file access in Atlassian products

- **Source**: Rapid7
- **Link**: <https://www.rapid7.com/blog/post/etr-cve-2026-21589-critical-unauthenticated-arbitrary-file-access-in-atlassian-products>
- **Published**: Wed, 07 Oct 2026 12:11:26 GMT
- **First seen**: 2026-10-07T12:54:57+00:00
- **Relevance score**: 54
- **Score rationale**: source weight (vendor)=+10, 1 CVE(s)=+20, 1 initial-access vector(s)=+7, 1 impact action(s)=+8, 1 product mention(s)=+3, 2 IOC(s)=+6

> Overview On October 5, 2026, Atlassian published a security advisory for CVE-2026-21589 , a critical arbitrary file access vulnerability affecting eight products: Bitbucket Data Center, Confluence Data Center, Jira Service Management Data Center, Jira Software Data Center, Bamboo Data Center, Crowd Data Center, Crucible, and Fisheye. Atlassian assigned the vulnerability a CVSSv4 score of 9.3 . An unauthenticated remote attacker who knows a target file's exact name and path can access it within the application's web root; the vulnerability does not provide directory listing or enumeration. Atlassian's advisory treats all versions before the applicable fixed releases as affected, including unsupported versions. Affected Atlassian Cloud products have already been patched, and no action is required from Cloud customers. Detailed technical analysis and file-read proof-of-concept scripts are public, so Rapid7 recommends patching on an emergency basis, outside of normal patch cycles, and reviewing access logs for attempted exploitation. Technical overview NVD lists files or directories accessible to external parties ( CWE-552 ) as the weakness associated with CVE-2026-21589. On October 6, watchTowr Labs published a technical analysis based on comparisons of vulnerable and patched Jira, Confluence, and Bitbucket packages. Their analysis identified a path traversal vulnerability in Atlassian's web-resource handling: double-colon ( :: ) sequences can become path separators during reque

**Extracted signals**
- CVEs: CVE-2026-21589
- Products: Atlassian Confluence
- Vectors: exploit
- Actions: fraud
- Sectors: manufacturing
- Domain IOCs: crowd.properties, urlrewrite.xml

### Hypotheses (3)

#### H-9e5e3958-1 · Initial access via CVE-2026-21589 affecting Atlassian Confluence  _(confidence: high)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2026-21589 in Atlassian Confluence within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2026-21589; vectors: exploit; impact: fraud; products: Atlassian Confluence.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-9e5e3958-1-O1] Inventory exposure to Atlassian Confluence** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of Atlassian Confluence, the external-exploitation hypothesis is disproven for CVE-2026-21589.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'Atlassian Confluence' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-9e5e3958-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2026-21589 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2026-21589/ | summarize count() by src_ip, dst_host`
- **[H-9e5e3958-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2026-21589 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2026-21589')) | summarize coverage = avg(installed) by host_role`
- **[H-9e5e3958-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on Atlassian Confluence hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-9e5e3958-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-9e5e3958-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2026-21589; vectors: exploit; impact: fraud; products: Atlassian Confluence.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-9e5e3958-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('crowd.properties','urlrewrite.xml') | summarize count() by client_ip`
- **[H-9e5e3958-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-9e5e3958-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-9e5e3958-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-9e5e3958-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-9e5e3958-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2026-21589; vectors: exploit; impact: fraud; products: Atlassian Confluence.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-9e5e3958-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-9e5e3958-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-9e5e3958-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-9e5e3958-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 35. AhsayCBS Flaws Exploited to Deploy Web Shells Get New Fixes After Incomplete Patches

- **Source**: The Hacker News
- **Link**: <https://thehackernews.com/2026/10/ahsaycbs-flaws-exploited-to-deploy-web.html>
- **Published**: Thu, 15 Oct 2026 12:13:08 +0530
- **First seen**: 2026-10-15T09:36:50+00:00
- **Relevance score**: 53
- **Score rationale**: source weight (news)=+5, 2 CVE(s)=+25, 1 MITRE technique hit(s)=+8, 1 initial-access vector(s)=+7, 1 impact action(s)=+8

> Singapore-based Ahsay Backup has released security updates to address two security flaws in AhsayCBS that have been exploited by bad actors to drop web shells and XMRig cryptocurrency miners. The vulnerabilities in question are CVE-2026-105133 and CVE-2026-105134, which could be chained to sidestep authentication and execute arbitrary commands on affected systems. In a report published earlier

**Extracted signals**
- CVEs: CVE-2026-105133, CVE-2026-105134
- Vectors: exploit
- Actions: cryptomining
- MITRE ATT&CK: T1505.003

### Hypotheses (3)

#### H-d6860c3f-1 · Initial access via CVE-2026-105133 affecting the affected product/service  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2026-105133 in the affected product/service within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2026-105133, CVE-2026-105134; vectors: exploit; impact: cryptomining.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-d6860c3f-1-O1] Inventory exposure to the affected product** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of the affected product, the external-exploitation hypothesis is disproven for CVE-2026-105133.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'the affected product' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-d6860c3f-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2026-105133 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2026-105133/ | summarize count() by src_ip, dst_host`
- **[H-d6860c3f-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2026-105133 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2026-105133')) | summarize coverage = avg(installed) by host_role`
- **[H-d6860c3f-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on the affected product hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-d6860c3f-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-d6860c3f-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: medium)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2026-105133, CVE-2026-105134; vectors: exploit; impact: cryptomining.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-d6860c3f-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('the published C2 domains') | summarize count() by client_ip`
- **[H-d6860c3f-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-d6860c3f-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-d6860c3f-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-d6860c3f-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-d6860c3f-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2026-105133, CVE-2026-105134; vectors: exploit; impact: cryptomining.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-d6860c3f-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-d6860c3f-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-d6860c3f-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-d6860c3f-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 36. More RMM Tools In the Wild, (Tue, Oct 6th)

- **Source**: SANS Internet Storm Center
- **Link**: <https://isc.sans.edu/diary/rss/33400>
- **Published**: Tue, 06 Oct 2026 09:34:56 GMT
- **First seen**: 2026-10-06T10:01:34+00:00
- **Relevance score**: 53
- **Score rationale**: source weight (advisory)=+15, 2 MITRE technique hit(s)=+11, 2 initial-access vector(s)=+9, 1 product mention(s)=+3, 10 IOC(s)=+15

> It seems that a trend started&#xe2;&#x80;&#xa6; I continue my journey discovering more RMM ("Remote Management & Monitoring") tools abused by threat actors! A few days ago, I wrote a diary[ 1 ] about ScreenConnect used in the wild. Today, I found another one.

**Extracted signals**
- Products: ConnectWise ScreenConnect
- Vectors: phishing, exploit
- Sectors: manufacturing, telecom
- MITRE ATT&CK: T1566, T1219
- Domain IOCs: pdf-parser.py, up-theta-rose.vercel.app, action1.msi, server.na-2.action1.com, isc.sans.edu, www.action1.com
- SHA256: eaff35d250c9b04f51c971e70082740dbfeee5dd846829d541f588ad43378727, 996b01e15f85e165899630721a141b178a9c372b6e878012180ec9e9d4e7bd06, 1b19115d5ebdc216e0ab3adf2c643648cfc70a385f4caf0217c679f9f3b20342, 941695d20d82dd5d62f74b0111feb23720637202f6c797df2a02e2cb6cb6e8e3

### Hypotheses (3)

#### H-7481de92-1 · Initial access via the disclosed vulnerability affecting ConnectWise ScreenConnect  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting the disclosed vulnerability in ConnectWise ScreenConnect within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on vectors: phishing, exploit; products: ConnectWise ScreenConnect.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-7481de92-1-O1] Inventory exposure to ConnectWise ScreenConnect** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of ConnectWise ScreenConnect, the external-exploitation hypothesis is disproven for the referenced CVE.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'ConnectWise ScreenConnect' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-7481de92-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for the referenced CVE in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-the referenced CVE/ | summarize count() by src_ip, dst_host`
- **[H-7481de92-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the the referenced CVE fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('the referenced CVE')) | summarize coverage = avg(installed) by host_role`
- **[H-7481de92-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on ConnectWise ScreenConnect hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-7481de92-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-7481de92-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on vectors: phishing, exploit; products: ConnectWise ScreenConnect.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-7481de92-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('pdf-parser.py','up-theta-rose.vercel.app','action1.msi') | summarize count() by client_ip`
- **[H-7481de92-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-7481de92-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-7481de92-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-7481de92-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-7481de92-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on vectors: phishing, exploit; products: ConnectWise ScreenConnect.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-7481de92-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-7481de92-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-7481de92-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-7481de92-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 37. CISA Adds Two Known Exploited Vulnerabilities to Catalog

- **Source**: CISA Advisories
- **Link**: <https://www.cisa.gov/news-events/alerts/2026/10/16/cisa-adds-two-known-exploited-vulnerabilities-catalog>
- **Published**: Fri, 16 Oct 26 12:00:00 +0000
- **First seen**: 2026-10-16T19:02:39+00:00
- **Relevance score**: 52
- **Score rationale**: source weight (advisory)=+15, 2 CVE(s)=+25, 2 initial-access vector(s)=+9, 1 product mention(s)=+3

> CISA has added two new vulnerabilities to its Known Exploited Vulnerabilities (KEV) Catalog , based on evidence of active exploitation. CVE-2025-61624 Fortinet Multiple Products Path Traversal Vulnerability CVE-2026-102764 BeyondTrust Remote Support Authentication Bypass by Spoofing Vulnerability These types of vulnerabilities are a frequent attack vector for malicious cyber actors and pose significant risks to the federal enterprise. Binding Operational Directive (BOD) 26-04: Prioritizing Security Updates Based on Risk establishes vulnerability management requirements for Federal Civilian Executive Branch (FCEB) agencies. BOD 26-04 reinforces the importance of the KEV Catalog and requires federal agencies to prioritize rapid remediation of high-risk vulnerabilities, specifically those identified by Common Vulnerabilities and Exposures (CVEs) listed in CISA’s KEV Catalog on publicly exposed assets that grant total control of the asset post-exploitation, while deferring action for lower-risk vulnerabilities. BOD 26-04 further establishes basic expectations for when agencies must check whether threat actors compromised the system before the patch was applied. While BOD 26-04 applies only to FCEB agencies, CISA encourages all organizations to adopt risk-based vulnerability management and prioritize remediation of KEV Catalog vulnerabilities . CISA will continue to add vulnerabilities to the catalog that meet the specified criteria . Aware of an exploited vulnerability not curren

**Extracted signals**
- CVEs: CVE-2025-61624, CVE-2026-102764
- Products: Fortinet FortiOS
- Vectors: exploit, vpn-edge
- Sectors: government, manufacturing

### Hypotheses (3)

#### H-fd52c4f3-1 · Initial access via CVE-2025-61624 affecting Fortinet FortiOS  _(confidence: high)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2025-61624 in Fortinet FortiOS within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2025-61624, CVE-2026-102764; vectors: exploit, vpn-edge; products: Fortinet FortiOS.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-fd52c4f3-1-O1] Inventory exposure to Fortinet FortiOS** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of Fortinet FortiOS, the external-exploitation hypothesis is disproven for CVE-2025-61624.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'Fortinet FortiOS' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-fd52c4f3-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2025-61624 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2025-61624/ | summarize count() by src_ip, dst_host`
- **[H-fd52c4f3-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2025-61624 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2025-61624')) | summarize coverage = avg(installed) by host_role`
- **[H-fd52c4f3-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on Fortinet FortiOS hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-fd52c4f3-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-fd52c4f3-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: medium)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2025-61624, CVE-2026-102764; vectors: exploit, vpn-edge; products: Fortinet FortiOS.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-fd52c4f3-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('the published C2 domains') | summarize count() by client_ip`
- **[H-fd52c4f3-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-fd52c4f3-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-fd52c4f3-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-fd52c4f3-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-fd52c4f3-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2025-61624, CVE-2026-102764; vectors: exploit, vpn-edge; products: Fortinet FortiOS.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-fd52c4f3-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-fd52c4f3-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-fd52c4f3-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-fd52c4f3-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 38. CISA Adds Two Known Exploited Vulnerabilities to Catalog

- **Source**: CISA Advisories
- **Link**: <https://www.cisa.gov/news-events/alerts/2026/10/13/cisa-adds-two-known-exploited-vulnerabilities-catalog>
- **Published**: Tue, 13 Oct 26 12:00:00 +0000
- **First seen**: 2026-10-13T20:48:54+00:00
- **Relevance score**: 52
- **Score rationale**: source weight (advisory)=+15, 2 CVE(s)=+25, 2 initial-access vector(s)=+9, 1 product mention(s)=+3

> CISA has added two new vulnerabilities to its Known Exploited Vulnerabilities (KEV) Catalog , based on evidence of active exploitation. CVE-2026-96951 Microsoft Windows Command Injection Vulnerability CVE-2026-104935 Ivanti Connect Secure Authentication Bypass by Spoofing Vulnerability These types of vulnerabilities are a frequent attack vector for malicious cyber actors and pose significant risks to the federal enterprise. Binding Operational Directive (BOD) 26-04: Prioritizing Security Updates Based on Risk establishes vulnerability management requirements for Federal Civilian Executive Branch (FCEB) agencies. BOD 26-04 reinforces the importance of the KEV Catalog and requires federal agencies to prioritize rapid remediation of high-risk vulnerabilities, specifically those identified by Common Vulnerabilities and Exposures (CVEs) listed in CISA’s KEV Catalog on publicly exposed assets that grant total control of the asset post-exploitation, while deferring action for lower-risk vulnerabilities. BOD 26-04 further establishes basic expectations for when agencies must check whether threat actors compromised the system before the patch was applied. While BOD 26-04 applies only to FCEB agencies, CISA encourages all organizations to adopt risk-based vulnerability management and prioritize remediation of KEV Catalog vulnerabilities . CISA will continue to add vulnerabilities to the catalog that meet the specified criteria . Aware of an exploited vulnerability not currently listed 

**Extracted signals**
- CVEs: CVE-2026-96951, CVE-2026-104935
- Products: Ivanti Connect Secure
- Vectors: exploit, vpn-edge
- Sectors: government, manufacturing

### Hypotheses (3)

#### H-8786243a-1 · Initial access via CVE-2026-96951 affecting Ivanti Connect Secure  _(confidence: high)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2026-96951 in Ivanti Connect Secure within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2026-96951, CVE-2026-104935; vectors: exploit, vpn-edge; products: Ivanti Connect Secure.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-8786243a-1-O1] Inventory exposure to Ivanti Connect Secure** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of Ivanti Connect Secure, the external-exploitation hypothesis is disproven for CVE-2026-96951.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'Ivanti Connect Secure' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-8786243a-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2026-96951 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2026-96951/ | summarize count() by src_ip, dst_host`
- **[H-8786243a-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2026-96951 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2026-96951')) | summarize coverage = avg(installed) by host_role`
- **[H-8786243a-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on Ivanti Connect Secure hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-8786243a-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-8786243a-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: medium)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2026-96951, CVE-2026-104935; vectors: exploit, vpn-edge; products: Ivanti Connect Secure.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-8786243a-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('the published C2 domains') | summarize count() by client_ip`
- **[H-8786243a-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-8786243a-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-8786243a-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-8786243a-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-8786243a-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2026-96951, CVE-2026-104935; vectors: exploit, vpn-edge; products: Ivanti Connect Secure.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-8786243a-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-8786243a-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-8786243a-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-8786243a-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 39. Attackers Exploit AhsayCBS Flaws to Deploy XMRig Miners Disguised as Microsoft Edge

- **Source**: The Hacker News
- **Link**: <https://thehackernews.com/2026/10/attackers-exploit-ahsaycbs-flaws-to.html>
- **Published**: Fri, 09 Oct 2026 18:17:26 +0530
- **First seen**: 2026-10-09T14:58:26+00:00
- **Relevance score**: 52
- **Score rationale**: source weight (news)=+5, 1 CVE(s)=+20, 1 MITRE technique hit(s)=+8, 1 initial-access vector(s)=+7, 1 impact action(s)=+8, 1 IOC(s)=+4

> Threat actors have been observed exploiting two recently disclosed flaws in the AhsayCBS backup utility to seize control of affected devices and deploy web shells and XMRig cryptocurrency miners. Details of the flaws are below - CVE-2026-105133 (CVSS v4 score: 5.5) - An improper authentication vulnerability in the checkSysPwd() function in the "com/ahsay/obs/api/ApiStructsAction.java"

**Extracted signals**
- CVEs: CVE-2026-105133
- Vectors: exploit
- Actions: cryptomining
- Sectors: energy
- MITRE ATT&CK: T1505.003
- Domain IOCs: apistructsaction.java

### Hypotheses (3)

#### H-5dc3760d-1 · Initial access via CVE-2026-105133 affecting the affected product/service  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2026-105133 in the affected product/service within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2026-105133; vectors: exploit; impact: cryptomining.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-5dc3760d-1-O1] Inventory exposure to the affected product** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of the affected product, the external-exploitation hypothesis is disproven for CVE-2026-105133.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'the affected product' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-5dc3760d-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2026-105133 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2026-105133/ | summarize count() by src_ip, dst_host`
- **[H-5dc3760d-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2026-105133 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2026-105133')) | summarize coverage = avg(installed) by host_role`
- **[H-5dc3760d-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on the affected product hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-5dc3760d-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-5dc3760d-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2026-105133; vectors: exploit; impact: cryptomining.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-5dc3760d-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('apistructsaction.java') | summarize count() by client_ip`
- **[H-5dc3760d-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-5dc3760d-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-5dc3760d-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-5dc3760d-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-5dc3760d-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2026-105133; vectors: exploit; impact: cryptomining.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-5dc3760d-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-5dc3760d-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-5dc3760d-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-5dc3760d-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 40. Flax Typhoon Exploits Five Flaws as CISA Sets October 11 Deadline for Federal Agencies

- **Source**: The Hacker News
- **Link**: <https://thehackernews.com/2026/10/flax-typhoon-exploits-five-flaws-as.html>
- **Published**: Fri, 09 Oct 2026 17:51:51 +0530
- **First seen**: 2026-10-09T12:59:07+00:00
- **Relevance score**: 52
- **Score rationale**: source weight (news)=+5, 1 CVE(s)=+20, 1 threat actor hit(s)=+20, 1 initial-access vector(s)=+7

> The U.S. Cybersecurity and Infrastructure Security Agency (CISA) on Thursday added five security flaws to its Known Exploited Vulnerabilities (KEV) catalog, following their abuse by a China-linked threat actor known as Flax Typhoon. The vulnerabilities in question are listed below - CVE-2015-3306 (CVSS score: 10.0) - An improper access control vulnerability in ProFTPD that could allow

**Extracted signals**
- CVEs: CVE-2015-3306
- Threat actors: Flax Typhoon
- Vectors: exploit
- Sectors: government

### Hypotheses (3)

#### H-b06e22fa-1 · Initial access via CVE-2015-3306 affecting the affected product/service  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2015-3306 in the affected product/service within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2015-3306; threat actors: Flax Typhoon; vectors: exploit.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-b06e22fa-1-O1] Inventory exposure to the affected product** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of the affected product, the external-exploitation hypothesis is disproven for CVE-2015-3306.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'the affected product' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-b06e22fa-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2015-3306 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2015-3306/ | summarize count() by src_ip, dst_host`
- **[H-b06e22fa-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2015-3306 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2015-3306')) | summarize coverage = avg(installed) by host_role`
- **[H-b06e22fa-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on the affected product hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-b06e22fa-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-b06e22fa-2 · Post-foothold lateral movement consistent with Flax Typhoon  _(confidence: medium)_

**Statement.** An attacker who matched the TTPs of Flax Typhoon has moved laterally inside the estate using RDP/SMB/WinRM, admin tooling, or Kerberos abuse.

**Why this hypothesis?** Archetype 'lateral_movement' selected based on CVEs cited: CVE-2015-3306; threat actors: Flax Typhoon; vectors: exploit.

**MITRE ATT&CK**: T1021.001, T1021.002, T1021.006, T1003

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-b06e22fa-2-O1] Anomalous remote logons (Type 3 / Type 10)** _(difficulty: medium · 200 pts · MITRE: T1021.001, T1021.002)_
  - Falsification criterion: If 4624 logon-type 3/10 events show no bursts from a single source to many destinations, lateral movement via RDP/SMB is unsupported.
  - Data sources: Windows Security event log, Domain Controller logs
  - Suggested query: `security | where event_id in (4624) and logon_type in (3,10) | summarize dests = dcount(dst_host) by src_user, src_host | where dests > 10`
- **[H-b06e22fa-2-O2] Admin-tool usage outside baseline** _(difficulty: medium · 200 pts · MITRE: T1021.002, T1021.006, T1059)_
  - Falsification criterion: If PsExec / WMIC / PowerShell remoting / Impacket-style usage is absent outside known admin jump-hosts, the lateral-tool hypothesis is disproven.
  - Data sources: Sysmon EID 1, EDR, 4688
  - Suggested query: `process | where name in ('psexec.exe','psexesvc.exe','wmic.exe','wsmprovhost.exe') and host !in (admin_jumphosts)`
- **[H-b06e22fa-2-O3] Kerberos abuse telemetry** _(difficulty: hard · 300 pts · MITRE: T1558.003, T1110.003)_
  - Falsification criterion: If 4769 ticket requests show no anomalous RC4 / odd-SPN patterns and no AS-REP roasting indicators, credential-based lateral movement is unsupported.
  - Data sources: Domain Controller security log
  - Suggested query: `security | where event_id == 4769 and ticket_encryption == 'RC4-HMAC' | summarize by target_spn, account_name`
- **[H-b06e22fa-2-O4] Lateral file-copy staging** _(difficulty: medium · 200 pts · MITRE: T1570, T1021.002)_
  - Falsification criterion: If SMB writes of archives / executables across multiple hosts from one user/host are absent, lateral staging is unsupported.
  - Data sources: File-share auditing (5145), EDR file events
  - Suggested query: `file | where action == 'write' and ext in ('.7z','.rar','.zip','.exe') and dest matches /\\\\.*\\(C\$|admin\$)/`

#### H-b06e22fa-3 · Outbound C2 beaconing to reported infrastructure  _(confidence: medium)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2015-3306; threat actors: Flax Typhoon; vectors: exploit.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-b06e22fa-3-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('the published C2 domains') | summarize count() by client_ip`
- **[H-b06e22fa-3-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-b06e22fa-3-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-b06e22fa-3-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-b06e22fa-3-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

---

## 41. CISA Urges Patching Critical Vulnerability in BeyondTrust Remote Support

- **Source**: CISA Advisories
- **Link**: <https://www.cisa.gov/news-events/alerts/2026/10/16/cisa-urges-patching-critical-vulnerability-beyondtrust-remote-support>
- **Published**: Fri, 16 Oct 26 12:00:00 +0000
- **First seen**: 2026-10-16T21:44:58+00:00
- **Relevance score**: 50
- **Score rationale**: source weight (advisory)=+15, 1 CVE(s)=+20, 1 MITRE technique hit(s)=+8, 1 initial-access vector(s)=+7

> CISA is aware of critical authentication bypass vulnerability CVE-2026-102764 , affecting BeyondTrust Remote Support (formerly Bomgar) versions 26.2.3 and earlier. Patches are available for supported versions (24.3.1 and later); organizations using older versions must upgrade first. Cyber threat actors are actively exploiting the vulnerability to gain initial access, then establishing persistence, escalating privileges, and moving laterally. CISA added CVE-2026-102764 to its Known Exploited Vulnerabilities (KEV) catalog on Oct. 16, 2026. CISA urges organizations with affected self-hosted Remote Support appliances to immediately take the following actions: Apply the BT26-05-RS patch, as outlined in BeyondTrust’s Security Advisory BT26-05 . Organizations on a self-hosted Remote Support version older than 24.3.1 will need to upgrade to a newer version to apply the patch. Organizations using BeyondTrust-hosted (SaaS) Remote Support deployments have already been patched. Review BeyondTrust’s blog ARMORY CASTLE and BT26-05: What Security Teams Need to Know for detailed information on the vulnerability and recommended response and mitigation actions. Limit external access to the Remote Support appliance to the services needed to support users and customers. Restrict access to administrative interfaces to trusted networks. Review BeyondTrust’s B Series Appliance on-premises security for additional guidance on securing network connectivity for self-hosted Remote Support appliances. Or

**Extracted signals**
- CVEs: CVE-2026-102764
- Vectors: exploit
- Sectors: manufacturing
- MITRE ATT&CK: T1219

### Hypotheses (3)

#### H-40c2793d-1 · Initial access via CVE-2026-102764 affecting the affected product/service  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2026-102764 in the affected product/service within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2026-102764; vectors: exploit.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-40c2793d-1-O1] Inventory exposure to the affected product** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of the affected product, the external-exploitation hypothesis is disproven for CVE-2026-102764.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'the affected product' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-40c2793d-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2026-102764 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2026-102764/ | summarize count() by src_ip, dst_host`
- **[H-40c2793d-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2026-102764 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2026-102764')) | summarize coverage = avg(installed) by host_role`
- **[H-40c2793d-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on the affected product hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-40c2793d-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-40c2793d-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: medium)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2026-102764; vectors: exploit.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-40c2793d-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('the published C2 domains') | summarize count() by client_ip`
- **[H-40c2793d-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-40c2793d-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-40c2793d-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-40c2793d-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-40c2793d-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2026-102764; vectors: exploit.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-40c2793d-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-40c2793d-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-40c2793d-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-40c2793d-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 42. Savannah lwIP SMTP client

- **Source**: CISA Advisories
- **Link**: <https://www.cisa.gov/news-events/ics-advisories/icsa-26-279-02>
- **Published**: Tue, 06 Oct 26 12:00:00 +0000
- **First seen**: 2026-10-06T16:35:14+00:00
- **Relevance score**: 50
- **Score rationale**: source weight (advisory)=+15, 1 CVE(s)=+20, 2 initial-access vector(s)=+9, 2 IOC(s)=+6

> View CSAF Summary Successful exploitation of this vulnerability could crash the device being accessed; a buffer overflow condition may allow remote code execution. The following versions of Savannah lwIP SMTP client are affected: lwIP SMTP client 2.2.1 (CVE-2026-15340) CVSS Vendor Equipment v3 9.8 Savannah lwIP SMTP client 1 Vulnerability Buffer Copy without Checking Size of Input ('Classic Buffer Overflow') Background Critical Infrastructure Sectors: Energy, Water and Wastewater Systems Countries/Areas Deployed: Worldwide Company Headquarters Location: Sweden Vulnerabilities CVE-2026-15340 lwIP SMTP client does not check the size of inputs, potentially allowing a buffer overflow. Read More 1 Affected Product Savannah lwIP SMTP client: 2.2.1 Product Status: known_affected Remediations Mitigation xchglabs reports that the vulnerability was fixed and released in the following patch: patch_125_smtp_txbuf.diff . This is available as available as git commit (614420f82c8729d070e01464c0dddb3c9525c772) Additional Metrics Relevant CWE: CWE-120 Buffer Copy without Checking Size of Input ('Classic Buffer Overflow') CVSS Version Base Score Base Severity Vector String 3.1 9.8 CRITICAL CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H 4.0 9.3 CRITICAL CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N View CVE Details Acknowledgments xchglabs reported this vulnerability directly to Savannah and then disclosed once the fix was released Legal Notice and Terms of Use This product is p

**Extracted signals**
- CVEs: CVE-2026-15340
- Vectors: exploit, vpn-edge
- Sectors: energy, manufacturing
- Domain IOCs: www.cisa.gov
- SHA1: 614420f82c8729d070e01464c0dddb3c9525c772

### Hypotheses (3)

#### H-2a14f756-1 · Initial access via CVE-2026-15340 affecting the affected product/service  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2026-15340 in the affected product/service within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2026-15340; vectors: exploit, vpn-edge.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-2a14f756-1-O1] Inventory exposure to the affected product** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of the affected product, the external-exploitation hypothesis is disproven for CVE-2026-15340.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'the affected product' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-2a14f756-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2026-15340 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2026-15340/ | summarize count() by src_ip, dst_host`
- **[H-2a14f756-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2026-15340 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2026-15340')) | summarize coverage = avg(installed) by host_role`
- **[H-2a14f756-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on the affected product hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-2a14f756-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-2a14f756-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2026-15340; vectors: exploit, vpn-edge.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-2a14f756-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('www.cisa.gov') | summarize count() by client_ip`
- **[H-2a14f756-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-2a14f756-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-2a14f756-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-2a14f756-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-2a14f756-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2026-15340; vectors: exploit, vpn-edge.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-2a14f756-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-2a14f756-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-2a14f756-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-2a14f756-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 43. The hidden network: Inside the phishing infrastructure ecosystem powering global cybercrime

- **Source**: Microsoft Security
- **Link**: <https://www.microsoft.com/en-us/security/blog/2026/10/14/the-hidden-network-inside-the-phishing-infrastructure-ecosystem-powering-global-cybercrime/>
- **Published**: Wed, 14 Oct 2026 13:00:00 +0000
- **First seen**: 2026-10-14T13:32:49+00:00
- **Relevance score**: 48
- **Score rationale**: source weight (vendor)=+10, 1 MITRE technique hit(s)=+8, 4 initial-access vector(s)=+13, 1 impact action(s)=+8, 1 product mention(s)=+3, 2 IOC(s)=+6

> Microsoft uncovered a Chinese-language cybercriminal ecosystem, an interconnected network of phishing kit operators (tracked as Storm-2990), and an illicit marketplace (tracked as Storm-3119) selling tools and infrastructure for large-scale phishing. In collaboration with law enforcement agencies and other partners worldwide, Microsoft’s Digital Crimes Unit (DCU) facilitated a disruption of the ecosystem. The post The hidden network: Inside the phishing infrastructure ecosystem powering global cybercrime appeared first on Microsoft Security Blog .

**Extracted signals**
- Products: Microsoft 365 / Entra ID
- Vectors: phishing, exploit, cloud-misconfig, social-engineering
- Actions: fraud
- Sectors: healthcare, finance, government, manufacturing, education, retail
- MITRE ATT&CK: T1566
- Domain IOCs: appcatalog.readwrite.all, jewishchoice.org

### Hypotheses (3)

#### H-580c9660-1 · Initial access via the disclosed vulnerability affecting Microsoft 365 / Entra ID  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting the disclosed vulnerability in Microsoft 365 / Entra ID within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on vectors: phishing, exploit, cloud-misconfig; impact: fraud; products: Microsoft 365 / Entra ID.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-580c9660-1-O1] Inventory exposure to Microsoft 365 / Entra ID** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of Microsoft 365 / Entra ID, the external-exploitation hypothesis is disproven for the referenced CVE.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'Microsoft 365 / Entra ID' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-580c9660-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for the referenced CVE in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-the referenced CVE/ | summarize count() by src_ip, dst_host`
- **[H-580c9660-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the the referenced CVE fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('the referenced CVE')) | summarize coverage = avg(installed) by host_role`
- **[H-580c9660-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on Microsoft 365 / Entra ID hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-580c9660-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-580c9660-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on vectors: phishing, exploit, cloud-misconfig; impact: fraud; products: Microsoft 365 / Entra ID.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-580c9660-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('appcatalog.readwrite.all','jewishchoice.org') | summarize count() by client_ip`
- **[H-580c9660-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-580c9660-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-580c9660-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-580c9660-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-580c9660-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on vectors: phishing, exploit, cloud-misconfig; impact: fraud; products: Microsoft 365 / Entra ID.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-580c9660-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-580c9660-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-580c9660-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-580c9660-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 44. CISA Adds One Known Exploited Vulnerability to Catalog

- **Source**: CISA Advisories
- **Link**: <https://www.cisa.gov/news-events/alerts/2026/10/04/cisa-adds-one-known-exploited-vulnerability-catalog>
- **Published**: Sun, 04 Oct 26 12:00:00 +0000
- **First seen**: 2026-10-04T20:46:52+00:00
- **Relevance score**: 47
- **Score rationale**: source weight (advisory)=+15, 1 CVE(s)=+20, 2 initial-access vector(s)=+9, 1 product mention(s)=+3

> CISA has added one new vulnerability to its Known Exploited Vulnerabilities (KEV) Catalog , based on evidence of active exploitation. CVE-2026-88779 Citrix NetScaler Improper Restriction of Operations within the Bounds of a Memory Buffer Vulnerability This type of vulnerability is a frequent attack vector for malicious cyber actors and poses significant risks to the federal enterprise. Binding Operational Directive (BOD) 26-04: Prioritizing Security Updates Based on Risk establishes vulnerability management requirements for Federal Civilian Executive Branch (FCEB) agencies. BOD 26-04 reinforces the importance of the KEV Catalog and requires federal agencies to prioritize rapid remediation of high-risk vulnerabilities, specifically those identified by Common Vulnerabilities and Exposures (CVEs) listed in CISA’s KEV Catalog on publicly exposed assets that grant total control of the asset post-exploitation, while deferring action for lower-risk vulnerabilities. BOD 26-04 further establishes basic expectations for when agencies must check whether threat actors compromised the system before the patch was applied. While BOD 26-04 applies only to FCEB agencies, CISA encourages all organizations to adopt risk-based vulnerability management and prioritize remediation of KEV Catalog vulnerabilities . CISA will continue to add vulnerabilities to the catalog that meet the specified criteria . Aware of an exploited vulnerability not currently listed in the KEV Catalog? Submit it for poten

**Extracted signals**
- CVEs: CVE-2026-88779
- Products: Citrix NetScaler
- Vectors: exploit, vpn-edge
- Sectors: government, manufacturing

### Hypotheses (3)

#### H-d7def80c-1 · Initial access via CVE-2026-88779 affecting Citrix NetScaler  _(confidence: high)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2026-88779 in Citrix NetScaler within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2026-88779; vectors: exploit, vpn-edge; products: Citrix NetScaler.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-d7def80c-1-O1] Inventory exposure to Citrix NetScaler** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of Citrix NetScaler, the external-exploitation hypothesis is disproven for CVE-2026-88779.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'Citrix NetScaler' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-d7def80c-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2026-88779 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2026-88779/ | summarize count() by src_ip, dst_host`
- **[H-d7def80c-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2026-88779 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2026-88779')) | summarize coverage = avg(installed) by host_role`
- **[H-d7def80c-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on Citrix NetScaler hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-d7def80c-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-d7def80c-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: medium)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2026-88779; vectors: exploit, vpn-edge; products: Citrix NetScaler.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-d7def80c-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('the published C2 domains') | summarize count() by client_ip`
- **[H-d7def80c-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-d7def80c-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-d7def80c-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-d7def80c-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-d7def80c-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2026-88779; vectors: exploit, vpn-edge; products: Citrix NetScaler.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-d7def80c-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-d7def80c-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-d7def80c-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-d7def80c-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 45. CVE-2026-97229: Critical Unauthenticated Remote Code Execution in GitLab

- **Source**: Rapid7
- **Link**: <https://www.rapid7.com/blog/post/etr-cve-2026-97229-critical-unauthenticated-remote-code-execution-in-gitlab>
- **Published**: Tue, 13 Oct 2026 11:29:03 GMT
- **First seen**: 2026-10-13T12:12:49+00:00
- **Relevance score**: 46
- **Score rationale**: source weight (vendor)=+10, 1 CVE(s)=+20, 1 initial-access vector(s)=+7, 1 product mention(s)=+3, 2 IOC(s)=+6

> Overview On October 12, 2026, GitLab published a critical patch release for CVE-2026-97229 , an integer overflow or wraparound ( CWE-190 ) in the CI/CD regular expression compiler affecting GitLab Community Edition (CE) and Enterprise Edition (EE). GitLab assigned the vulnerability a CVSSv3.1 score of 10.0 . Under certain conditions, a remote attacker can execute arbitrary code on an affected GitLab server through a specially crafted regular expression stored in a malicious CI/CD configuration. While the vendor supplied CVSS score indicates that exploitation is fully unauthenticated, in reproducing the exploit it was noted that an attacker must have a mechanism to plant a malicious CI/CD configuration to a repository prior to triggering the vulnerability. On GitLab instances where new users can self register and create projects, this constraint is removed. The vulnerability affects self-managed GitLab instances across all deployment types. GitLab.com is already running a patched version, and GitLab Dedicated customers do not need to take action. As of this writing, there is no confirmed in-the-wild exploitation of CVE-2026-97229. However, Rapid7 Intelligence has independently reproduced arbitrary code execution on an unpatched, official GitLab CE image. Given the vulnerability's maximum CVSS score, network-accessible trigger, and code execution in a GitLab application worker, Rapid7 recommends upgrading affected self-managed instances on an urgent basis, outside of normal pat

**Extracted signals**
- CVEs: CVE-2026-97229
- Products: GitLab
- Vectors: exploit
- Sectors: manufacturing
- Domain IOCs: gitlab.com, gitlab-ci.yml

### Hypotheses (3)

#### H-b7d1712a-1 · Initial access via CVE-2026-97229 affecting GitLab  _(confidence: high)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2026-97229 in GitLab within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2026-97229; vectors: exploit; products: GitLab.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-b7d1712a-1-O1] Inventory exposure to GitLab** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of GitLab, the external-exploitation hypothesis is disproven for CVE-2026-97229.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'GitLab' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-b7d1712a-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2026-97229 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2026-97229/ | summarize count() by src_ip, dst_host`
- **[H-b7d1712a-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2026-97229 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2026-97229')) | summarize coverage = avg(installed) by host_role`
- **[H-b7d1712a-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on GitLab hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-b7d1712a-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-b7d1712a-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2026-97229; vectors: exploit; products: GitLab.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-b7d1712a-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('gitlab.com','gitlab-ci.yml') | summarize count() by client_ip`
- **[H-b7d1712a-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-b7d1712a-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-b7d1712a-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-b7d1712a-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-b7d1712a-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2026-97229; vectors: exploit; products: GitLab.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-b7d1712a-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-b7d1712a-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-b7d1712a-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-b7d1712a-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 46. User Agent Strings Curiosities, (Sun, Oct 4th)

- **Source**: SANS Internet Storm Center
- **Link**: <https://isc.sans.edu/diary/rss/33394>
- **Published**: Sun, 04 Oct 2026 07:58:51 GMT
- **First seen**: 2026-10-04T08:23:13+00:00
- **Relevance score**: 46
- **Score rationale**: source weight (advisory)=+15, 1 MITRE technique hit(s)=+8, 2 initial-access vector(s)=+9, 1 impact action(s)=+8, 2 IOC(s)=+6

> Sometimes I have to smile, or my interest is triggered, when I review new User Agent Strings in the honeypot logs.

**Extracted signals**
- Vectors: exploit, rdp
- Actions: fraud
- Sectors: manufacturing
- MITRE ATT&CK: T1021.001
- Domain IOCs: blog.didierstevens.com, isc.sans.edu

### Hypotheses (3)

#### H-e4e816a7-1 · Initial access via the disclosed vulnerability affecting the affected product/service  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting the disclosed vulnerability in the affected product/service within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on vectors: exploit, rdp; impact: fraud.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-e4e816a7-1-O1] Inventory exposure to the affected product** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of the affected product, the external-exploitation hypothesis is disproven for the referenced CVE.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'the affected product' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-e4e816a7-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for the referenced CVE in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-the referenced CVE/ | summarize count() by src_ip, dst_host`
- **[H-e4e816a7-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the the referenced CVE fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('the referenced CVE')) | summarize coverage = avg(installed) by host_role`
- **[H-e4e816a7-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on the affected product hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-e4e816a7-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-e4e816a7-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on vectors: exploit, rdp; impact: fraud.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-e4e816a7-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('blog.didierstevens.com','isc.sans.edu') | summarize count() by client_ip`
- **[H-e4e816a7-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-e4e816a7-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-e4e816a7-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-e4e816a7-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-e4e816a7-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on vectors: exploit, rdp; impact: fraud.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-e4e816a7-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-e4e816a7-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-e4e816a7-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-e4e816a7-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 47. Orphaned VBA Projects Inside DWG Files, (Wed, Oct 14th)

- **Source**: SANS Internet Storm Center
- **Link**: <https://isc.sans.edu/diary/rss/33420>
- **Published**: Wed, 14 Oct 2026 06:49:46 GMT
- **First seen**: 2026-10-14T07:29:56+00:00
- **Relevance score**: 45
- **Score rationale**: source weight (advisory)=+15, 1 initial-access vector(s)=+7, 1 impact action(s)=+8, 7 IOC(s)=+15

> Years ago I wrote diary entries about VBA code stored inside AutoCAD drawing files (.dwg).

**Extracted signals**
- Vectors: exploit
- Actions: fraud
- Sectors: manufacturing, telecom
- Domain IOCs: autocad.py, cut-bytes.py, vir.zip, oledump.py, blog.didierstevens.com, isc.sans.edu
- SHA256: 461ed52aeb75384133a8238b2eb481ae5d505d4961effa622673d65a889c8218

### Hypotheses (3)

#### H-251d43b3-1 · Initial access via the disclosed vulnerability affecting the affected product/service  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting the disclosed vulnerability in the affected product/service within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on vectors: exploit; impact: fraud.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-251d43b3-1-O1] Inventory exposure to the affected product** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of the affected product, the external-exploitation hypothesis is disproven for the referenced CVE.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'the affected product' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-251d43b3-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for the referenced CVE in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-the referenced CVE/ | summarize count() by src_ip, dst_host`
- **[H-251d43b3-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the the referenced CVE fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('the referenced CVE')) | summarize coverage = avg(installed) by host_role`
- **[H-251d43b3-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on the affected product hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-251d43b3-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-251d43b3-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on vectors: exploit; impact: fraud.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-251d43b3-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('autocad.py','cut-bytes.py','vir.zip') | summarize count() by client_ip`
- **[H-251d43b3-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-251d43b3-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-251d43b3-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-251d43b3-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-251d43b3-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on vectors: exploit; impact: fraud.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-251d43b3-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-251d43b3-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-251d43b3-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-251d43b3-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 48. Reconstructing AI Agent Activity: Two New Scripts for Forensic Review, (Thu, Oct 8th)

- **Source**: SANS Internet Storm Center
- **Link**: <https://isc.sans.edu/diary/rss/33410>
- **Published**: Thu, 08 Oct 2026 16:52:53 GMT
- **First seen**: 2026-10-08T17:15:04+00:00
- **Relevance score**: 45
- **Score rationale**: source weight (advisory)=+15, 1 initial-access vector(s)=+7, 1 impact action(s)=+8, 13 IOC(s)=+15

> We just did a major update to FOR577 and added a lot of new material on day 5 about investigating AI usage in incident response. In the new material we dicsuss 8&#;x26;#;xc2;&#;x26;#;xa0;of the most popular AI coding assistants and&#;x26;#;xc2;&#;x26;#;xa0;agents including Claude Code, Codex, Gemini CLI, Cursor, Copilot, Warp, Windsurf, and Qwen Code. I&#;x26;#;39;ve been using Claude Code and a little bit of Codex, but I also have recently been playing with OpenCode and am setting up Hermes. I decided to figure out where the chat history was in OpenCode and where any Hermes evidence might be located.

**Extracted signals**
- Vectors: exploit
- Actions: fraud
- Sectors: manufacturing
- Domain IOCs: opencode-chat-replay.py, opencode.db, report.md, chat.json, full-transcript.md, turn.error, turn.id, turn.role, chat.jsonl, auth.json, state.db, evidence.jsonl, isc.sans.edu

### Hypotheses (3)

#### H-0706d8a4-1 · Initial access via the disclosed vulnerability affecting the affected product/service  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting the disclosed vulnerability in the affected product/service within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on vectors: exploit; impact: fraud.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-0706d8a4-1-O1] Inventory exposure to the affected product** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of the affected product, the external-exploitation hypothesis is disproven for the referenced CVE.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'the affected product' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-0706d8a4-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for the referenced CVE in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-the referenced CVE/ | summarize count() by src_ip, dst_host`
- **[H-0706d8a4-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the the referenced CVE fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('the referenced CVE')) | summarize coverage = avg(installed) by host_role`
- **[H-0706d8a4-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on the affected product hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-0706d8a4-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-0706d8a4-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on vectors: exploit; impact: fraud.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-0706d8a4-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('opencode-chat-replay.py','opencode.db','report.md') | summarize count() by client_ip`
- **[H-0706d8a4-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-0706d8a4-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-0706d8a4-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-0706d8a4-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-0706d8a4-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on vectors: exploit; impact: fraud.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-0706d8a4-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-0706d8a4-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-0706d8a4-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-0706d8a4-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 49. Four Compliance Frameworks, One Security Team. How Universities Can Stop Drowning in Regulatory Risk

- **Source**: Rapid7
- **Link**: <https://www.rapid7.com/blog/post/it-compliance-frameworks-for-universities-drowning-in-regulatory-risk>
- **Published**: Wed, 07 Oct 2026 19:29:23 GMT
- **First seen**: 2026-10-07T20:09:47+00:00
- **Relevance score**: 45
- **Score rationale**: source weight (vendor)=+10, 1 MITRE technique hit(s)=+8, 2 initial-access vector(s)=+9, 3 impact action(s)=+14, 1 IOC(s)=+4

> Most industries manage one major compliance framework. Universities might manage four simultaneously, each bringing with it unique requirements, enforcement mechanisms, and consequences for failure. Here's what that actually looks like in practice. In Part 1 of this series, we laid out the scale of the threat facing higher education: 4,388 cyberattacks per organization per week, a 24% year-over-year increase, and the fundamental architectural flaw of defending each campus independently. If the threat picture alone wasn't enough to demand action, there's a second crisis unfolding in parallel that is, if anything, more immediately consequential. The regulatory environment for higher education has quietly become one of the most complex in any sector. Universities don't just face the legal and reputational fallout of a data breach. They face simultaneous obligations under four distinct federal frameworks, each with its own definition of adequate security, its own reporting timelines, and its own set of penalties for non-compliance. Managing those four frameworks across a single campus is hard. Managing them across a multi-campus system where each school operates its own IT environment, with its own tools, its own staff, and its own data governance practices, is a compounding nightmare that most institutions haven't fully reckoned with yet. Let's walk through each framework from the ground-level. FERPA: The 24-hour clock nobody talks about The Family Educational Rights and Privacy

**Extracted signals**
- Vectors: phishing, exploit
- Actions: ransomware, data-breach, fraud
- Sectors: healthcare, finance, government, manufacturing, education
- MITRE ATT&CK: T1486
- Domain IOCs: rapid7.com

### Hypotheses (4)

#### H-9a1c8a79-1 · Initial access via the disclosed vulnerability affecting the affected product/service  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting the disclosed vulnerability in the affected product/service within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on vectors: phishing, exploit; impact: ransomware, data-breach, fraud.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-9a1c8a79-1-O1] Inventory exposure to the affected product** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of the affected product, the external-exploitation hypothesis is disproven for the referenced CVE.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'the affected product' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-9a1c8a79-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for the referenced CVE in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-the referenced CVE/ | summarize count() by src_ip, dst_host`
- **[H-9a1c8a79-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the the referenced CVE fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('the referenced CVE')) | summarize coverage = avg(installed) by host_role`
- **[H-9a1c8a79-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on the affected product hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-9a1c8a79-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-9a1c8a79-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on vectors: phishing, exploit; impact: ransomware, data-breach, fraud.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-9a1c8a79-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('rapid7.com') | summarize count() by client_ip`
- **[H-9a1c8a79-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-9a1c8a79-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-9a1c8a79-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-9a1c8a79-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-9a1c8a79-3 · Post-foothold lateral movement consistent with the reported actor  _(confidence: medium)_

**Statement.** An attacker who matched the TTPs of the reported actor has moved laterally inside the estate using RDP/SMB/WinRM, admin tooling, or Kerberos abuse.

**Why this hypothesis?** Archetype 'lateral_movement' selected based on vectors: phishing, exploit; impact: ransomware, data-breach, fraud.

**MITRE ATT&CK**: T1021.001, T1021.002, T1021.006, T1003

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-9a1c8a79-3-O1] Anomalous remote logons (Type 3 / Type 10)** _(difficulty: medium · 200 pts · MITRE: T1021.001, T1021.002)_
  - Falsification criterion: If 4624 logon-type 3/10 events show no bursts from a single source to many destinations, lateral movement via RDP/SMB is unsupported.
  - Data sources: Windows Security event log, Domain Controller logs
  - Suggested query: `security | where event_id in (4624) and logon_type in (3,10) | summarize dests = dcount(dst_host) by src_user, src_host | where dests > 10`
- **[H-9a1c8a79-3-O2] Admin-tool usage outside baseline** _(difficulty: medium · 200 pts · MITRE: T1021.002, T1021.006, T1059)_
  - Falsification criterion: If PsExec / WMIC / PowerShell remoting / Impacket-style usage is absent outside known admin jump-hosts, the lateral-tool hypothesis is disproven.
  - Data sources: Sysmon EID 1, EDR, 4688
  - Suggested query: `process | where name in ('psexec.exe','psexesvc.exe','wmic.exe','wsmprovhost.exe') and host !in (admin_jumphosts)`
- **[H-9a1c8a79-3-O3] Kerberos abuse telemetry** _(difficulty: hard · 300 pts · MITRE: T1558.003, T1110.003)_
  - Falsification criterion: If 4769 ticket requests show no anomalous RC4 / odd-SPN patterns and no AS-REP roasting indicators, credential-based lateral movement is unsupported.
  - Data sources: Domain Controller security log
  - Suggested query: `security | where event_id == 4769 and ticket_encryption == 'RC4-HMAC' | summarize by target_spn, account_name`
- **[H-9a1c8a79-3-O4] Lateral file-copy staging** _(difficulty: medium · 200 pts · MITRE: T1570, T1021.002)_
  - Falsification criterion: If SMB writes of archives / executables across multiple hosts from one user/host are absent, lateral staging is unsupported.
  - Data sources: File-share auditing (5145), EDR file events
  - Suggested query: `file | where action == 'write' and ext in ('.7z','.rar','.zip','.exe') and dest matches /\\\\.*\\(C\$|admin\$)/`

#### H-9a1c8a79-4 · Data staging and exfiltration to attacker-controlled storage  _(confidence: medium)_

**Statement.** Sensitive data has been staged (archived) and exfiltrated to attacker-controlled endpoints or cloud-storage tenants in the reporting window.

**Why this hypothesis?** Archetype 'exfiltration' selected based on vectors: phishing, exploit; impact: ransomware, data-breach, fraud.

**MITRE ATT&CK**: T1560, T1041, T1567, T1567.002

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-9a1c8a79-4-O1] Cloud-storage exfil to non-corp tenants** _(difficulty: easy · 100 pts · MITRE: T1567.002, T1567)_
  - Falsification criterion: If DLP / proxy show no uploads to mega.nz, anonfiles, transfer.sh, or personal Dropbox/OneDrive tenants, cloud exfil is disproven.
  - Data sources: Proxy logs, CASB / DLP
  - Suggested query: `proxy | where host matches /mega\.nz|anonfiles\.com|transfer\.sh|filebin\.net/ | summarize bytes = sum(bytes_out) by user`
- **[H-9a1c8a79-4-O2] Archive-then-egress pattern** _(difficulty: medium · 250 pts · MITRE: T1560, T1041)_
  - Falsification criterion: If user/host telemetry shows no archive creation (rar/7z) within minutes of a large outbound transfer, the stage-then-exfil pattern is absent.
  - Data sources: EDR process+file events, NetFlow
  - Suggested query: `file_create | where ext in ('.rar','.7z','.zip') | join (egress | where bytes_out > 50MB) on host within 30m`
- **[H-9a1c8a79-4-O3] Outbound volume to rare ASNs** _(difficulty: medium · 200 pts · MITRE: T1041, T1567)_
  - Falsification criterion: If outbound bytes-by-ASN over the last 30 days show no first-seen / low-reputation destination receiving >1GB, bulk exfil is unsupported.
  - Data sources: NetFlow, Firewall logs
  - Suggested query: `netflow | summarize bytes = sum(bytes_out) by asn | where asn !in (corp_known_asns) and bytes > 1GB`
- **[H-9a1c8a79-4-O4] DNS-tunnelling search** _(difficulty: hard · 300 pts · MITRE: T1071.004, T1048.003)_
  - Falsification criterion: If DNS query-length and txt-record distributions show no entropy / volume anomalies per source, DNS-tunnelled exfil is unsupported.
  - Data sources: DNS resolver logs
  - Suggested query: `dns | summarize avg(query_length), p99(query_length), count() by client_ip | where p99 > 200 and count() > 1000`

---

## 50. TTY Logs and the Data it Captures, (Sun, Oct 4th)

- **Source**: SANS Internet Storm Center
- **Link**: <https://isc.sans.edu/diary/rss/33396>
- **Published**: Mon, 05 Oct 2026 00:15:00 GMT
- **First seen**: 2026-10-05T00:40:06+00:00
- **Relevance score**: 45
- **Score rationale**: source weight (advisory)=+15, 1 MITRE technique hit(s)=+8, 1 initial-access vector(s)=+7, 15 IOC(s)=+15

> For an experiment, I created a script [ 1 ] that parses and send the TTY logs collected from actors or bots activity that run various commands after they successfully login the DShield sensor. Those TTY logs are sent daily at the end of each day to the DShield SIEM [ 2 ] to be correlated with all the data.

**Extracted signals**
- Vectors: exploit
- Sectors: manufacturing
- MITRE ATT&CK: T1053
- IP IOCs: 102.88.137.80, 42.96.20.16, 182.253.221.210, 46.188.119.26, 159.223.97.218, 185.158.22.150, 193.233.48.169, 209.99.190.200, 45.64.74.51, 202.152.148.27
- Domain IOCs: transaction.id, event.hash, www.elastic.co, isc.sans.edu
- SHA256: f904275333aeac48d7df6cf53fe5fb9212c7d132a7d37253d2ab9321ba2690d8

### Hypotheses (3)

#### H-34220df6-1 · Initial access via the disclosed vulnerability affecting the affected product/service  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting the disclosed vulnerability in the affected product/service within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on vectors: exploit.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-34220df6-1-O1] Inventory exposure to the affected product** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of the affected product, the external-exploitation hypothesis is disproven for the referenced CVE.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'the affected product' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-34220df6-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for the referenced CVE in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-the referenced CVE/ | summarize count() by src_ip, dst_host`
- **[H-34220df6-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the the referenced CVE fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('the referenced CVE')) | summarize coverage = avg(installed) by host_role`
- **[H-34220df6-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on the affected product hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-34220df6-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-34220df6-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on vectors: exploit.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-34220df6-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('transaction.id','event.hash','www.elastic.co') | summarize count() by client_ip`
- **[H-34220df6-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('102.88.137.80','42.96.20.16','182.253.221.210') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-34220df6-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-34220df6-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-34220df6-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-34220df6-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on vectors: exploit.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-34220df6-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-34220df6-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-34220df6-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-34220df6-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---
