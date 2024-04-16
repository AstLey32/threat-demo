--
-- PostgreSQL database dump
--

-- Dumped from database version 11.2
-- Dumped by pg_dump version 11.2

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: data_source_autoincrease; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.data_source_autoincrease
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.data_source_autoincrease OWNER TO postgres;

SET default_tablespace = '';

SET default_with_oids = false;

--
-- Name: data_source; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.data_source (
    id bigint DEFAULT nextval('public.data_source_autoincrease'::regclass) NOT NULL,
    url character varying(255),
    rule character varying(255),
    poster character varying(255),
    category character varying(255),
    valid boolean
);


ALTER TABLE public.data_source OWNER TO postgres;

--
-- Name: key_words_autoincrease; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.key_words_autoincrease
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.key_words_autoincrease OWNER TO postgres;

--
-- Name: key_words; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.key_words (
    id bigint DEFAULT nextval('public.key_words_autoincrease'::regclass) NOT NULL,
    keywords character varying(255),
    points integer
);


ALTER TABLE public.key_words OWNER TO postgres;

--
-- Name: saved_info_autoincrease; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.saved_info_autoincrease
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.saved_info_autoincrease OWNER TO postgres;

--
-- Name: saved_info; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.saved_info (
    id bigint DEFAULT nextval('public.saved_info_autoincrease'::regclass) NOT NULL,
    title character varying(2048),
    link character varying(2048),
    poster character varying(255),
    category character varying(2048),
    mark character varying(1024),
    savetime date,
    titlecn character varying(2048)
);


ALTER TABLE public.saved_info OWNER TO postgres;

--
-- Name: spring_session; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.spring_session (
    primary_id character(36) NOT NULL,
    session_id character(36) NOT NULL,
    creation_time bigint NOT NULL,
    last_access_time bigint NOT NULL,
    max_inactive_interval integer NOT NULL,
    expiry_time bigint NOT NULL,
    principal_name character varying(100)
);


ALTER TABLE public.spring_session OWNER TO postgres;

--
-- Name: spring_session_attributes; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.spring_session_attributes (
    session_primary_id character(36) NOT NULL,
    attribute_name character varying(200) NOT NULL,
    attribute_bytes bytea NOT NULL
);


ALTER TABLE public.spring_session_attributes OWNER TO postgres;

--
-- Data for Name: data_source; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.data_source (id, url, rule, poster, category, valid) FROM stdin;
1	https://securitylabs.datadoghq.com/	//*[@id="/"]/main/section[1]/div/div/div/div[1]/ul/li[*]$3$2	datadog	news	t
36	https://www.bleepingcomputer.com/feed/	rss	bleepingcomputer	news	t
20	https://www.darkreading.com/rss.xml	rss	darkreading	news	t
41	http://podcast.securityweekly.com	rss	securityweekly	news	t
43	https://blog.drhack.net/feed/	rss	drhack	news	t
44	https://blog.exodusintel.com/	//*[@id="content"]/div/div/div/section[2]/div/div/div[1]/div/div/div[3]/div/div/article[*]$1$3	exodusintel	vuln	t
23	https://www.kitploit.com/feeds/posts/default?alt=rss	rss	kitploit	tool	t
13	https://infosecwriteups.com/feed	rss	infosecwriteups	tech	t
24	https://blog.knowbe4.com/rss.xml	rss	knowbe4	news	t
21	https://gbhackers.com/feed/	rss	GBHacker	news	t
42	https://360.net/about/news/#%E5%AE%89%E5%85%A8%E8%A7%A3%E6%9E%90	//*[contains(@id,'1article')]$1$3	360	news	t
30	https://fetchrss.com/rss/65b0eb775582bd1c19083c4365b0fdb664898a0daa63bef4.xml	rss	wizio	incident	t
37	https://buaq.net/rss.xml	rss	buaq	newscopy	t
38	https://www.freebuf.com/feed	rss	freebuf	news	t
22	https://www.helpnetsecurity.com/feed/	rss	helpnetsecurity	news	t
45	https://breachforums.cx/Forum-Databases	//*[@id="content"]/table[2]/tbody/tr[*]$2$10	breachforum	ransom	f
35	https://www.mandiant.com/resources/blog/rss.xml	rss	mandiant	news	t
19	https://rss.packetstormsecurity.com/files/	rss	packetstorm	vuln	t
11	https://www.microsoft.com/en-us/security/blog/feed/	rss	microsoft	news	t
39	https://xz.aliyun.com/feed	rss	阿里先知实验室	news	t
3	https://xlab.tencent.com/cn/atom.xml	rss	腾讯xlab	news	t
14	https://www.nu11secur1ty.com/feeds/posts/default?alt=rss	rss	nu11security	vuln	t
27	https://www.wired.com/feed/category/security/latest/rss	rss	wired	news	t
34	https://www.breaches.cloud/index.xml	rss	breaches	incident	t
8	https://threatninja.net/feed/	rss	threatninja	sectest	t
25	https://www.mcafee.com/blogs/feed/	rss	mcafee	news	t
17	https://cxsecurity.com/wlb/rss/dorks/	rss	cxsecurity	vuln	t
16	https://cxsecurity.com/wlb/rss/exploit/	rss	cxsecurity	vuln	t
18	https://cxsecurity.com/wlb/rss/vulnerabilities/	rss	cxsecurity	vuln	t
9	https://ransomfeed.it/rss-complete.php	rss	ransomfeed	ransom	t
28	https://www.sentinelone.com/blog/	rss	sentinelone	news	t
32	https://blog.nsfocus.net/feed/	rss	绿盟	news	t
33	https://pentestlab.blog/feed/	rss	pentestlab	tech	t
31	https://www.welivesecurity.com/en/rss/feed/	rss	eset	news	f
12	https://feeds.feedburner.com/TheHackersNews	rss	feedburner	news	t
10	https://therecord.media/feed	rss	therecord	ransom	f
29	https://securelist.com/feed/	rss	securelist	news	t
15	https://securityboulevard.com/feed/	rss	securityboulevard	news	t
6	https://professionalhackers.in/feed/	rss	professionalhackers	tech	f
7	https://paper.seebug.org/rss/	rss	seebug	news	f
48	https://malpedia.caad.fkie.fraunhofer.de/feeds/rss/latest	rss	fraunhofer	incident	t
47	weibo.py	python	sina.weibo	hotsearch	t
\.


--
-- Data for Name: key_words; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.key_words (id, keywords, points) FROM stdin;
1	korea	2
2	russia	2
3	iran	2
4	huawei	5
5	lockbit	1
6	apt	1
7	ransom	1
8	china	3
9	chinese	3
10	darknet	1
11	cve	2
12	漏洞	2
13	恶意软件	1
14	小米	0
15	海思	0
17	字节	0
18	特斯拉	0
19	谷歌	0
20	阿里	0
21	百度	0
22	鸿蒙	0
23	滴滴	0
24	崩了	0
25	拼多多	0
26	华为	0
27	iPhone	0
28	iphone	1
29	android	1
16	荣耀	0
\.


--
-- Data for Name: saved_info; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.saved_info (id, title, link, poster, category, mark, savetime, titlecn) FROM stdin;
17653	CoralRaider Hackers Steals Login Credentials, Financial Data & Social Media Logins	https://gbhackers.com/coralraider-hackers-steal-data/	GBHacker	news;Cyber Attack;Cyber Security News;Malware;computer security;CoralRaider;	1	2024-04-08	Corraider Hackers 偷盗登录证书、财务数据和社会媒体登录
9955	CISA Alerts on Active Exploitation of Flaws in Fortinet, Ivanti, and Nice Products	https://thehackernews.com/2024/03/cisa-alerts-on-active-exploitation-of.html	feedburner	news;	1	2024-03-26	CISA 关于积极利用Fortinet、Ivanti和Nice Products法的警报
17665	FreeBuf 早报 | 美国卫生部警告医院黑客攻击IT服务台；全新恶意软件 JSOutProx 曝光	https://www.freebuf.com/news/397038.html	freebuf	news;资讯;	2	2024-04-07	FreeBuf 早报 | 美国卫生部警告医院黑客攻击IT服务台；全新恶意软件 JSOutProx 曝光
28	Human vs. Non-Human Identity in SaaS	https://thehackernews.com/2024/03/human-vs-non-human-identity-in-saas.html	feedburner	news;	1	2024-03-07	SaaS中的人类与非人类特性
29	Magnet Goblin Hacker Group Leveraging 1-Day Exploits to Deploy Nerbian RAT	https://thehackernews.com/2024/03/magnet-goblin-hacker-group-leveraging-1.html	feedburner	news;	1	2024-03-11	Gignet Goblin Hacker集团利用为期1天的爆破来部署Nerbian RAT
30	Malware Campaign Exploits Popup Builder WordPress Plugin to Infect 3,900+ Sites	https://thehackernews.com/2024/03/malware-campaign-exploits-popup-builder.html	feedburner	news;	1	2024-03-12	WordPress 插件到 3,900 个感染点
32	Microsoft Confirms Russian Hackers Stole Source Code, Some Customer Secrets	https://thehackernews.com/2024/03/microsoft-confirms-russian-hackers.html	feedburner	news;	3	2024-03-09	微软确认俄罗斯黑客商店源代码、一些客户秘密
33	New APT Group 'Lotus Bane' Behind Recent Attacks on Vietnam's Financial Entities	https://thehackernews.com/2024/03/new-apt-group-lotus-bane-behind-recent.html	feedburner	news;	2	2024-03-06	最近对越南金融实体的袭击背后的新APT集团“Lotus Bane”
6	How to Prioritize Cybersecurity Spending: A Risk-Based Strategy for the Highest ROI	https://thehackernews.com/2024/02/why-risk-based-approach-to.html	feedburner	news;	1	2024-02-29	如何将网络安全支出列为优先事项:以风险为基础的最高ROI战略
7	4 Instructive Postmortems on Data Downtime and Loss	https://thehackernews.com/2024/03/4-instructive-postmortems-on-data.html	feedburner	news;	1	2024-03-01	4 关于数据减少和损失的验尸报告
11	Chinese State Hackers Target Tibetans with Supply Chain, Watering Hole Attacks	https://thehackernews.com/2024/03/chinese-state-hackers-target-tibetans.html	feedburner	news;	4	2024-03-07	中华国家黑客以供应链、水洞袭击西藏人为目标
8	A New Way To Manage Your Web Exposure: The Reflectiz Product Explained	https://thehackernews.com/2024/03/a-new-way-to-manage-your-web-exposure.html	feedburner	news;	1	2024-03-06	管理网络曝光的新方式:反思产品解释
10	BianLian Threat Actors Exploiting JetBrains TeamCity Flaws in Ransomware Attacks	https://thehackernews.com/2024/03/bianlian-threat-actors-exploiting.html	feedburner	news;	2	2024-03-11	BianLian威胁行为者 在Ransomware袭击中 利用喷气排队
16	QEMU Emulator Exploited as Tunneling Tool to Breach Company Network	https://thehackernews.com/2024/03/cybercriminals-utilize-qemu-emulator-as.html	feedburner	news;	1	2024-03-08	QEMU 模拟器被利用为违反公司网络的隧道工具
17615	The new features coming in Windows 11 24H2, expected this fall	https://www.bleepingcomputer.com/news/microsoft/the-new-features-coming-in-windows-11-24h2-expected-this-fall/	bleepingcomputer	news;Microsoft;Software;	1	2024-04-07	视窗11 24H2的新功能预计今年秋天
18	Ex-Google Engineer Arrested for Stealing AI Technology Secrets for China	https://thehackernews.com/2024/03/ex-google-engineer-arrested-for.html	feedburner	news;	4	2024-03-07	中国前谷歌工程师因窃盗AI技术机密被捕
10838	Comohotelscom	http://www.ransomfeed.it/index.php?page=post_details&id_post=14019	ransomfeed	ransom;redransomware;	1	2024-03-28	Comohotelscom公司
26	How Cybercriminals are Exploiting India's UPI for Money Laundering Operations	https://thehackernews.com/2024/03/how-cybercriminals-are-exploiting.html	feedburner	news;	1	2024-03-04	网络罪犯如何利用印度的UPI洗钱行动
15	Cybercriminals Using Novel DNS Hijacking Technique for Investment Scams	https://thehackernews.com/2024/03/cybercriminals-using-novel-dns.html	feedburner	news;	1	2024-03-05	利用新DNS劫持技术进行投资垃圾交易的网络罪犯
17	Guide: On-Prem is Dead. Have You Adjusted Your Web DLP Plan?	https://thehackernews.com/2024/03/data-leakage-prevention-in-age-of-cloud.html	feedburner	news;	1	2024-03-11	指南:前期死亡。您调整了您的网络 DLP计划吗 ?
17613	New Windows driver blocks software from changing default web browser	https://www.bleepingcomputer.com/news/microsoft/new-windows-driver-blocks-software-from-changing-default-web-browser/	bleepingcomputer	news;Microsoft;	1	2024-04-07	新建 Windows 驱动器, 将新 Windows 驱动软件从更改默认 Web 浏览器中阻隔
10837	Bendallmednick	http://www.ransomfeed.it/index.php?page=post_details&id_post=14018	ransomfeed	ransom;redransomware;	1	2024-03-28	班达麦尼克Name
17618	Home Depot confirms third-party data breach exposed employee info	https://www.bleepingcomputer.com/news/security/home-depot-confirms-third-party-data-breach-exposed-employee-info/	bleepingcomputer	news;Security;	1	2024-04-07	Home Depot确认第三方数据违约 暴露的员工信息
21	From 500 to 5000 Employees - Securing 3rd Party App-Usage in Mid-Market Companies	https://thehackernews.com/2024/03/from-500-to-5000-employees-securing-3rd.html	feedburner	news;	1	2024-03-04	500 000至5000名雇员 -- -- 保障中市公司第三党App-UP-UP-UP-AF-AF-AF
22	GitHub Rolls Out Default Secret Scanning Push Protection for Public Repositories	https://thehackernews.com/2024/03/github-rolls-out-default-secret.html	feedburner	news;	1	2024-03-01	GitHub Rolls为公共仓库秘密扫描推进保护
24	Hackers Exploit ConnectWise ScreenConnect Flaws to Deploy TODDLERSHARK Malware	https://thehackernews.com/2024/03/hackers-exploit-connectwise.html	feedburner	news;	1	2024-03-05	部署 TODLERSHARK 磁盘
55	通过漫游交换进行隐蔽访问的新型后门 GTPDOOR 分析	https://paper.seebug.org/3126/	seebug	news;威胁情报;	1	2024-03-07	通过漫游交换进行隐蔽访问的新型后门 GTPDOOR 分析
59	网络空间指纹：新型网络犯罪研判的关键路径	https://paper.seebug.org/3130/	seebug	news;威胁情报;	1	2024-03-12	网络空间指纹：新型网络犯罪研判的关键路径
57	拥抱 PHP 之在 crash 中遇见 generator	https://paper.seebug.org/3128/	seebug	news;经验心得;Web安全;	1	2024-03-08	拥抱 PHP 之在 crash 中遇见 generator
58	FORTIGATE 固件分析	https://paper.seebug.org/3129/	seebug	news;安全工具&安全开发;经验心得;	1	2024-03-12	FORTIGATE 固件分析
17686	A Breakthrough Online Privacy Proposal Hits Congress	https://www.wired.com/story/apra-congress-online-privacy-proposal/	wired	news;Politics;Politics / Policy;Security / Privacy;	1	2024-04-07	突破线上隐私建议攻击大会
9961	Malicious NuGet Package Linked to Industrial Espionage Targets Developers	https://thehackernews.com/2024/03/malicious-nuget-package-linked-to.html	feedburner	news;	1	2024-03-26	与工业对视目标开发者链接的恶意 NuGet 软件包
9965	U.S. Charges 7 Chinese Nationals in Major 14-Year Cyber Espionage Operation	https://thehackernews.com/2024/03/us-charges-7-chinese-nationals-in-major.html	feedburner	news;	4	2024-03-26	美国在主要14年网络监视行动中向7名中国国民收费
9966	U.S. Sanctions 3 Cryptocurrency Exchanges for Helping Russia Evade Sanctions	https://thehackernews.com/2024/03/us-sanctions-3-cryptocurrency-exchanges.html	feedburner	news;	3	2024-03-26	美国制裁 3 帮助俄罗斯规避制裁的加密货币兑换
4739	Third-Party ChatGPT Plugins Could Lead to Account Takeovers	https://thehackernews.com/2024/03/third-party-chatgpt-plugins-could-lead.html	feedburner	news;	1	2024-03-15	第三方可导致账户接管的第三方聊天插件
5573	思科修补高严重性 IOS RX 漏洞	https://buaq.net/go-228686.html	buaq	newscopy;	0	2024-03-18	思科修补高严重性 IOS RX 漏洞
5574	绿盟科技2024年合作伙伴大会 | 坚定渠道战略，让合作共赢之路越走越宽广	https://buaq.net/go-228687.html	buaq	newscopy;	0	2024-03-18	绿盟科技2024年合作伙伴大会 | 坚定渠道战略，让合作共赢之路越走越宽广
62	Top 10 web application vulnerabilities in 2021–2023	https://securelist.com/top-10-web-app-vulnerabilities/112144/	securelist	news;Research;Passwords;Security assessment;Security services;SQL injection;Vulnerabilities;Vulnerability Statistics;Web apps;XSS;Cybersecurity;Vulnerabilities and exploits;	1	2024-03-12	2021-2023年10大网络应用脆弱性
69	Introducing Salt Security’s New AI-Powered Knowledge Base Assistant: Pepper!	https://securityboulevard.com/2024/03/introducing-salt-securitys-new-ai-powered-knowledge-base-assistant-pepper/	securityboulevard	news;Security Bloggers Network;	1	2024-03-11	推出盐安全部的新AI授权知识库助理:Pepper!
39	Over 225,000 Compromised ChatGPT Credentials Up for Sale on Dark Web Markets	https://thehackernews.com/2024/03/over-225000-compromised-chatgpt.html	feedburner	news;	1	2024-03-05	超过225,000份在黑暗网络市场上出售的简化的查封和查封证书
40	Phobos Ransomware Aggressively Targeting U.S. Critical Infrastructure	https://thehackernews.com/2024/03/phobos-ransomware-aggressively.html	feedburner	news;	2	2024-03-04	Phoosos Ransomwar 攻击美国关键基础设施
42	Secrets Sensei: Conquering Secrets Management Challenges	https://thehackernews.com/2024/03/secrets-sensei-conquering-secrets.html	feedburner	news;	1	2024-03-08	秘秘先生:对付密秘管理的挑战
43	South Korean Citizen Detained in Russia on Cyber Espionage Charges	https://thehackernews.com/2024/03/south-korean-citizen-detained-in-russia.html	feedburner	news;	5	2024-03-12	南韩公民因网络间谍指控在俄罗斯被拘留
44	Urgent: Apple Issues Critical Updates for Actively Exploited Zero-Day Flaws	https://thehackernews.com/2024/03/urgent-apple-issues-critical-updates.html	feedburner	news;	1	2024-03-06	紧急: 苹果问题 关键更新 积极被利用的零日法律
5879	EFF 反对 TikTok 禁令	https://buaq.net/go-228727.html	buaq	newscopy;	0	2024-03-18	EFF 反对 TikTok 禁令
5880	忆阻器模拟计算能完成复杂任务且能耗更低	https://buaq.net/go-228728.html	buaq	newscopy;	0	2024-03-18	忆阻器模拟计算能完成复杂任务且能耗更低
45	U.S. Charges Iranian Hacker, Offers $10 Million Reward for Capture	https://thehackernews.com/2024/03/us-charges-iranian-hacker-offers-10.html	feedburner	news;	4	2024-03-02	美国指控伊朗黑客, 提供1000万美元的奖赏来抓捕
5881	Weekly Update 391	https://buaq.net/go-228729.html	buaq	newscopy;	0	2024-03-18	《每周更新》第391次
10839	Aluminumtrailercom	http://www.ransomfeed.it/index.php?page=post_details&id_post=14020	ransomfeed	ransom;redransomware;	1	2024-03-28	铝拖轮器
10840	Southcoindustriescom	http://www.ransomfeed.it/index.php?page=post_details&id_post=14021	ransomfeed	ransom;redransomware;	1	2024-03-28	南方工业公司
5882	Email accounts of the International Monetary Fund compromised	https://buaq.net/go-228730.html	buaq	newscopy;	0	2024-03-18	国际货币基金组织的电子邮件帐户
49	Warning: Thread Hijacking Attack Targets IT Networks, Stealing NTLM Hashes	https://thehackernews.com/2024/03/warning-thread-hijacking-attack-targets.html	feedburner	news;	1	2024-03-05	警告:Tread 劫持攻击目标 IT网络 偷窃NTLM Hashes
50	Watch Out for Spoofed Zoom, Skype, Google Meet Sites Delivering Malware	https://thehackernews.com/2024/03/watch-out-for-spoofed-zoom-skype-google.html	feedburner	news;	1	2024-03-07	Watch Out for Spoofed Zoom, Skype, Google Meet Sites Delivering Malware
51	What is Exposure Management and How Does it Differ from ASM?	https://thehackernews.com/2024/03/what-is-exposure-management-and-how.html	feedburner	news;	1	2024-03-05	什么是接触管理? 与ASM有何不同?
52	USB 设备开发：从入门到实践指南（二）	https://paper.seebug.org/3123/	seebug	news;安全工具&安全开发;经验心得;404专栏;	1	2024-02-28	USB 设备开发：从入门到实践指南（二）
54	SolarWinds Security Event Manager AMF 反序列化 RCE (CVE-2024-0692)	https://paper.seebug.org/3125/	seebug	news;Web安全;	3	2024-03-05	SolarWinds Security Event Manager AMF 反序列化 RCE (CVE-2024-0692)
74	Microsoft says Windows 10 21H2 support is ending in June	https://www.bleepingcomputer.com/news/microsoft/microsoft-says-windows-10-21h2-support-is-ending-in-june/	bleepingcomputer	news;Microsoft;	1	2024-03-11	Microsoft says Windows 10 21H2 support is ending in June
9042	InGmbH	http://www.ransomfeed.it/index.php?page=post_details&id_post=13854	ransomfeed	ransom;raworld;	1	2024-03-21	InGmbH
76	Equilend warns employees their data was stolen by ransomware gang	https://www.bleepingcomputer.com/news/security/equilend-warns-employees-their-data-was-stolen-by-ransomware-gang/	bleepingcomputer	news;Security;	2	2024-03-11	向员工发出警告 他们的数据被勒索软件团伙盗走
78	Hackers exploit WordPress plugin flaw to infect 3,300 sites with malware	https://www.bleepingcomputer.com/news/security/hackers-exploit-wordpress-plugin-flaw-to-infect-3-300-sites-with-malware/	bleepingcomputer	news;Security;	1	2024-03-10	黑客利用WordPress插件的瑕疵,
79	Magnet Goblin hackers use 1-day flaws to drop custom Linux malware	https://www.bleepingcomputer.com/news/security/magnet-goblin-hackers-use-1-day-flaws-to-drop-custom-linux-malware/	bleepingcomputer	news;Security;	1	2024-03-09	Gignet Goblin 黑客使用1天的缺陷来减少自定义 Linux 恶意软件
80	Okta says data leaked on hacking forum not from its systems	https://www.bleepingcomputer.com/news/security/okta-says-data-leaked-on-hacking-forum-not-from-its-systems/	bleepingcomputer	news;Security;	1	2024-03-11	Okta说 黑客论坛的数据泄露 而不是来自其系统
81	Over 15,000 hacked Roku accounts sold for 50¢ each to buy hardware	https://www.bleepingcomputer.com/news/security/over-15-000-hacked-roku-accounts-sold-for-50-each-to-buy-hardware/	bleepingcomputer	news;Security;	1	2024-03-11	超过15 000个黑黑黑的罗库账户,每个账户出售50元,购买硬件
82	Researchers expose Microsoft SCCM misconfigs usable in cyberattacks	https://www.bleepingcomputer.com/news/security/researchers-expose-microsoft-sccm-misconfigs-usable-in-cyberattacks/	bleepingcomputer	news;Security;	1	2024-03-11	研究人员揭露微软SCCM错误配置,这些配置可用于网络攻击
10258	polycabcom	http://www.ransomfeed.it/index.php?page=post_details&id_post=13954	ransomfeed	ransom;lockbit3;	1	2024-03-26	复数
84	Tuta Mail adds new quantum-resistant encryption to protect email	https://www.bleepingcomputer.com/news/security/tuta-mail-adds-new-quantum-resistant-encryption-to-protect-email/	bleepingcomputer	news;Security;Software;	1	2024-03-11	Tuta Mail 添加新的抗量子加密来保护电子邮件
10259	SummerFresh	http://www.ransomfeed.it/index.php?page=post_details&id_post=13955	ransomfeed	ransom;qilin;	1	2024-03-26	夏夏法国
87	Stealth Bomber: Atlassian Confluence Exploits Drop Web Shells In-Memory	https://www.darkreading.com/application-security/stealth-bomber-atlassian-confluence-exploits-drop-web-shells-in-memory	darkreading	news;	1	2024-03-08	隐形轰炸机:阿特拉斯集成爆炸投射网壳
88	The Challenges of AI Security Begin With Defining It	https://www.darkreading.com/application-security/the-challenges-of-ai-security-begin-with-defining-it	darkreading	news;	1	2024-03-05	AI " 安全从定义安全开始 " 的挑战
89	Cloud-y Linux Malware Rains on Apache, Docker, Redis &amp; Confluence	https://www.darkreading.com/cloud-security/cloud-y-linux-malware-rains-apache-docker-redis-confluence	darkreading	news;	1	2024-03-06	阿帕奇、多克、雷迪斯等地的恶意雨
90	Linux Variants of Bifrost Trojan Evade Detection via Typosquatting	https://www.darkreading.com/cloud-security/stealthy-bifrost-rat-linux-variants-use-typosquatting-to-evade-detection-	darkreading	news;	1	2024-03-07	通过Typosqutting探测的Bifrost Trojan Evade的Linux 变式
9968	Exploiting the libwebp Vulnerability, Part 1： Playing with Huffman Code	https://paper.seebug.org/3135/	seebug	news;经验心得;	1	2024-03-26	利用libwebp脆弱性,第一部分:利用Huffman守则
91	Veeam Launches Veeam Data Cloud	https://www.darkreading.com/cloud-security/veeam-launches-veeam-data-cloud	darkreading	news;	1	2024-03-06	Veeam 发射Veeam Veeam数据云
93	Army Vet Spills National Secrets to Fake Ukrainian Girlfriend	https://www.darkreading.com/cyber-risk/air-force-employee-shares-classified-info-via-dating-app-charged-with-conspiracy	darkreading	news;	1	2024-03-05	假冒乌克兰女友的国家机密
94	Anti-Fraud Project Boosts Security of African, Asian Financial Systems	https://www.darkreading.com/cyber-risk/anti-fraud-project-boosts-security-of-african-asian-financial-systems	darkreading	news;	1	2024-03-11	非洲、亚洲金融系统反欺诈项目促进非洲、亚洲金融系统安全
96	Cyber Insurance Strategy Requires CISO-CFO Collaboration	https://www.darkreading.com/cyber-risk/cyber-insurance-strategy-requires-ciso-cfo-collaboration	darkreading	news;	1	2024-03-07	网络保险战略要求CISO-CFO协作
97	Google's Gemini AI Vulnerable to Content Manipulation	https://www.darkreading.com/cyber-risk/google-gemini-vulnerable-to-content-manipulation-researchers-say	darkreading	news;	1	2024-03-12	Google的Gemini的Gemini AI 易被内容操纵
17706	9 Best Practices for Using AWS Access Analyzer	https://securityboulevard.com/2024/04/9-best-practices-for-using-aws-access-analyzer/	securityboulevard	news;Security Bloggers Network;articles;	1	2024-04-07	9 使用AWS获取分析器的最佳做法
9040	Ranzijn	http://www.ransomfeed.it/index.php?page=post_details&id_post=13852	ransomfeed	ransom;raworld;	1	2024-03-21	兰津
71	The Rise of AI Worms in Cybersecurity	https://securityboulevard.com/2024/03/the-rise-of-ai-worms-in-cybersecurity/	securityboulevard	news;Security Bloggers Network;Threats & Breaches;cyber attacks;Cyber Security;	1	2024-03-12	AI虫子在网络安全中的崛起
73	YouTube stops recommending videos when signed out of Google	https://www.bleepingcomputer.com/news/google/youtube-stops-recommending-videos-when-signed-out-of-google/	bleepingcomputer	news;Google;Software;	1	2024-03-10	在Google上签名后,
17690	Chinese hackers are using AI to inflame social tensions in US, Microsoft says	https://therecord.media/china-ai-influence-operations	therecord	ransom;China;Government;Elections;Nation-state;News;	4	2024-04-08	微软指出,
9041	SHORTERM-GROUP	http://www.ransomfeed.it/index.php?page=post_details&id_post=13853	ransomfeed	ransom;raworld;	1	2024-03-21	贫民窟
104	Ivanti Breach Prompts CISA to Take Systems Offline	https://www.darkreading.com/cyberattacks-data-breaches/ivanti-breach-cisa-systems-offline	darkreading	news;	1	2024-03-11	伊万蒂·伊凡蒂(Ivanti)
121	Sophisticated Vishing Campaigns Take World by Storm	https://www.darkreading.com/endpoint-security/sophisticated-vishing-campaigns-take-world-by-storm	darkreading	news;	1	2024-03-11	由暴风雨带回世界
126	'The Weirdest Trend in Cybersecurity': Nation-States Returning to USBs	https://www.darkreading.com/ics-ot-security/weirdest-trend-cybersecurity-nation-states-usb	darkreading	news;	1	2024-03-07	“网络安全中最奇特的趋势 ” : 回到USB的民族国家
110	Broke Cyber Pros Flock to Cybercrime Side Hustles	https://www.darkreading.com/cybersecurity-operations/broke-cyber-pros-cybercrime-side-hustles	darkreading	news;	1	2024-03-08	打破网络网络赛事Pros Flock 进入网络犯罪侧的外观
112	CISO Corner: NSA Guidelines; a Utility SBOM Case Study; Lava Lamps	https://www.darkreading.com/cybersecurity-operations/ciso-corner-nsa-guidelines-utility-sbom-case-study-lava-lamps	darkreading	news;	1	2024-03-08	CISO角:国安局准则;公用事业SBOM案例研究;Lava灯光
114	CISO Sixth Sense: NIST CSF 2.0's Govern Function	https://www.darkreading.com/cybersecurity-operations/ciso-sixth-sense-nist-csf-2-govern-function	darkreading	news;	1	2024-03-07	CISO 第六感:NIST CCSF 2. 0 的 Govern 函数
122	Network Perception Introduces Rapid Verification of Zone-to-Zone Segmentation	https://www.darkreading.com/ics-ot-security/network-perception-introduces-rapid-verification-of-zone-to-zone-segmentation	darkreading	news;	1	2024-03-05	网络感知引入区对区分割的快速核查
17708	Conn. CISO Raises Security Concerns Over BadGPT, FraudGPT	https://securityboulevard.com/2024/04/conn-ciso-raises-security-concerns-over-badgpt-fraudgpt/	securityboulevard	news;Security Bloggers Network;	1	2024-04-07	CISO Conn. CISO 对BadGPT、欺诈GPT提出安全问题
129	North Korea Hits ScreenConnect Bugs to Drop 'ToddleShark' Malware	https://www.darkreading.com/remote-workforce/north-korea-screenconnect-bugs-toddleshark-malware	darkreading	news;	3	2024-03-05	朝鲜用屏幕连接错误来丢弃“ TodddleShark ” 错误
120	Predator Spyware Operators Slapped With US Sanctions	https://www.darkreading.com/endpoint-security/global-commercial-spyware-operators-sanctioned-by-us	darkreading	news;	1	2024-03-05	被美国制裁的捕食者 Spyware 操作员
108	The Rise of Social Engineering Fraud in Business Email Compromise	https://www.darkreading.com/cyberattacks-data-breaches/the-rise-of-social-engineering-fraud-in-business-email-compromise	darkreading	news;	1	2024-03-06	商业电子邮件中社会工程欺诈的兴起
116	How Not to Become the Target of the Next Microsoft Hack	https://www.darkreading.com/cybersecurity-operations/how-not-to-become-target-of-next-microsoft-hack	darkreading	news;	1	2024-03-11	如何不成为下一个微软黑客的目标
127	Google Engineer Steals AI Trade Secrets for Chinese Companies	https://www.darkreading.com/insider-threats/google-engineer-steals-ai-trade-secrets-chinese-companies	darkreading	news;	4	2024-03-08	Google Engle Estestesteings AI 中国公司贸易秘密
106	Russia-Sponsored Cyberattackers Infiltrate Microsoft's Code Base	https://www.darkreading.com/cyberattacks-data-breaches/russia-sponsored-cyberattackers-infiltrate-microsoft-s-code-base	darkreading	news;	3	2024-03-08	俄罗斯赞助的网络攻击者 侵入微软的代码基地
123	The Ongoing Struggle to Protect PLCs	https://www.darkreading.com/ics-ot-security/ongoing-struggle-to-protect-plcs	darkreading	news;	1	2024-03-08	为保护PLCs正在进行的斗争
9970	Cloud-based DCIM Software Powers Modern Data Center Operations	https://securityboulevard.com/2024/03/cloud-based-dcim-software-powers-modern-data-center-operations/	securityboulevard	news;Security Bloggers Network;DCIM Tools;	1	2024-03-26	现代数据中心业务
10260	El-Debate	http://www.ransomfeed.it/index.php?page=post_details&id_post=13956	ransomfeed	ransom;rhysida;	1	2024-03-26	El- 减试
10261	nampakcom	http://www.ransomfeed.it/index.php?page=post_details&id_post=13957	ransomfeed	ransom;lockbit3;	1	2024-03-27	楠巴康
10262	NHS-Scotland	http://www.ransomfeed.it/index.php?page=post_details&id_post=13958	ransomfeed	ransom;incransom;	1	2024-03-27	NHS - 苏格兰
3608	Critical FortiClient EMS vulnerability fixed, (fake?) PoC for sale (CVE-2023-48788)	https://www.helpnetsecurity.com/2024/03/14/cve-2023-48788-poc/	helpnetsecurity	news;Don't miss;Hot stuff;News;endpoint management;Fortinet;Horizon3.ai;PoC;SANS ISC;vulnerability;	3	2024-03-14	确定(假?)用于销售的poC(CVE-2023-48788)
107	Spoofed Zoom, Google &amp; Skype Meetings Spread Corporate RATs	https://www.darkreading.com/cyberattacks-data-breaches/spoofed-zoom-google-skype-meetings-spread-corporate-rats	darkreading	news;	1	2024-03-06	Spooofed Zom, 谷歌
8723	Kaspersky Identifies Three New Android Malware Threats	https://www.darkreading.com/endpoint-security/kaspersky-identifies-three-new-android-malware-threats	darkreading	news;	2	2024-03-20	Kaspersky 识别三个新机器人的马拉威威胁
128	Creating Security Through Randomness	https://www.darkreading.com/remote-workforce/creating-security-through-randomness	darkreading	news;	1	2024-03-08	通过随机创建安全
111	How CISA Fights Cyber Threats During Election Primary Season	https://www.darkreading.com/cybersecurity-operations/cisa-fights-cyber-threats-election-primary-season	darkreading	news;	1	2024-03-07	CISA 在选举第一季期间如何对抗网络威胁
113	The CISO Role Is Changing. Can CISOs Themselves Keep Up?	https://www.darkreading.com/cybersecurity-operations/ciso-role-changing-can-cisos-keep-up	darkreading	news;	1	2024-03-11	CISO 角色正在改变 CISO 能够保持自我吗?
117	IT-Harvest Reaches Milestone With Ingestion of 10K Cybersecurity Products Into Dashboard	https://www.darkreading.com/cybersecurity-operations/it-harvest-reaches-milestone-with-ingestion-of-10k-cybersecurity-products-into-dashboard	darkreading	news;	1	2024-03-11	将10K网络安全产品摄入10K个网络安全产品进入仪表板
124	Patch Now: Apple Zero-Day Exploits Bypass Kernel Security	https://www.darkreading.com/ics-ot-security/patch-now-apple-zero-day-exploits-bypass-kernel-security	darkreading	news;	1	2024-03-06	现在的补丁: 苹果零日爆破绕过核心安全
130	NSA's Zero-Trust Guidelines Focus on Segmentation	https://www.darkreading.com/remote-workforce/nsa-s-zero-trust-guidelines-focus-on-segmentation	darkreading	news;	1	2024-03-08	消极安全保证零信任准则
157	数智化研发安全体系建设“秘籍” | FreeBuf 企业安全俱乐部·广州站议题前瞻	https://www.freebuf.com/fevents/393650.html	freebuf	news;活动;	1	2024-03-07	数智化研发安全体系建设“秘籍” | FreeBuf 企业安全俱乐部·广州站议题前瞻
13	Cisco Issues Patch for High-Severity VPN Hijacking Bug in Secure Client	https://thehackernews.com/2024/03/cisco-issues-patch-for-high-severity.html	feedburner	news;	1	2024-03-08	安全客户端中高强度 VPN VPN 劫持错误的 Cisco 问题补丁
160	Play 勒索软件泄露了6.5 万份瑞士政府机密文件	https://www.freebuf.com/news/393783.html	freebuf	news;资讯;	1	2024-03-08	Play 勒索软件泄露了6.5 万份瑞士政府机密文件
162	这个超火的黑客小工具，可以通过WiFi解锁特斯拉	https://www.freebuf.com/news/393813.html	freebuf	news;资讯;	1	2024-03-08	这个超火的黑客小工具，可以通过WiFi解锁特斯拉
161	WogRAT 恶意软件用记事本服务攻击 Windows 和 Linux 系统	https://www.freebuf.com/news/393800.html	freebuf	news;资讯;	2	2024-03-08	WogRAT 恶意软件用记事本服务攻击 Windows 和 Linux 系统
9984	Finland confirms APT31 hackers behind 2021 parliament breach	https://www.bleepingcomputer.com/news/security/finland-confirms-apt31-hackers-behind-2021-parliament-breach/	bleepingcomputer	news;Security;	2	2024-03-26	芬兰确认,APT31黑客在2021年议会违约后
166	新型钓鱼活动激增，Dropbox被大规模利用	https://www.freebuf.com/news/393909.html	freebuf	news;资讯;	1	2024-03-11	新型钓鱼活动激增，Dropbox被大规模利用
167	禁止支付赎金，然后呢？	https://www.freebuf.com/news/393921.html	freebuf	news;资讯;	1	2024-03-11	禁止支付赎金，然后呢？
168	遭俄APT组织暴力攻击，微软部分源代码和机密信息泄露	https://www.freebuf.com/news/393940.html	freebuf	news;资讯;	2	2024-03-11	遭俄APT组织暴力攻击，微软部分源代码和机密信息泄露
170	法国多个政府机构遭受”猛烈“的网络攻击	https://www.freebuf.com/news/394067.html	freebuf	news;资讯;	1	2024-03-12	法国多个政府机构遭受”猛烈“的网络攻击
136	Chicago Man Sentenced to Eight Years in Prison for Phishing Scheme	https://blog.knowbe4.com/chicago-man-sentenced-to-eight-years-for-phishing-scheme	knowbe4	news;Social Engineering;Phishing;Security Awareness Training;Security Culture;	1	2024-03-06	芝加哥人因钓鱼计划被判处8年监禁
137	Customer Spotlight: MESA’s Strategy for Building Strong Security Culture and Email Defense	https://blog.knowbe4.com/customer-spotlight-mesa	knowbe4	news;KnowBe4;Security Culture;	1	2024-03-07	客户焦点:欧空局的加强安全文化和电子邮件防御战略
138	CyberheistNews Vol 14 #10 [SCARY] You Knew About OSINT, But Did You Know About ADINT?	https://blog.knowbe4.com/cyberheistnews-vol-14-10-scary-you-knew-about-osint-but-did-you-know-about-adint	knowbe4	news;Cybercrime;KnowBe4;	1	2024-03-05	网络新闻第14卷
139	New Research: Spike In DNS Queries Driving Phishing and Cyber Attacks	https://blog.knowbe4.com/day-old-domains-spikes-showing-malicious-activity	knowbe4	news;Phishing;Security Awareness Training;Security Culture;	1	2024-03-06	新研究:Spike in DNS 询问钓鱼和网络攻击
140	European Diplomats Targeted With Phony Invitations to a Wine-Tasting Party	https://blog.knowbe4.com/european-diplomats-targeted-by-phony-invitations-wine-tasting-party	knowbe4	news;Social Engineering;Security Culture;	1	2024-03-07	欧洲外交官被邀请到一个饮酒旅游党
141	The European Union's Unified Approach to Cybersecurity: The Cyber Solidarity Act	https://blog.knowbe4.com/european-unions-cyber-solidarity-act	knowbe4	news;Security Awareness Training;Cybersecurity;	1	2024-03-11	欧洲联盟的网络安全统一办法:网络团结法
143	Microsoft and OpenAI Team Up to Block Threat Actor Access to AI	https://blog.knowbe4.com/microsoft-openai-team-block-threat-actor	knowbe4	news;Phishing;Spear Phishing;Security Culture;	1	2024-03-05	微软和OpenAI 阻止威胁行为者接触AI小组
144	Three Essential Truths Every CISO Should Know To Guide Their Career	https://blog.knowbe4.com/three-essential-truths-every-ciso-should-know	knowbe4	news;Social Engineering;MFA;	1	2024-03-11	每个加拿大公民公民组织都应该知道指导其职业生涯的三个基本真理
145	Viamedis breach	https://threats.wiz.io/2e3bcaf9bd3f447fa843489efbb566bf	wizio	incident;	1	2024-03-05	违反维亚米蒂斯
146	Almerys breach	https://threats.wiz.io/5180b7e5d6c544b19b14ea6fefec5f6b	wizio	incident;	1	2024-03-05	损用平利器
10841	Kogokcom	http://www.ransomfeed.it/index.php?page=post_details&id_post=14022	ransomfeed	ransom;redransomware;	1	2024-03-28	科哥康
147	C3Pool mining via Confluence vulnerability	https://threats.wiz.io/all-incidents/c3pool-mining-via-confluence-vulnerability	wizio	incident;	1	2024-03-05	C3 通过多重脆弱性进行C3Pool采矿
10842	Baystateedu	http://www.ransomfeed.it/index.php?page=post_details&id_post=14023	ransomfeed	ransom;redransomware;	1	2024-03-28	Baystateedu 湾
149	From social engineering to cryptocurrency theft	https://threats.wiz.io/all-incidents/from-social-engineering-to-cryptocurrency-theft	wizio	incident;	1	2024-03-07	从社会工程到密码货币盗窃
150	Magnet Goblin campaign (2024)	https://threats.wiz.io/all-incidents/magnet-goblin-campaign-2024	wizio	incident;	1	2024-03-10	Gignet Goblin运动(2024年)
151	Malware Campaign Targeting Misconfigured Servers	https://threats.wiz.io/all-incidents/malware-campaign-targeting-misconfigured-servers	wizio	incident;	1	2024-03-07	针对错误配置服务器的恶意运动
152	Sliver deployment via Confluence vulnerability	https://threats.wiz.io/all-incidents/sliver-deployment-via-confluence-vulnerability	wizio	incident;	1	2024-03-05	通过 " 多重脆弱性 " 进行部署
153	z0Miner Targeting WebLogic Servers	https://threats.wiz.io/all-incidents/z0miner-targeting-weblogic-servers	wizio	incident;	1	2024-03-07	zz0Miner 瞄准 WebLogic 服务器
154	如何保护你的个人信息不被黑客攻击	https://www.freebuf.com/articles/paper/393879.html	freebuf	news;安全报告;	1	2024-03-10	如何保护你的个人信息不被黑客攻击
156	SharkTeam：Woo Finance被攻击事件分析	https://www.freebuf.com/articles/web/393717.html	freebuf	news;Web安全;	1	2024-03-07	SharkTeam：Woo Finance被攻击事件分析
193	How we’re #InspiringInclusion at McAfee for International Women’s Day 2024	https://www.mcafee.com/blogs/other-blogs/life-at-mcafee/how-were-inspiringinclusion-at-mcafee-for-international-womens-day-2024/	mcafee	news;Life at McAfee;International Women's Day;life at mcafee;careers;	1	2024-03-08	我们如何
194	GUloader Unmasked: Decrypting the Threat of Malicious SVG Files	https://www.mcafee.com/blogs/other-blogs/mcafee-labs/guloader-unmasked-decrypting-the-threat-of-malicious-svg-files/	mcafee	news;McAfee Labs;	1	2024-02-29	GUloader 无面具: 解密恶意 SVG 文件的威胁
195	Rise in Deceptive PDF: The Gateway to Malicious Payloads	https://www.mcafee.com/blogs/other-blogs/mcafee-labs/rise-in-deceptive-pdf-the-gateway-to-malicious-payloads/	mcafee	news;McAfee Labs;	1	2024-03-01	欺骗性PDF的崛起:恶意有效载荷的通道
196	How to Protect Yourself Against Tax Scams	https://www.mcafee.com/blogs/privacy-identity-protection/how-to-protect-yourself-against-tax-scams/	mcafee	news;Privacy & Identity Protection;tax season;tax scam;taxes;	1	2024-03-04	如何保护自己免受税收垃圾邮件的影响
192	From Military Kid to Product Marketing: My McAfee Journey	https://www.mcafee.com/blogs/other-blogs/life-at-mcafee/from-military-kid-to-product-marketing-my-mcafee-journey/	mcafee	news;Life at McAfee;	1	2024-02-28	《从军事儿童到产品销售:我的麦卡菲旅程》
172	意大利数据监管机构对Sora展开调查	https://www.freebuf.com/news/394077.html	freebuf	news;资讯;	1	2024-03-12	意大利数据监管机构对Sora展开调查
173	红队实战小课，快来涨经验|Webshell下bypass360	https://www.freebuf.com/news/394133.html	freebuf	news;资讯;	1	2024-03-12	红队实战小课，快来涨经验|Webshell下bypass360
175	Microsoft: Russian hackers accessed internal systems, code repositories	https://www.helpnetsecurity.com/2024/03/11/microsoft-russian-hackers-srouce-code/	helpnetsecurity	news;Don't miss;Hot stuff;News;account hijacking;APT;brute-force;government-backed attacks;IBM X-Force;Microsoft;	3	2024-03-11	微软:俄罗斯黑客进入内部系统、代码储存库
56	CVE-2023-3824 幸运的 Off-by-one	https://paper.seebug.org/3127/	seebug	news;漏洞分析;经验心得;	3	2024-03-07	CVE-2023-3824 幸运的 Off-by-one
177	AuditBoard unveils AI, analytics, and annotation capabilities to deliver more timely insights	https://www.helpnetsecurity.com/2024/03/12/auditboard-ai/	helpnetsecurity	news;Industry news;AuditBoard;	1	2024-03-12	审计 Board 披露AI、分析和说明能力,以提供更及时的真知灼见
185	Cookie Theft: How to Keep Cybercriminals Out of Your Accounts	https://www.mcafee.com/blogs/internet-security/cookie-theft-how-to-keep-cybercriminals-out-of-your-accounts/	mcafee	news;Internet Security;	1	2024-03-05	Cookie Top: 如何将网络罪犯排除在你的账户之外
67	Enable Sharing of Datamodel Acceleration Summaries between Search Heads	https://securityboulevard.com/2024/03/enable-sharing-of-datamodel-acceleration-summaries-between-search-heads/	securityboulevard	news;Security Bloggers Network;Splunk Tutorials;	1	2024-03-12	使搜索负责人之间能够分享数据模型加速摘要
179	Cybersecurity jobs available right now: March 12, 2024	https://www.helpnetsecurity.com/2024/03/12/cybersecurity-jobs-available-right-now-march-12-2024/	helpnetsecurity	news;Don't miss;Hot stuff;News;cybersecurity jobs;	1	2024-03-12	2024年3月12日 2024年3月12日
180	Image-based phishing tactics evolve	https://www.helpnetsecurity.com/2024/03/12/image-based-phishing-attacks/	helpnetsecurity	news;News;cybercrime;cybersecurity;email security;Ironscales;Osterman Research;phishing;QR codes;report;survey;	1	2024-03-12	以图像为基础的钓鱼策略演化
182	How organizations can keep up with shifting data privacy regulations	https://www.helpnetsecurity.com/2024/03/12/shifting-data-privacy-regulations-video/	helpnetsecurity	news;Don't miss;Hot stuff;Video;compliance;cybersecurity;data;digital transformation;encryption;key management;privacy;regulation;Thales;video;	1	2024-03-12	各组织如何跟上不断变化的数据隐私条例
183	Tax-related scams escalate as filing deadline approaches	https://www.helpnetsecurity.com/2024/03/12/tax-scams/	helpnetsecurity	news;Don't miss;Hot stuff;News;Cisco;fraud;identity theft;IRS;Malwarebytes;scams;tax e-filing;trends;USA;Webroot;	1	2024-03-12	随着提交期限的临近,与税收有关的骗局升级
184	Delving into Dalvik: A Look Into DEX Files	https://www.mandiant.com/resources/blog/dalvik-look-into-dex-files	mandiant	news;	1	2024-03-06	切切到 Dalvik: 查看 DEX 文件
17642	GDBFuzz - Fuzzing Embedded Systems Using Hardware Breakpoints	http://www.kitploit.com/2024/04/gdbfuzz-fuzzing-embedded-systems-using.html	kitploit	tool;Embedded;Gdbfuzz;Visualization;Websockets;Wrapper;	1	2024-04-07	GDBFuzz - 使用硬件断点模糊嵌入系统
188	The What, Why, and How of AI and Threat Detection	https://www.mcafee.com/blogs/internet-security/the-what-why-and-how-of-ai-and-threat-detection/	mcafee	news;Internet Security;Privacy & Identity Protection;AI;AI cybersecurity;	1	2024-03-07	人工智能和威胁侦测的什么、为什么和如何
189	What are Pig Butchering Scams and How Do They Work?	https://www.mcafee.com/blogs/internet-security/what-are-pig-butchering-scams-and-how-do-they-work/	mcafee	news;Internet Security;	1	2024-03-08	什么是猪肉屠宰场 如何运作?
190	What is Sora and What Does It Mean for Your Personal Internet Security?	https://www.mcafee.com/blogs/internet-security/what-is-sora-and-what-does-it-mean-for-your-personal-internet-security/	mcafee	news;Internet Security;	1	2024-02-27	Sora是什么? 它对你个人互联网安全意味着什么?
191	Get Yourself AI-powered Scam Protection That Spots and Block Scams in Real Time	https://www.mcafee.com/blogs/mcafee-news/get-yourself-ai-powered-scam-protection-that-spots-and-block-scams-in-real-time/	mcafee	news;McAfee News;McAfee;artificial intelligence;	1	2024-02-28	获取您自己的 AI 动力的 Scam 保护, 在实时点和屏蔽 Scams 屏蔽
9090	How Microsoft Incident Response and Microsoft Defender for Identity work together to detect and respond to cyberthreats	https://www.microsoft.com/en-us/security/blog/2024/03/21/how-microsoft-incident-response-and-microsoft-defender-for-identity-work-together-to-detect-and-respond-to-cyberthreats/	microsoft	news;	1	2024-03-21	微微微微微微微微微微微微微微软事件反应和微微微微事件事件反应和身份身份维护者如何共同努力发现和应对网络威胁
226	智能合约安全之业务逻辑缺陷介绍	https://xz.aliyun.com/t/13956	阿里先知实验室	news;	1	2024-02-29	智能合约安全之业务逻辑缺陷介绍
227	USB Flash闪存驱动器安全分析（第一部分）	https://xz.aliyun.com/t/13957	阿里先知实验室	news;	1	2024-02-29	USB Flash闪存驱动器安全分析（第一部分）
228	最新Ruoyi组合拳RCE分析	https://xz.aliyun.com/t/13958	阿里先知实验室	news;	1	2024-02-29	最新Ruoyi组合拳RCE分析
229	逆向WiFi驱动板 RISC-V BL602	https://xz.aliyun.com/t/13959	阿里先知实验室	news;	1	2024-02-29	逆向WiFi驱动板 RISC-V BL602
230	漏洞挖掘中的组合拳攻击	https://xz.aliyun.com/t/13960	阿里先知实验室	news;	3	2024-02-29	漏洞挖掘中的组合拳攻击
231	针对以哈网络战Wiper攻击武器的详细分析	https://xz.aliyun.com/t/13961	阿里先知实验室	news;	1	2024-02-29	针对以哈网络战Wiper攻击武器的详细分析
232	PHP代码审计-某0Day分析	https://xz.aliyun.com/t/13969	阿里先知实验室	news;	1	2024-02-29	PHP代码审计-某0Day分析
233	IOT安全-固件提取	https://xz.aliyun.com/t/13970	阿里先知实验室	news;	1	2024-02-29	IOT安全-固件提取
235	一款Bitter组织使用的手机远控木马分析	https://xz.aliyun.com/t/13976	阿里先知实验室	news;	1	2024-03-01	一款Bitter组织使用的手机远控木马分析
236	APT组织“蔓灵花“RPC”后门武器样本逆向分析	https://xz.aliyun.com/t/13977	阿里先知实验室	news;	2	2024-03-01	APT组织“蔓灵花“RPC”后门武器样本逆向分析
238	Apache DolphinScheduler auth RCE（CVE-2023-49299&CVE-2024-23320&CVE-2023-49109）	https://xz.aliyun.com/t/13981	阿里先知实验室	news;	3	2024-03-01	Apache DolphinScheduler RCE(CVE-2023-49299) (CVE-2023-49299)
239	记某模版菠菜管理后台登录思路	https://xz.aliyun.com/t/13984	阿里先知实验室	news;	1	2024-03-01	记某模版菠菜管理后台登录思路
2	GTPDOOR Linux Malware Targets Telecoms, Exploiting GPRS Roaming Networks	https://thehackernews.com/2024/02/gtpdoor-linux-malware-targets-telecoms.html	feedburner	news;	1	2024-02-29	GTPDOOR Linux 恶意目标电信,利用GPRS旋转网络
4745	Patch Tuesday Update – March 2024	https://securityboulevard.com/2024/03/patch-tuesday-update-march-2024-2/	securityboulevard	news;Security Bloggers Network;security posture;	1	2024-03-15	2024年3月的更新 - 2024年3月
240	从CTF中学习多媒体安全	https://xz.aliyun.com/t/13985	阿里先知实验室	news;	1	2024-03-01	从CTF中学习多媒体安全
242	apache-cayenne代码审计	https://xz.aliyun.com/t/13990	阿里先知实验室	news;	1	2024-03-01	apache-cayenne代码审计
243	应急响应-隧道篇	https://xz.aliyun.com/t/13991	阿里先知实验室	news;	1	2024-03-01	应急响应-隧道篇
99	Why Criminals Like AI for Synthetic Identity Fraud	https://www.darkreading.com/cyber-risk/why-criminals-like-ai-for-synthetic-identity-fraud	darkreading	news;	1	2024-03-05	为什么像合成身份欺诈的大赦国际这样的罪犯
204	Zig语言免杀探索	https://xz.aliyun.com/t/13902	阿里先知实验室	news;	1	2024-02-28	Zig语言免杀探索
205	Atlassian Confluence CVE-2023-22527 分析及武器化实现	https://xz.aliyun.com/t/13907	阿里先知实验室	news;	3	2024-02-28	Atlassian Confluence CVE-2023-22527 分析及武器化实现
206	Oracle 注入 RCE 由浅入深	https://xz.aliyun.com/t/13908	阿里先知实验室	news;	1	2024-02-28	Oracle 注入 RCE 由浅入深
207	Remote Code Execution in Apache Dolphinscheduler(CVE-2023-49109)	https://xz.aliyun.com/t/13913	阿里先知实验室	news;	3	2024-02-28	Apache Dolphincheduler(CVE-2023-49109)的远程代码执行
209	RSA系列解题研究——e与phi不互素	https://xz.aliyun.com/t/13917	阿里先知实验室	news;	1	2024-02-28	RSA系列解题研究——e与phi不互素
208	浅谈白盒下命令执行与注入绕过的挖掘	https://xz.aliyun.com/t/13915	阿里先知实验室	news;	1	2024-02-28	浅谈白盒下命令执行与注入绕过的挖掘
10843	Tecnolitecom	http://www.ransomfeed.it/index.php?page=post_details&id_post=14024	ransomfeed	ransom;redransomware;	1	2024-03-28	铁石棉
10844	Solucioneslscom	http://www.ransomfeed.it/index.php?page=post_details&id_post=14025	ransomfeed	ransom;redransomware;	1	2024-03-28	社会委员会
210	内网不出网上线学习研究	https://xz.aliyun.com/t/13918	阿里先知实验室	news;	1	2024-02-28	内网不出网上线学习研究
212	Donut生成的shellcode免杀	https://xz.aliyun.com/t/13920	阿里先知实验室	news;	1	2024-02-28	Donut生成的shellcode免杀
214	某导航站系统代码审计	https://xz.aliyun.com/t/13923	阿里先知实验室	news;	1	2024-02-28	某导航站系统代码审计
215	Windows下的ASLR保护机制详解及其绕过	https://xz.aliyun.com/t/13924	阿里先知实验室	news;	1	2024-02-28	Windows下的ASLR保护机制详解及其绕过
216	「车联网安全」OBD（汽车诊断插头）与CAN报文	https://xz.aliyun.com/t/13925	阿里先知实验室	news;	1	2024-02-28	「车联网安全」OBD（汽车诊断插头）与CAN报文
217	RSA系列之《算法三》	https://xz.aliyun.com/t/13928	阿里先知实验室	news;	1	2024-02-28	RSA系列之《算法三》
218	JDBC-Attack 攻击利用汇总	https://xz.aliyun.com/t/13931	阿里先知实验室	news;	1	2024-02-29	JDBC-Attack 攻击利用汇总
220	记某次AWDP的坎坷之旅	https://xz.aliyun.com/t/13935	阿里先知实验室	news;	1	2024-02-28	记某次AWDP的坎坷之旅
221	供应链投毒预警 | 开源供应链投毒 202401 最新月报来啦！	https://xz.aliyun.com/t/13938	阿里先知实验室	news;	1	2024-02-29	供应链投毒预警 | 开源供应链投毒 202401 最新月报来啦！
222	开发一款扫描器，Goroutine越多越好？	https://xz.aliyun.com/t/13939	阿里先知实验室	news;	1	2024-02-29	开发一款扫描器，Goroutine越多越好？
223	从CTF中学习Vaadin gadgets	https://xz.aliyun.com/t/13941	阿里先知实验室	news;	1	2024-02-29	从CTF中学习Vaadin gadgets
225	供应链投毒预警 | 恶意NPM包利用Windows反向shell后门攻击开发者	https://xz.aliyun.com/t/13955	阿里先知实验室	news;	1	2024-02-29	供应链投毒预警 | 恶意NPM包利用Windows反向shell后门攻击开发者
268	JetBrains TeamCity 鉴权绕过浅析	https://xz.aliyun.com/t/14050	阿里先知实验室	news;	1	2024-03-06	JetBrains TeamCity 鉴权绕过浅析
269	[翻译]使用 QEMU 进行内网穿透？	https://xz.aliyun.com/t/14052	阿里先知实验室	news;	1	2024-03-06	[翻译]使用 QEMU 进行内网穿透？
270	JA 指纹识全系讲解（下）	https://xz.aliyun.com/t/14054	阿里先知实验室	news;	1	2024-03-07	JA 指纹识全系讲解（下）
272	给EXE加个密码【免杀系列】	https://xz.aliyun.com/t/14057	阿里先知实验室	news;	1	2024-03-08	给EXE加个密码【免杀系列】
273	使用太阿（Tai-e）进行静态代码安全分析（spring-boot篇二）	https://xz.aliyun.com/t/14058	阿里先知实验室	news;	1	2024-03-08	使用太阿（Tai-e）进行静态代码安全分析（spring-boot篇二）
274	内网横向下的135,445与5985端口利用	https://xz.aliyun.com/t/14060	阿里先知实验室	news;	1	2024-03-08	内网横向下的135,445与5985端口利用
275	pickle反序列化漏洞基础知识与绕过简析	https://xz.aliyun.com/t/14061	阿里先知实验室	news;	3	2024-03-08	pickle反序列化漏洞基础知识与绕过简析
276	【翻译】使用 AFL++ Frida 模式进行 Android 灰盒模糊测试	https://xz.aliyun.com/t/14062	阿里先知实验室	news;	2	2024-03-08	【翻译】使用 AFL++ Frida 模式进行 Android 灰盒模糊测试
278	某HR系统组合漏洞挖掘过程	https://xz.aliyun.com/t/14069	阿里先知实验室	news;	3	2024-03-11	某HR系统组合漏洞挖掘过程
279	DeFi技术及其安全风险浅析	https://xz.aliyun.com/t/14070	阿里先知实验室	news;	1	2024-03-11	DeFi技术及其安全风险浅析
280	某通用系统Nday分析	https://xz.aliyun.com/t/14071	阿里先知实验室	news;	1	2024-03-11	某通用系统Nday分析
281	Prototype Pollution Attack	https://xz.aliyun.com/t/14072	阿里先知实验室	news;	1	2024-03-11	原型污染攻击
282	Quasar RAT客户端木马执行流程逆向分析	https://xz.aliyun.com/t/14073	阿里先知实验室	news;	1	2024-03-11	Quasar RAT客户端木马执行流程逆向分析
283	Quaser RAT加解密技术剖析	https://xz.aliyun.com/t/14074	阿里先知实验室	news;	1	2024-03-11	Quaser RAT加解密技术剖析
284	利用白加黑静态逃逸杀软	https://xz.aliyun.com/t/14075	阿里先知实验室	news;	1	2024-03-11	利用白加黑静态逃逸杀软
287	duh@1pl1k@ - SQLi Bypass Authentication puncher - 2014.1	https://www.nu11secur1ty.com/2024/02/duh1pl1k-sqli-bypass-authentication.html	nu11security	vuln;	1	2024-02-29	1pl1k@ - SQLi 绕行验证打印器 - 2014 1
289	gaatitrack-1.0 Multiple-SQLi & G0BurpSQLmaPI usage	https://www.nu11secur1ty.com/2024/03/gaatitrack-10-multiple-sqli.html	nu11security	vuln;	1	2024-03-08	多SQLi 多SQLi
10206	Vietnam Securities Broker Suffers Cyberattack That Suspended Trading	https://www.darkreading.com/cyberattacks-data-breaches/vietnam-securities-broker-suffered-cyberattack-that-suspended-trading	darkreading	news;	1	2024-03-27	越南证券经纪公司在暂停交易时遭受的网络攻击
291	RUPPEINVOICE-1.0 Multiple-SQLi	https://www.nu11secur1ty.com/2024/03/ruppeinvoice-10-multiple-sqli.html	nu11security	vuln;	1	2024-03-08	RUPPEINVOICE-1.0 多SQLi
245	JS敏感泄露小帮手----WIH介绍	https://xz.aliyun.com/t/13993	阿里先知实验室	news;	1	2024-03-01	JS敏感泄露小帮手----WIH介绍
247	'另类'APP漏洞挖掘	https://xz.aliyun.com/t/13999	阿里先知实验室	news;	3	2024-03-01	'另类'APP漏洞挖掘
248	基于TLS回调的PE文件导入表项混淆 - 构造精心的解混淆Shellcode	https://xz.aliyun.com/t/14005	阿里先知实验室	news;	1	2024-03-01	基于TLS回调的PE文件导入表项混淆 - 构造精心的解混淆Shellcode
290	NDtaskmatic-1.0-by-Mayuri.K Multiple-SQLi	https://www.nu11secur1ty.com/2024/03/ndtaskmatic-10-by-mayurik-multiple-sqli.html	nu11security	vuln;	1	2024-03-07	NDtaskmatic- 1.0 by- Mayuri.K 多SQLi
249	某在线监控信息管理平台-java代审	https://xz.aliyun.com/t/14010	阿里先知实验室	news;	1	2024-03-01	某在线监控信息管理平台-java代审
250	[翻译]-用调用堆栈揭开攻击的帷幕	https://xz.aliyun.com/t/14011	阿里先知实验室	news;	1	2024-03-01	[翻译]-用调用堆栈揭开攻击的帷幕
251	NET环境下的多款同源RAT对比	https://xz.aliyun.com/t/14014	阿里先知实验室	news;	1	2024-03-01	NET环境下的多款同源RAT对比
252	某次众测的加解密对抗	https://xz.aliyun.com/t/14015	阿里先知实验室	news;	1	2024-03-01	某次众测的加解密对抗
254	Symantec + EDR 极端白名单策略下的 C&C Bypass 研究	https://xz.aliyun.com/t/14018	阿里先知实验室	news;	1	2024-03-01	Symantec + EDR 极端白名单策略下的 C&C Bypass 研究
256	GraphStrike：进攻性工具开发剖析	https://xz.aliyun.com/t/14032	阿里先知实验室	news;	1	2024-03-02	GraphStrike：进攻性工具开发剖析
257	hook初识之inline hook	https://xz.aliyun.com/t/14033	阿里先知实验室	news;	1	2024-03-01	hook初识之inline hook
258	Bypass AMSI	https://xz.aliyun.com/t/14034	阿里先知实验室	news;	1	2024-03-01	绕过AMSI
259	浅析WIFI攻击手法	https://xz.aliyun.com/t/14035	阿里先知实验室	news;	1	2024-03-03	浅析WIFI攻击手法
261	APP测试保姆级教程	https://xz.aliyun.com/t/14037	阿里先知实验室	news;	1	2024-03-01	APP测试保姆级教程
262	代码审计之tp各版本链子调式随笔	https://xz.aliyun.com/t/14038	阿里先知实验室	news;	1	2024-03-01	代码审计之tp各版本链子调式随笔
263	[翻译]【Ninja逆向】使用Ninja IL逆向自定义ISA：破解大赛37C3“Pot of Gold”	https://xz.aliyun.com/t/14042	阿里先知实验室	news;	1	2024-03-05	[翻译]【Ninja逆向】使用Ninja IL逆向自定义ISA：破解大赛37C3“Pot of Gold”
264	SolarWinds Security Event Manager AMF 反序列化 RCE (CVE-2024-0692)	https://xz.aliyun.com/t/14044	阿里先知实验室	news;	3	2024-03-04	SolarWinds Security Event Manager AMF 反序列化 RCE (CVE-2024-0692)
265	pwn堆的结构及堆溢出理解	https://xz.aliyun.com/t/14046	阿里先知实验室	news;	1	2024-03-05	pwn堆的结构及堆溢出理解
266	从一道题初接触RASP	https://xz.aliyun.com/t/14048	阿里先知实验室	news;	1	2024-03-05	从一道题初接触RASP
310	Russia Attacked Ukraine's Power Grid at Least 66 Times to ‘Freeze It Into Submission’	https://www.wired.com/story/russia-ukraine-power-war-crimes/	wired	news;Security;Security / National Security;Security / Security News;	3	2024-02-29	俄罗斯在至少66个时报袭击乌克兰电网,
306	The Privacy Danger Lurking in Push Notifications	https://www.wired.com/story/push-notification-privacy-security-roundup/	wired	news;Security;Security / Cyberattacks and Hacks;Security / National Security;Security / Security News;	1	2024-03-02	推动通知中的隐私危险
46	U.S. Court Orders NSO Group to Hand Over Pegasus Spyware Code to WhatsApp	https://thehackernews.com/2024/03/us-court-orders-nso-group-to-hand-over.html	feedburner	news;	1	2024-03-02	美国法院命令国家统计局集团将Pegasus Spyware代码移交给WhessApp
4162	派早报：Google 将在 5 月 14 日召开 I/O 大会	https://buaq.net/go-228247.html	buaq	newscopy;	0	2024-03-15	派早报：Google 将在 5 月 14 日召开 I/O 大会
313	Vulnerabilities in business VPNs under the spotlight	https://www.welivesecurity.com/en/business-security/vulnerabilities-business-vpns-spotlight/	eset	news;	1	2024-02-28	受关注的自愿、自愿、可观和
5883	The TikTok Ban Bill, Your Car is Spying on You, Signal’s Username Update	https://buaq.net/go-228732.html	buaq	newscopy;	0	2024-03-18	TikTok Ban Bill, 你的汽车正在监视你, 信号用户名更新
314	Evasive Panda leverages Monlam Festival to target Tibetans	https://www.welivesecurity.com/en/eset-research/evasive-panda-leverages-monlam-festival-target-tibetans/	eset	news;	1	2024-03-07	伊娃熊猫利用蒙拉姆节来对付西藏人
315	Top 10 scams targeting seniors – and how to keep your money safe	https://www.welivesecurity.com/en/scams/top-10-scams-seniors-how-keep-money-safe/	eset	news;	1	2024-03-06	以老年人为目标的十大骗局 — — 以及如何保证你的钱的安全
316	APT attacks taking aim at Tibetans – Week in security with Tony Anscombe	https://www.welivesecurity.com/en/videos/apt-attacks-tibetans-week-security-tony-anscombe/	eset	news;	2	2024-03-08	APT攻击西藏人 — — 与Tony Ascombe的“安全周”
318	Irresistible: Hooks, habits and why you can’t put down your phone	https://www.welivesecurity.com/en/we-live-progress/irresistible-hooks-habits-why-you-cant-put-down-your-phone/	eset	news;	1	2024-03-05	不可否认:钩子、习惯和为什么不能放下手机
320	Hack The Box: CozyHosting Machine – Easy Difficulty	https://threatninja.net/2024/03/hack-the-box-cozyhosting-machine-easy-difficulty/	threatninja	sectest;Easy Machine;BurpSuite;Challenges;gobuster;gtfobins;HackTheBox;hashcat;Linux;Penetration Testing;postgres;springboot;ssh;Still drafting;	1	2024-03-02	黑盒:合居机器 — — 容易困难
294	Biden Executive Order Bans Sale of US Data to China, Russia. Good Luck	https://www.wired.com/story/biden-data-broker-executive-order/	wired	news;Security;Security / National Security;Security / Privacy;Security / Security News;Politics / Policy;	6	2024-02-28	拜登行政命令禁止向中国俄罗斯出售美国数据。
295	Binance’s Top Crypto Crime Investigator Is Being Detained in Nigeria	https://www.wired.com/story/binance-top-investigator-detained-nigeria/	wired	news;Security;Security / Security News;Business / Blockchain and Cryptocurrency;	1	2024-03-12	在尼日利亚被拘留的顶级隐秘犯罪调查员
296	Change Healthcare Ransomware Attack: BlackCat Hackers Quickly Returned After FBI Bust	https://www.wired.com/story/blackcat-ransomware-disruptions-comebacks/	wired	news;Security;Security / Cyberattacks and Hacks;Security / Security News;	2	2024-02-27	改变医疗系统, 核暖器攻击:BlackCat Hackers在联邦调查局暴动后迅速返回
297	The White House Warns Cars Made in China Could Unleash Chaos on US Highways	https://www.wired.com/story/china-cars-national-security-threat-investigation/	wired	news;Security;Security / National Security;Business;Business / Transportation;	4	2024-02-29	白宫华时汽车在中国制造,
298	How to Turn Off Facebook’s Two-Factor Authentication Change	https://www.wired.com/story/facebook-two-factor-authentication-2fa-change/	wired	news;Security;Security / Security Advice;Business / Social Media;	1	2024-03-05	如何关闭Facebook的双要素验证变化
299	Google Is Getting Thousands of Deepfake Porn Complaints	https://www.wired.com/story/google-deepfake-porn-dmca-takedowns/	wired	news;Security;Security / Privacy;Security / Security News;	1	2024-03-11	Google正在获得成千上万的深假色情投诉
300	The UK’s GPS Tagging of Migrants Has Been Ruled Illegal	https://www.wired.com/story/gps-ankle-tags-uk-privacy-illegal/	wired	news;Security;Security / Privacy;	1	2024-03-01	联合王国对移民的GPS跟踪被非法统治。
159	黑客冒充美国政府机构，开展网络欺诈活动	https://www.freebuf.com/news/393709.html	freebuf	news;资讯;	1	2024-03-07	黑客冒充美国政府机构，开展网络欺诈活动
304	Meta Abandons Hacking Victims, Draining Law Enforcement Resources, Officials Say	https://www.wired.com/story/meta-hacked-users-draining-resources/	wired	news;Security;Security / Cyberattacks and Hacks;Security / Security News;Business / Social Media;	1	2024-03-06	将受害者、排水执法资源、官员说
10847	Lodan-Electronics-Inc	http://www.ransomfeed.it/index.php?page=post_details&id_post=14029	ransomfeed	ransom;incransom;	1	2024-03-29	Lodan-eem-Inc 电子集成器
305	A Pornhub Chatbot Stopped Millions From Searching for Child Abuse Videos	https://www.wired.com/story/pornhub-chatbot-csam-help/	wired	news;Security;Security / Security News;	1	2024-02-29	A Pornhub Chatbot 阻止数以百万计的人搜索虐待儿童录像
10845	Saglobalcom	http://www.ransomfeed.it/index.php?page=post_details&id_post=14026	ransomfeed	ransom;redransomware;	1	2024-03-28	Sagloglobal 天文学组织
26166	华为Pocket2大溪地灰 	https://s.weibo.com/weibo?q=%23华为Pocket2大溪地灰 %23	sina.weibo	hotsearch;weibo	1	2024-02-22	华为Pocket2大溪地灰
26167	华为Pocket2媲美二十万元检测仪 	https://s.weibo.com/weibo?q=%23华为Pocket2媲美二十万元检测仪 %23	sina.weibo	hotsearch;weibo	1	2024-02-22	华为Pocket2媲美二十万元检测仪
10846	Thors-Datadk	http://www.ransomfeed.it/index.php?page=post_details&id_post=14027	ransomfeed	ransom;redransomware;	1	2024-03-28	Thors- Datadk 索尔- 数据
26168	华为Pocket2首发向日葵通信技术 	https://s.weibo.com/weibo?q=%23华为Pocket2首发向日葵通信技术 %23	sina.weibo	hotsearch;weibo	1	2024-02-22	华为Pocket2首发向日葵通信技术
26169	华为nova12	https://s.weibo.com/weibo?q=%23华为nova12%23	sina.weibo	hotsearch;weibo	1	2023-12-18	华为nova12
346	Saflok System 6000 Key Derivation	https://cxsecurity.com/issue/WLB-2024020101	cxsecurity	vuln;	1	2024-02-29	Saflok 系统 6000 键导出
347	Moodle 4.3 Insecure Direct Object Reference	https://cxsecurity.com/issue/WLB-2024020102	cxsecurity	vuln;	1	2024-02-29	Moodle 4.3 不安全的直接物体参考
348	WP Fastest Cache 1.2.2 Unauthenticated SQL Injection	https://cxsecurity.com/issue/WLB-2024020103	cxsecurity	vuln;	1	2024-02-29	WP 最快缓存 1.2.2 未认证 SQL 喷射
350	employee_akpoly-1.0-2024 Multiple-SQLi	https://cxsecurity.com/issue/WLB-2024030002	cxsecurity	vuln;	1	2024-03-01	多SQLi 多SQLi
351	Zoo Management System 1.0 Unauthenticated RCE	https://cxsecurity.com/issue/WLB-2024030003	cxsecurity	vuln;	1	2024-03-01	动物园管理系统1.0 未经认证的RCE
353	Enrollment System v1.0 SQL Injection	https://cxsecurity.com/issue/WLB-2024030006	cxsecurity	vuln;	1	2024-03-03	输入系统 v1.0 SQL 输入
354	Easywall 0.3.1 Authenticated Remote Command Execution	https://cxsecurity.com/issue/WLB-2024030007	cxsecurity	vuln;	1	2024-03-03	经认证的远程指令执行
355	Maxima Max Pro Power BLE Traffic Replay	https://cxsecurity.com/issue/WLB-2024030008	cxsecurity	vuln;	1	2024-03-06	Maxima 最大最大功率
356	GLiNet Router Authentication Bypass	https://cxsecurity.com/issue/WLB-2024030009	cxsecurity	vuln;	1	2024-03-06	GLiNet 路由器认证过路口
359	MongoDB 2.0.1 / 2.1.1 / 2.1.4 / 2.1.5 Local Password Disclosure	https://cxsecurity.com/issue/WLB-2024030013	cxsecurity	vuln;	1	2024-03-09	MongoDB 2. 0.1 / 2.1.1 / 2.1.1 / 2.1.4 / 2.1.5 本地密码披露
360	NDtaskmatic-1.0-by-Mayuri.K Multiple-SQLi	https://cxsecurity.com/issue/WLB-2024030014	cxsecurity	vuln;	1	2024-03-09	NDtaskmatic- 1.0 by- Mayuri.K 多SQLi
361	FullCourt Enterprise 8.2 Cross Site Scripting	https://cxsecurity.com/issue/WLB-2024030015	cxsecurity	vuln;	1	2024-03-09	8.2 跨站点文稿
362	Artica Proxy 4.50 Unauthenticated PHP Deserialization	https://cxsecurity.com/issue/WLB-2024030016	cxsecurity	vuln;	1	2024-03-09	未经认证 PHP
363	WordPress Hide My WP SQL Injection	https://cxsecurity.com/issue/WLB-2024030017	cxsecurity	vuln;	1	2024-03-11	Wordpress 隐藏我的 WP SQL 输入
364	DataCube3 1.0 Shell Upload	https://cxsecurity.com/issue/WLB-2024030018	cxsecurity	vuln;	1	2024-03-11	DataCube3 1.0 壳牌上传
366	Adobe ColdFusion 2018,15 / 2021,5 Arbitrary File Read	https://cxsecurity.com/issue/WLB-2024030022	cxsecurity	vuln;	1	2024-03-11	2018,15 / 2021,5 任意阅读文件
368	RUPPEINVOICE-1.0 Multiple-SQLi	https://cxsecurity.com/issue/WLB-2024030024	cxsecurity	vuln;	1	2024-03-11	RUPPEINVOICE-1.0 多SQLi
369	Red Hat Security Advisory 2024-1239-03	https://packetstormsecurity.com/files/177505/RHSA-2024-1239-03.txt	packetstorm	vuln;;	1	2024-03-08	红帽子安保咨询 2024-1239-03
370	Ladder 0.0.21 Server-Side Request Forgery	https://packetstormsecurity.com/files/177506/ladder0021-ssrf.txt	packetstorm	vuln;;	1	2024-03-08	云梯 0.0.21 服务器- Side 请求伪造
372	Ubuntu Security Notice USN-6683-1	https://packetstormsecurity.com/files/177508/USN-6683-1.txt	packetstorm	vuln;;	1	2024-03-08	Ubuntu Ubuntu 安全通知 USN6683-1
325	Sandhya Branding Agency - Sql Injection	https://cxsecurity.com/issue/WLB-2024030021	cxsecurity	vuln;	1	2024-03-11	Sandhya品牌机构 - Sql喷射
322	Agencia NUBA- Sql Injection	https://cxsecurity.com/issue/WLB-2024020095	cxsecurity	vuln;	1	2024-02-28	NUBA-Sql注射
326	phpFox <  4.8.13 (redirect) PHP Object Injection Exploit	https://cxsecurity.com/issue/WLB-2024020089	cxsecurity	vuln;	1	2024-02-27	phpFox < 4.8.13( 直接) PHP 对象喷射 爆破
371	MongoDB 2.0.1 / 2.1.1 / 2.1.4 / 2.1.5 Local Password Disclosure	https://packetstormsecurity.com/files/177507/mongodb-disclose.txt	packetstorm	vuln;;	1	2024-03-08	MongoDB 2. 0.1 / 2.1.1 / 2.1.1 / 2.1.4 / 2.1.5 本地密码披露
328	A-PDF All to MP3 Converter 2.0.0 DEP Bypass via HeapCreate + HeapAlloc	https://cxsecurity.com/issue/WLB-2024030011	cxsecurity	vuln;	1	2024-03-06	A-PDF 全部到 MP3 转换器 2. 0.0 DEP 通过 HeapCreate HeapAlloc 通过 HeapCreate HeapAlloc 绕行
329	Akaunting 3.1.3 Remote Command Execution	https://cxsecurity.com/issue/WLB-2024030019	cxsecurity	vuln;	1	2024-03-11	3.1.3 远程指挥执行
331	TP-Link TL-WR740N Buffer Overflow / Denial Of Service	https://cxsecurity.com/issue/WLB-2024030025	cxsecurity	vuln;	1	2024-03-11	缓冲溢额/拒服兵役
332	Automatic-Systems SOC FL9600 FastLine Hardcoded Credentials	https://cxsecurity.com/issue/WLB-2024020086	cxsecurity	vuln;	1	2024-02-27	自动系统 SOC FL9600 FL9600 FastLine 硬码证书
333	perl2exe 30.10C Arbitrary Code Execution	https://cxsecurity.com/issue/WLB-2024020087	cxsecurity	vuln;	1	2024-02-27	30.10C 任意处决
10848	PSEC-Church	http://www.ransomfeed.it/index.php?page=post_details&id_post=14030	ransomfeed	ransom;incransom;	1	2024-03-29	PSEC-教堂
10849	Tech-Quip-Inc	http://www.ransomfeed.it/index.php?page=post_details&id_post=14031	ransomfeed	ransom;incransom;	1	2024-03-29	技术Quip-Inc
334	Automatic-Systems SOC FL9600 FastLine Directory Traversal	https://cxsecurity.com/issue/WLB-2024020088	cxsecurity	vuln;	1	2024-02-27	自动系统 SOC FL9600 FastLine 目录 Traversal
10850	rameywinecom	http://www.ransomfeed.it/index.php?page=post_details&id_post=14032	ransomfeed	ransom;abyss;	1	2024-03-29	拉麦葡萄酒
336	DealBert Cross Site Scripting	https://cxsecurity.com/issue/WLB-2024020091	cxsecurity	vuln;	1	2024-02-28	发牌Bert 跨站点脚本
337	WordPress WP Fastest Cache 1.2.2 SQL Injection	https://cxsecurity.com/issue/WLB-2024020092	cxsecurity	vuln;	1	2024-02-28	Wordpress WP 最快缓存 1.2.2 SQL 喷射
338	Blood Bank 1.0 SQL Injection	https://cxsecurity.com/issue/WLB-2024020093	cxsecurity	vuln;	1	2024-02-28	血库1.0 SQL注射
342	Backdoor.Win32.Jeemp.c  / Cleartext Hardcoded Credentials	https://cxsecurity.com/issue/WLB-2024020097	cxsecurity	vuln;	1	2024-02-29	Win32.Jeemp.c/明确文本硬编码证书
343	Backdoor.Win32.Agent.amt MVID-2024-0673 Authentication Bypass / Code Execution	https://cxsecurity.com/issue/WLB-2024020098	cxsecurity	vuln;	1	2024-02-29	Win32. MVID-2024-0673 认证过道/代码执行
344	Backdoor.Win32.Agent.amt / Authentication Bypass	https://cxsecurity.com/issue/WLB-2024020099	cxsecurity	vuln;	1	2024-02-29	后门 Win32. Agent. amt / 身份验证过道
345	Source Guardian Cross Site Scripting	https://cxsecurity.com/issue/WLB-2024020100	cxsecurity	vuln;	1	2024-02-29	源码保护者跨站点脚本
399	Persistence – Visual Studio Code Extensions	https://pentestlab.blog/2024/03/04/persistence-visual-studio-code-extensions/	pentestlab	tech;Persistence;C2;PowerShell;Visual Studio Code;	1	2024-03-04	持久性 - 视觉工作室代码扩展
397	Roku cancels unauthorized subscriptions and provides refunds for 15k breached accounts	https://therecord.media/roku-unauthorized-subscriptions-account-refunds	therecord	ransom;Cybercrime;News;News Briefs;	1	2024-03-11	Roku取消未经授权的订阅,并退还15公里被违反账户的退款
377	Ubuntu Security Notice USN-6680-2	https://packetstormsecurity.com/files/177513/USN-6680-2.txt	packetstorm	vuln;;	1	2024-03-08	Ubuntu Ubuntu 安全通知 USN6680-2
10851	Sysmex	http://www.ransomfeed.it/index.php?page=post_details&id_post=14033	ransomfeed	ransom;hunters;	1	2024-03-29	Sysmex
10852	Graypen-Ltd	http://www.ransomfeed.it/index.php?page=post_details&id_post=14035	ransomfeed	ransom;incransom;	1	2024-03-29	灰色日数
390	OpenSSH 9.7p1	https://packetstormsecurity.com/files/177526/openssh-9.7p1.tar.gz	packetstorm	vuln;;	1	2024-03-11	OpenSSH 9.7p1
4758	International Monetary Fund email accounts hacked in cyberattack	https://www.bleepingcomputer.com/news/security/international-monetary-fund-email-accounts-hacked-in-cyberattack/	bleepingcomputer	news;Security;	1	2024-03-15	国际货币基金组织在网络攻击中黑入的电子邮件账户
403	Moukthar - Android Remote Administration Tool	http://www.kitploit.com/2024/02/moukthar-android-remote-administration.html	kitploit	tool;Android RAT;Command And Control;Dynamic Routing;Moukthar;Spyware;Web Socket Server;Web Sockets;	2	2024-03-02	Moukthar - Android远程管理工具
27	How to Find and Fix Risky Sharing in Google Drive	https://thehackernews.com/2024/03/how-to-find-and-fix-risky-sharing-in.html	feedburner	news;	1	2024-03-06	如何在谷歌驱动器中发现和固定风险分担
379	TP-Link TL-WR740N Buffer Overflow / Denial Of Service	https://packetstormsecurity.com/files/177515/tplinktlwr740n-overflowdos.txt	packetstorm	vuln;;	1	2024-03-11	缓冲溢额/拒服兵役
35	New BIFROSE Linux Malware Variant Using Deceptive VMware Domain for Evasion	https://thehackernews.com/2024/03/new-bifrose-linux-malware-variant-using.html	feedburner	news;	1	2024-03-01	BIFROSE Linux 使用欺骗性 VMware 域来进行疏散的新 BIFROSE Linux Malware 变换
387	Adobe ColdFusion 2018,15 / 2021,5 Arbitrary File Read	https://packetstormsecurity.com/files/177523/adobecf-fileread.txt	packetstorm	vuln;;	1	2024-03-11	2018,15 / 2021,5 任意阅读文件
393	Ubuntu Security Notice USN-6687-1	https://packetstormsecurity.com/files/177529/USN-6687-1.txt	packetstorm	vuln;;	1	2024-03-11	Ubuntu Ubuntu 安全通知 USN-6687-1
385	WordPress Duplicator Data Exposure / Account Takeover	https://packetstormsecurity.com/files/177521/wpduplicator-takeover.txt	packetstorm	vuln;;	1	2024-03-11	WordPress Dusplictor 数据曝光/账户接管
404	BloodHound - Six Degrees Of Domain Admin	http://www.kitploit.com/2024/03/bloodhound-six-degrees-of-domain-admin.html	kitploit	tool;Neo4J;Privilege;React;REST API;Socket;Username;	1	2024-03-04	血狗 - 六度地域管理
378	Debian Security Advisory 5637-1	https://packetstormsecurity.com/files/177514/dsa-5637-1.txt	packetstorm	vuln;;	1	2024-03-08	Debian安全咨询 5637-1
408	Nomore403 - Tool To Bypass 403/40X Response Codes	http://www.kitploit.com/2024/03/nomore403-tool-to-bypass-40340x.html	kitploit	tool;403 Bypass;Bugbounty;Nomore403;WAF Bypass;Websec;	1	2024-03-08	Nomore403 - 绕过403/40X反应代码工具
396	ODNI releases new open-source intelligence strategy with limited details	https://therecord.media/odni-osint-strategy-few-details	therecord	ransom;Government;Industry;Leadership;News;Privacy;	1	2024-03-11	ODNI发布新的公开来源情报战略,细节有限
10148	Alert: New Phishing Attack Delivers Keylogger Disguised as Bank Payment Notice	https://thehackernews.com/2024/03/alert-new-phishing-attack-delivers.html	feedburner	news;	1	2024-03-27	警示:作为银行付款通知的《银行付款通知》
10150	CISA Warns: Hackers Actively Attacking Microsoft SharePoint Vulnerability	https://thehackernews.com/2024/03/cisa-warns-hackers-actively-attacking.html	feedburner	news;	1	2024-03-27	CISA Warns:黑客积极攻击微软共享点脆弱性
384	RUPPEINVOICE 1.0 SQL Injection	https://packetstormsecurity.com/files/177520/ruppeinvoice10-sql.txt	packetstorm	vuln;;	1	2024-03-11	RUPPPEINVOICE 1.0 SQL 注射
392	Debian Security Advisory 5638-1	https://packetstormsecurity.com/files/177528/dsa-5638-1.txt	packetstorm	vuln;;	1	2024-03-11	Debian安全咨询 5638-1
388	Sitecore 8.2 Remote Code Execution	https://packetstormsecurity.com/files/177524/sitecore82-exec.txt	packetstorm	vuln;;	1	2024-03-11	8.2 远程代码执行
402	LeakSearch - Search & Parse Password Leaks	http://www.kitploit.com/2024/02/leaksearch-search-parse-password-leaks.html	kitploit	tool;LeakSearch;Python3;	1	2024-02-29	渗漏搜索 - 搜索
383	WordPress Hide My WP SQL Injection	https://packetstormsecurity.com/files/177519/wphidemywp-sql.txt	packetstorm	vuln;;	1	2024-03-11	Wordpress 隐藏我的 WP SQL 输入
5866	3·15曝光 | AI换脸，数字身份的迷失与重构	https://buaq.net/go-228708.html	buaq	newscopy;	0	2024-03-18	3·15曝光 | AI换脸，数字身份的迷失与重构
382	DataCube3 1.0 Shell Upload	https://packetstormsecurity.com/files/177518/datacube310-shell.txt	packetstorm	vuln;;	1	2024-03-11	DataCube3 1.0 壳牌上传
395	ODNI appoints new election security leader ahead of presidential race	https://therecord.media/jessica-brandt-election-security-odni-foreign-malign-influence-center	therecord	ransom;People;Leadership;Government;Nation-state;Elections;News;	1	2024-03-11	国家民主党在总统竞选之前任命新的选举安全领导人
389	Numbas Remote Code Execution	https://packetstormsecurity.com/files/177525/numbas-exec.txt	packetstorm	vuln;;	1	2024-03-11	Numbas 远程代码执行
391	Lynis Auditing Tool 3.1.0	https://packetstormsecurity.com/files/177527/lynis-3.1.0.tar.gz	packetstorm	vuln;;	1	2024-03-11	Lynis审计工具 3.1.0
376	Ubuntu Security Notice USN-6686-1	https://packetstormsecurity.com/files/177512/USN-6686-1.txt	packetstorm	vuln;;	1	2024-03-08	Ubuntu Ubuntu 安全通知 USN6686-1
386	Backdoor.Win32.Beastdoor.oq MVID-2024-0674 Remote Command Execution	https://packetstormsecurity.com/files/177522/MVID-2024-0674.txt	packetstorm	vuln;;	1	2024-03-11	Win32.Beastern door.oq MVID-2024-0674遥控执行
407	n0Mac - Yet Another Mac Changer!!!	http://www.kitploit.com/2024/03/n0mac-yet-another-mac-changer.html	kitploit	tool;	1	2024-03-11	又是又一个麦克变换者!
10855	大模型如何赋能企业安全；重要文件的保护措施有哪些 | FB甲方群话题讨论	https://www.freebuf.com/articles/396293.html	freebuf	news;	1	2024-03-28	大模型如何赋能企业安全；重要文件的保护措施有哪些 | FB甲方群话题讨论
430	绿盟科技威胁周报（2024.03.04-2024.03.10）	https://blog.nsfocus.net/weeklyreport202410/	绿盟	news;威胁通告;周报;威胁防护;	1	2024-03-11	绿盟科技威胁周报（2024.03.04-2024.03.10）
10263	HC-Quertaro	http://www.ransomfeed.it/index.php?page=post_details&id_post=13959	ransomfeed	ransom;8base;	1	2024-03-27	HC-克雷塔罗
421	Mastering Fuzzing: A Comprehensive Tutorial	https://infosecwriteups.com/mastering-fuzzing-a-comprehensive-tutorial-ba9431c8ff0f?source=rss----7b722bfd1b8d---4	infosecwriteups	tech;fuzzing;bug-bounty;tutorial;cybersecurity;bugs;	1	2024-03-04	掌握模糊学:综合教学
18899	DOJ data on 341,000 people leaked in cyberattack on consulting firm	https://therecord.media/doj-data-leaked-in-attack-on-consulting-firm	therecord	ransom;Government;Cybercrime;News Briefs;News;Privacy;	1	2024-04-08	司法部关于341 000人在对咨询公司进行网络攻击中泄漏的341 000人的数据
425	【公益译文】2023：生成式AI的爆发之年	https://blog.nsfocus.net/ai-2/	绿盟	news;公益译文;	1	2024-03-11	【公益译文】2023：生成式AI的爆发之年
435	Italian DPA Asks OpenAI’s ‘Sora’ to Reveal Algorithm Information	https://gbhackers.com/italian-dpa-asks-openais-sora/	GBHacker	news;Cyber AI;Cyber Security News;computer security;	1	2024-03-12	意大利政治部 要求 OpenAI 的“Sora” 解析算法信息
424	SANS Offensive CTF - Taskist:: 01–04	https://infosecwriteups.com/sans-offensive-ctf-taskist-01-04-56452aa43905?source=rss----7b722bfd1b8d---4	infosecwriteups	tech;offensive;ssrf;idor;şans;ctf;	1	2024-03-06	SANS 进攻性CTF - 专报告员: 01-04
426	绿盟威胁情报月报-2024年2月	https://blog.nsfocus.net/monthlyreport202402/	绿盟	news;威胁通告;威胁防护;月报;	1	2024-03-06	绿盟威胁情报月报-2024年2月
428	将S端目录mount到C端文件系统中	https://blog.nsfocus.net/smountc/	绿盟	news;安全分享;	1	2024-03-12	将S端目录mount到C端文件系统中
434	Hackers Deliver MSIX Malware in The Lure of Freemium Productivity App	https://gbhackers.com/hackers-deliver-msix-malware/	GBHacker	news;Cyber Security News;Malware;computer security;	1	2024-03-12	在 " 免费生产力应用卢尔 " 中,黑客交付 MSIX Malware
436	KrustyLoader Backdoor Attack Both Windows & Linux Systems	https://gbhackers.com/krustyloader-backdoor/	GBHacker	news;cyber security;Cyber Security News;Malware;	1	2024-03-12	Krusty Loader 后门攻击两个窗口
427	PDF合并方案	https://blog.nsfocus.net/pdf/	绿盟	news;安全分享;	1	2024-02-28	PDF合并方案
418	How I Found Multiple XSS Vulnerabilities Using Unknown Techniques	https://infosecwriteups.com/how-i-found-multiple-xss-vulnerabilities-using-unknown-techniques-74f8e705ea0d?source=rss----7b722bfd1b8d---4	infosecwriteups	tech;xss-attack;hacking;bug-bounty;bug-bounty-tips;cybersecurity;	1	2024-03-05	我是如何用未知技术 找到多重 XSS 脆弱性的
417	GTFOBins and LOLBAS: Mastering Binary Exploitation for Unix and Windows	https://infosecwriteups.com/gtfobins-and-lolbas-mastering-binary-exploitation-in-ethical-hacking-for-unix-and-windows-30dd86e52370?source=rss----7b722bfd1b8d---4	infosecwriteups	tech;cybersecurity;hacking;exploitation;vulnerability;ctf;	1	2024-03-04	GTFOBins和LOLBAS:掌握Unix和Windows的二进制开发
423	Mastering Wireshark: A Beginner’s Guide for Networks Analysis	https://infosecwriteups.com/mastering-wireshark-a-comprehensive-guide-for-networks-analysis-6b2b8d5c1812?source=rss----7b722bfd1b8d---4	infosecwriteups	tech;cybersecurity;penetration-testing;packet-capture;network-analysis;wireshark;	1	2024-03-04	掌握无线电通信:网络分析初学者指南
432	CyberGate RAT Mimic as Dorks Tool to Attack Cybersecurity Professionals	https://gbhackers.com/cybergate-rat-dorks-tattack-cybersecurity/	GBHacker	news;Cyber Attack;cyber security;Cyber Security News;	1	2024-03-11	CyberGate RAT Mimimic作为攻击网络安全专业人员的多克工具
433	French Government Hit with Severe DDoS Attack	https://gbhackers.com/french-government-hit-with-severe-ddos-attack/	GBHacker	news;Cyber Security News;DDOS;Cyber Attack;	1	2024-03-12	法国政府用严重DDoS攻击打击法国政府
429	绿盟科技威胁周报（2024.02.26-2024.03.03）	https://blog.nsfocus.net/weeklyreport202409/	绿盟	news;威胁通告;周报;威胁防护;	1	2024-03-06	绿盟科技威胁周报（2024.02.26-2024.03.03）
10853	Control-Technology	http://www.ransomfeed.it/index.php?page=post_details&id_post=14036	ransomfeed	ransom;akira;	1	2024-03-29	控制技术
636	Essential-Labs	http://www.ransomfeed.it/index.php?page=post_details&id_post=13499	ransomfeed	ransom;8base;	1	2024-02-29	基本病历
420	Mastering CSRF: A Beginner’s Guide to Cross-Site Request Forgery	https://infosecwriteups.com/mastering-csrf-a-comprehensive-guide-to-cross-site-request-forgery-a380aca0eab0?source=rss----7b722bfd1b8d---4	infosecwriteups	tech;web-development;programming;csrf;cybersecurity;bug-bounty;	1	2024-03-04	掌握CSRF:初创者跨点请求伪造指南
4750	What it’s Like Using Integrations Built by D3	https://securityboulevard.com/2024/03/what-its-like-using-integrations-built-by-d3/	securityboulevard	news;DevOps;Security Bloggers Network;Automation;Cybersecurity;efficiency;Error Handling;integrations;Playbook Creation;SOAR;technology innovation;Vendor APIs;	1	2024-03-15	如何使用D3建造的融合
9986	Germany warns of 17K vulnerable Microsoft Exchange servers exposed online	https://www.bleepingcomputer.com/news/security/germany-warns-of-17k-vulnerable-microsoft-exchange-servers-exposed-online/	bleepingcomputer	news;Security;	1	2024-03-26	德国警告17K脆弱的微软交换服务器在网上曝光
17715	XZ-Utils Supply Chain Backdoor Vulnerability Updated Advisory (CVE-2024-3094)	https://securityboulevard.com/2024/04/xz-utils-supply-chain-backdoor-vulnerability-updated-advisory-cve-2024-3094/	securityboulevard	news;Security Bloggers Network;Blog;CVE-2024-3094;;DDoS Mitigation;XZ Utils;	3	2024-04-07	XZ-UITLs供应链后门脆弱性最新咨询(CVE-2024-3094)
10152	Critical Unpatched Ray AI Platform Vulnerability Exploited for Cryptocurrency Mining	https://thehackernews.com/2024/03/critical-unpatched-ray-ai-platform.html	feedburner	news;	1	2024-03-27	用于加密货币开采的
456	Welcoming the Liechtenstein Government to Have I Been Pwned	https://buaq.net/go-227540.html	buaq	newscopy;	0	2024-03-12	欢迎列支敦士登政府邀请我参加
457	Insurance scams via QR codes: how to recognise and defend yourself	https://buaq.net/go-227541.html	buaq	newscopy;	0	2024-03-12	通过QR码的保险骗骗骗:如何识别和为自己辩护
458	Bypassing OGNL sandboxes for fun and charities	https://buaq.net/go-227542.html	buaq	newscopy;	0	2024-03-12	绕过OGNL沙箱以换取乐趣和慈善
459	The Rise of AI Worms in Cybersecurity	https://buaq.net/go-227543.html	buaq	newscopy;	0	2024-03-12	AI虫子在网络安全中的崛起
460	Alert: FBI Warns Of BlackCat Ransomware Healthcare Attack	https://buaq.net/go-227544.html	buaq	newscopy;	0	2024-03-12	警示: 联邦调查局的黑猫战警
613	JS-International	http://www.ransomfeed.it/index.php?page=post_details&id_post=13471	ransomfeed	ransom;medusa;	1	2024-02-27	联合国际
614	npgandourcom	http://www.ransomfeed.it/index.php?page=post_details&id_post=13472	ransomfeed	ransom;lockbit3;	1	2024-02-27	npgandour 通信
615	verbraucherzentrale-hessen	http://www.ransomfeed.it/index.php?page=post_details&id_post=13474	ransomfeed	ransom;alphv;	1	2024-02-27	粗金刚石
616	Acies-Srl	http://www.ransomfeed.it/index.php?page=post_details&id_post=13475	ransomfeed	ransom;8base;	1	2024-02-28	Acites- Srl
617	ROYAL-INSIGNIA	http://www.ransomfeed.it/index.php?page=post_details&id_post=13476	ransomfeed	ransom;8base;	1	2024-02-28	罗马尼亚 -- -- 法国
618	RWF-Frmelt	http://www.ransomfeed.it/index.php?page=post_details&id_post=13477	ransomfeed	ransom;8base;	1	2024-02-28	RWF-熔石
619	Saudia-MRO	http://www.ransomfeed.it/index.php?page=post_details&id_post=13478	ransomfeed	ransom;8base;	1	2024-02-28	Saudia-MRO 沙特
620	Bertani-Trasporti-Spa	http://www.ransomfeed.it/index.php?page=post_details&id_post=13479	ransomfeed	ransom;8base;	1	2024-02-28	贝尔塔尼-特拉斯波蒂-斯帕
621	Orange-Public-School-District	http://www.ransomfeed.it/index.php?page=post_details&id_post=13480	ransomfeed	ransom;incransom;	1	2024-02-28	Orange-公立-公立-学校区
622	Frencken	http://www.ransomfeed.it/index.php?page=post_details&id_post=13482	ransomfeed	ransom;snatch;	1	2024-02-28	弗伦肯
623	abtexelgroupcom	http://www.ransomfeed.it/index.php?page=post_details&id_post=13484	ransomfeed	ransom;cactus;	1	2024-02-28	abtexelgroup 群組
625	sundbirstacom	http://www.ransomfeed.it/index.php?page=post_details&id_post=13486	ransomfeed	ransom;lockbit3;	1	2024-02-28	eundbirstacom( 日光网络)
624	vertdurecom	http://www.ransomfeed.it/index.php?page=post_details&id_post=13485	ransomfeed	ransom;lockbit3;	1	2024-02-28	verturecom 旋转线
629	DTN-Management-Company	http://www.ransomfeed.it/index.php?page=post_details&id_post=13490	ransomfeed	ransom;akira;	1	2024-02-28	DTN-管理-公司
630	etairoshealthcom	http://www.ransomfeed.it/index.php?page=post_details&id_post=13491	ransomfeed	ransom;qilin;	1	2024-02-28	健康委员会
176	Windstream Enterprise and Fortinet join forces to accelerate digital transformation for enterprises	https://www.helpnetsecurity.com/2024/03/11/windstream-enterprise-fortinet-secure-flex-premium/	helpnetsecurity	news;Industry news;Fortinet;Windstream Enterprise;	1	2024-03-11	企业和Fortinet联合起来,加速企业的数字转换
631	J-A-Piper-Roofing	http://www.ransomfeed.it/index.php?page=post_details&id_post=13493	ransomfeed	ransom;blacksuit;	1	2024-02-28	J -A - Piper - 屋顶
632	easternshipbuildingcom	http://www.ransomfeed.it/index.php?page=post_details&id_post=13494	ransomfeed	ransom;lockbit3;	1	2024-02-28	东船东建筑公司
634	Dinamic-Oil	http://www.ransomfeed.it/index.php?page=post_details&id_post=13497	ransomfeed	ransom;trigona;	1	2024-02-28	Dinamimimimic- Oiil 显微粒
10856	LockBit引领勒索软件进入下个时代	https://www.freebuf.com/articles/396374.html	freebuf	news;	2	2024-03-29	LockBit引领勒索软件进入下个时代
635	HAL-Allergy	http://www.ransomfeed.it/index.php?page=post_details&id_post=13498	ransomfeed	ransom;ransomhouse;	1	2024-02-28	HAL 过敏
441	红队实战小课，快来涨经验|Webshell下bypass360	https://buaq.net/go-227513.html	buaq	newscopy;	0	2024-03-12	红队实战小课，快来涨经验|Webshell下bypass360
444	How to Install .ipa Files on iPhone Without Jailbreak	https://buaq.net/go-227525.html	buaq	newscopy;	0	2024-03-12	如何在 iPhone iPhone 上安装 ipa 文件而没有破禁
445	将S端目录mount到C端文件系统中	https://buaq.net/go-227527.html	buaq	newscopy;	0	2024-03-12	将S端目录mount到C端文件系统中
446	Earth Kapre 黑客使用武器化 ISO 和 IMG 文件攻击组织	https://buaq.net/go-227528.html	buaq	newscopy;	0	2024-03-12	Earth Kapre 黑客使用武器化 ISO 和 IMG 文件攻击组织
447	Magnet Goblin 黑客组织利用 1 day 漏洞部署 Nerbian RAT	https://buaq.net/go-227529.html	buaq	newscopy;	0	2024-03-12	Magnet Goblin 黑客组织利用 1 day 漏洞部署 Nerbian RAT
449	Ultimate Member Plugin 漏洞致 10 万个 WordPress 网站遭受攻击	https://buaq.net/go-227531.html	buaq	newscopy;	0	2024-03-12	Ultimate Member Plugin 漏洞致 10 万个 WordPress 网站遭受攻击
450	意大利数据监管机构对 Sora 展开调查	https://buaq.net/go-227532.html	buaq	newscopy;	0	2024-03-12	意大利数据监管机构对 Sora 展开调查
452	马斯克的慈善基金会	https://buaq.net/go-227536.html	buaq	newscopy;	0	2024-03-12	马斯克的慈善基金会
11062	一周网安优质PDF资源推荐丨FreeBuf知识大陆	https://www.freebuf.com/news/396518.html	freebuf	news;资讯;	1	2024-03-29	一周网安优质PDF资源推荐丨FreeBuf知识大陆
453	法国政府机构遭遇 DDoS 攻击	https://buaq.net/go-227537.html	buaq	newscopy;	0	2024-03-12	法国政府机构遭遇 DDoS 攻击
11063	你们就当个故事听——黑客如何10秒钟盗走4.5万美金	https://www.freebuf.com/news/396537.html	freebuf	news;资讯;	1	2024-03-30	你们就当个故事听——黑客如何10秒钟盗走4.5万美金
455	South Korean Citizen Detained in Russia on Cyber Espionage Charges	https://buaq.net/go-227539.html	buaq	newscopy;	0	2024-03-12	南韩公民因网络间谍指控在俄罗斯被拘留
650	hvdhost	http://www.ransomfeed.it/index.php?page=post_details&id_post=13526	ransomfeed	ransom;blackbasta;	1	2024-02-29	hvdd 主机
651	Allan-Berger--Associates	http://www.ransomfeed.it/index.php?page=post_details&id_post=13527	ransomfeed	ransom;alphv;	1	2024-02-29	Allan-Berger-Associates 协会
652	Gilmore--Associates	http://www.ransomfeed.it/index.php?page=post_details&id_post=13528	ransomfeed	ransom;play;	1	2024-02-29	吉尔莫尔协会
653	Kumagai-Gumi-Group	http://www.ransomfeed.it/index.php?page=post_details&id_post=13529	ransomfeed	ransom;alphv;	1	2024-03-01	Kumagai-Gumi小组
654	CoreData	http://www.ransomfeed.it/index.php?page=post_details&id_post=13533	ransomfeed	ransom;akira;	1	2024-03-01	核心数据
655	Gansevoort-Hotel-Group	http://www.ransomfeed.it/index.php?page=post_details&id_post=13534	ransomfeed	ransom;akira;	1	2024-03-01	Gansevoort-旅馆集团
657	Gilmore-Construction	http://www.ransomfeed.it/index.php?page=post_details&id_post=13536	ransomfeed	ransom;blacksuit;	1	2024-03-01	吉尔莫尔建筑
658	Petrus-Resources-Ltd	http://www.ransomfeed.it/index.php?page=post_details&id_post=13537	ransomfeed	ransom;alphv;	1	2024-03-01	Petrus-Resources- Ltd 资源日志
659	Shooting-House-	http://www.ransomfeed.it/index.php?page=post_details&id_post=13538	ransomfeed	ransom;ransomhub;	1	2024-03-01	射击之家...
660	SBM--Co	http://www.ransomfeed.it/index.php?page=post_details&id_post=13540	ransomfeed	ransom;alphv;	1	2024-03-01	SPBM-Co 建立信任措施(SBM-Co)
661	FBi-Construction	http://www.ransomfeed.it/index.php?page=post_details&id_post=13541	ransomfeed	ransom;play;	1	2024-03-01	建 建 建
663	Compact-Mould	http://www.ransomfeed.it/index.php?page=post_details&id_post=13543	ransomfeed	ransom;play;	1	2024-03-01	契约模块
665	Marketon	http://www.ransomfeed.it/index.php?page=post_details&id_post=13545	ransomfeed	ransom;play;	1	2024-03-01	市场市场
666	Stack-Infrastructure	http://www.ransomfeed.it/index.php?page=post_details&id_post=13546	ransomfeed	ransom;play;	1	2024-03-01	堆堆基础设施
662	Red-River-Title	http://www.ransomfeed.it/index.php?page=post_details&id_post=13542	ransomfeed	ransom;play;	1	2024-03-01	红色立体文字
667	Coastal-Car	http://www.ransomfeed.it/index.php?page=post_details&id_post=13547	ransomfeed	ransom;play;	1	2024-03-01	沿海车辆
668	New-Bedford-Welding-Supply	http://www.ransomfeed.it/index.php?page=post_details&id_post=13548	ransomfeed	ransom;play;	1	2024-03-01	新贝德福德焊接供应商
669	Influence-Communication	http://www.ransomfeed.it/index.php?page=post_details&id_post=13549	ransomfeed	ransom;play;	1	2024-03-01	影响通信
381	Akaunting 3.1.3 Remote Command Execution	https://packetstormsecurity.com/files/177517/akaunting3-exec.txt	packetstorm	vuln;;	1	2024-03-11	3.1.3 远程指挥执行
671	Hedlunds	http://www.ransomfeed.it/index.php?page=post_details&id_post=13551	ransomfeed	ransom;play;	1	2024-03-01	外壳
672	Skyland-Grain	http://www.ransomfeed.it/index.php?page=post_details&id_post=13552	ransomfeed	ransom;play;	1	2024-03-02	天地草地
673	American-Nuts	http://www.ransomfeed.it/index.php?page=post_details&id_post=13553	ransomfeed	ransom;play;	1	2024-03-02	美 美 纽
674	AA-Wireless	http://www.ransomfeed.it/index.php?page=post_details&id_post=13554	ransomfeed	ransom;play;	1	2024-03-02	AA无线
676	TransPlus-Systems	http://www.ransomfeed.it/index.php?page=post_details&id_post=13556	ransomfeed	ransom;play;	1	2024-03-02	横式顶层系统
677	esser-psde	http://www.ransomfeed.it/index.php?page=post_details&id_post=13559	ransomfeed	ransom;lockbit3;	1	2024-03-02	eser- psde
679	roehr-stolbergde	http://www.ransomfeed.it/index.php?page=post_details&id_post=13561	ransomfeed	ransom;lockbit3;	1	2024-03-02	罗赫尔-斯托尔贝格德
680	schuett-grundeide	http://www.ransomfeed.it/index.php?page=post_details&id_post=13562	ransomfeed	ransom;lockbit3;	1	2024-03-02	schuett-grundeide 树脂
682	smuldescom	http://www.ransomfeed.it/index.php?page=post_details&id_post=13564	ransomfeed	ransom;lockbit3;	1	2024-03-02	smuldescom
681	unitednotionscom	http://www.ransomfeed.it/index.php?page=post_details&id_post=13563	ransomfeed	ransom;lockbit3;	1	2024-03-02	电联
241	RSA系列之进阶实战	https://xz.aliyun.com/t/13986	阿里先知实验室	news;	1	2024-03-01	RSA系列之进阶实战
683	aerospacecom	http://www.ransomfeed.it/index.php?page=post_details&id_post=13565	ransomfeed	ransom;lockbit3;	1	2024-03-02	航空航天航空航天器
684	stockdevelopmentcom	http://www.ransomfeed.it/index.php?page=post_details&id_post=13566	ransomfeed	ransom;lockbit3;	1	2024-03-03	发展股
638	HSPG--Associates	http://www.ransomfeed.it/index.php?page=post_details&id_post=13511	ransomfeed	ransom;snatch;	1	2024-02-29	HSPG - 协会
639	sunharbormanorcom	http://www.ransomfeed.it/index.php?page=post_details&id_post=13512	ransomfeed	ransom;abyss;	1	2024-02-29	日光夏博马诺康colomba. kgm
640	Benthanh-Group	http://www.ransomfeed.it/index.php?page=post_details&id_post=13516	ransomfeed	ransom;ransomhub;	1	2024-02-29	班吉小组
10264	Miki-Travel-Limited	http://www.ransomfeed.it/index.php?page=post_details&id_post=13960	ransomfeed	ransom;snatch;	1	2024-03-27	Miki- Travel- 限制
643	fcwch	http://www.ransomfeed.it/index.php?page=post_details&id_post=13519	ransomfeed	ransom;blackbasta;	1	2024-02-29	湿重( fcwch)
642	haas4com	http://www.ransomfeed.it/index.php?page=post_details&id_post=13518	ransomfeed	ransom;blackbasta;	1	2024-02-29	公顷4com
645	goodinabernathycom	http://www.ransomfeed.it/index.php?page=post_details&id_post=13521	ransomfeed	ransom;blackbasta;	1	2024-02-29	Goodinabernathycom 网络
646	Array-Networks	http://www.ransomfeed.it/index.php?page=post_details&id_post=13522	ransomfeed	ransom;dunghill_leak;	1	2024-02-29	阵列- 网络
647	Faison	http://www.ransomfeed.it/index.php?page=post_details&id_post=13523	ransomfeed	ransom;dragonforce;	1	2024-02-29	Faiear 传真
649	Artissimo-Designs	http://www.ransomfeed.it/index.php?page=post_details&id_post=13525	ransomfeed	ransom;dragonforce;	1	2024-02-29	艺术设计
10871	暗藏 11 年的 Linux 漏洞曝光，可用于伪造 SUDO 命令	https://www.freebuf.com/news/396355.html	freebuf	news;资讯;	3	2024-03-29	暗藏 11 年的 Linux 漏洞曝光，可用于伪造 SUDO 命令
695	Centennial-Law-Group-LLP	http://www.ransomfeed.it/index.php?page=post_details&id_post=13577	ransomfeed	ransom;medusa;	1	2024-03-03	百年法律小组
698	Martins-Inc	http://www.ransomfeed.it/index.php?page=post_details&id_post=13580	ransomfeed	ransom;bianlian;	1	2024-03-04	马丁斯 Inc
699	jovanicom	http://www.ransomfeed.it/index.php?page=post_details&id_post=13581	ransomfeed	ransom;lockbit3;	1	2024-03-04	经济、社会和文化权利
700	valoremreplycom	http://www.ransomfeed.it/index.php?page=post_details&id_post=13582	ransomfeed	ransom;lockbit3;	1	2024-03-04	价格restreplycom
702	DiVal-Safety-Equipment-Inc	http://www.ransomfeed.it/index.php?page=post_details&id_post=13584	ransomfeed	ransom;hunters;	1	2024-03-04	迪瓦尔-安全设备
703	dismogas	http://www.ransomfeed.it/index.php?page=post_details&id_post=13585	ransomfeed	ransom;stormous;	1	2024-03-04	甲烷
704	everplast	http://www.ransomfeed.it/index.php?page=post_details&id_post=13586	ransomfeed	ransom;stormous;	1	2024-03-04	雪花
705	Paul-Davis-Restoration	http://www.ransomfeed.it/index.php?page=post_details&id_post=13587	ransomfeed	ransom;medusa;	1	2024-03-04	保罗-戴维斯-恢复
706	Veeco	http://www.ransomfeed.it/index.php?page=post_details&id_post=13588	ransomfeed	ransom;medusa;	1	2024-03-04	维科
707	Seven-Seas-Group	http://www.ransomfeed.it/index.php?page=post_details&id_post=13590	ransomfeed	ransom;snatch;	1	2024-03-05	七海小组
708	Future-Generations-Foundation	http://www.ransomfeed.it/index.php?page=post_details&id_post=13591	ransomfeed	ransom;meow;	1	2024-03-05	未来基金会-未来基金会
709	iemsccom	http://www.ransomfeed.it/index.php?page=post_details&id_post=13592	ransomfeed	ransom;qilin;	1	2024-03-05	iemsccom (iemsccom )
710	hawita-gruppe	http://www.ransomfeed.it/index.php?page=post_details&id_post=13593	ransomfeed	ransom;qilin;	1	2024-03-05	哈维塔- 格鲁普
711	centralk12orus	http://www.ransomfeed.it/index.php?page=post_details&id_post=13594	ransomfeed	ransom;lockbit3;	1	2024-03-05	中中k12orus
712	SJCMEEDU	http://www.ransomfeed.it/index.php?page=post_details&id_post=13595	ransomfeed	ransom;clop;	1	2024-03-05	谢米杜
713	toxchat	http://www.ransomfeed.it/index.php?page=post_details&id_post=13596	ransomfeed	ransom;stormous;	1	2024-03-05	托x聊天
714	sunwavecomcn	http://www.ransomfeed.it/index.php?page=post_details&id_post=13597	ransomfeed	ransom;lockbit3;	1	2024-03-05	太阳电波
715	airbogo	http://www.ransomfeed.it/index.php?page=post_details&id_post=13598	ransomfeed	ransom;stormous;	1	2024-03-05	空斗
716	Ko	http://www.ransomfeed.it/index.php?page=post_details&id_post=13599	ransomfeed	ransom;play;	1	2024-03-06	Ko Ko 高
717	Mediplast-AB	http://www.ransomfeed.it/index.php?page=post_details&id_post=13600	ransomfeed	ransom;8base;	1	2024-03-06	医疗-AB型
718	Enplast	http://www.ransomfeed.it/index.php?page=post_details&id_post=13601	ransomfeed	ransom;8base;	1	2024-03-06	放大器
719	Kudulis-Reisinger-Price	http://www.ransomfeed.it/index.php?page=post_details&id_post=13602	ransomfeed	ransom;8base;	1	2024-03-06	Kudulis- Reminiser- price 库杜利斯- Reminiser- 原始本
720	Global-Zone	http://www.ransomfeed.it/index.php?page=post_details&id_post=13603	ransomfeed	ransom;8base;	1	2024-03-06	全球合作区
721	Biomedical-Research-Institute	http://www.ransomfeed.it/index.php?page=post_details&id_post=13604	ransomfeed	ransom;meow;	1	2024-03-06	生物医学研究所
722	Steiner-Austrian-furniture-makers	http://www.ransomfeed.it/index.php?page=post_details&id_post=13605	ransomfeed	ransom;akira;	1	2024-03-06	施泰纳-奥地利家具制造商
724	Telecentro	http://www.ransomfeed.it/index.php?page=post_details&id_post=13607	ransomfeed	ransom;akira;	1	2024-03-06	电电电中心
725	brightwirescomsa	http://www.ransomfeed.it/index.php?page=post_details&id_post=13608	ransomfeed	ransom;qilin;	1	2024-03-06	光电网a
726	Infosoft	http://www.ransomfeed.it/index.php?page=post_details&id_post=13609	ransomfeed	ransom;akira;	1	2024-03-06	信息软件
728	viadirectamarketing	http://www.ransomfeed.it/index.php?page=post_details&id_post=13611	ransomfeed	ransom;stormous;	1	2024-03-06	中转市场
729	Haivision-MCS	http://www.ransomfeed.it/index.php?page=post_details&id_post=13612	ransomfeed	ransom;medusa;	1	2024-03-06	医务和医务司
730	Tocci-Building-Corporation	http://www.ransomfeed.it/index.php?page=post_details&id_post=13613	ransomfeed	ransom;medusa;	1	2024-03-06	建立和安置行动
731	JVCKENWOOD-	http://www.ransomfeed.it/index.php?page=post_details&id_post=13614	ransomfeed	ransom;medusa;	1	2024-03-06	约肯沃德...
685	Ewig-Usa	http://www.ransomfeed.it/index.php?page=post_details&id_post=13567	ransomfeed	ransom;alphv;	1	2024-03-03	埃维格乌萨
687	Ponokaca	http://www.ransomfeed.it/index.php?page=post_details&id_post=13569	ransomfeed	ransom;cloak;	1	2024-03-03	波诺卡卡语Name
688	Ward-Transport--Logistics	http://www.ransomfeed.it/index.php?page=post_details&id_post=13570	ransomfeed	ransom;dragonforce;	1	2024-03-03	沃德-运输-运输-后勤
689	earnesthealthcom	http://www.ransomfeed.it/index.php?page=post_details&id_post=13571	ransomfeed	ransom;lockbit3;	1	2024-03-03	热心健康委员会
10265	tmt-mcjp	http://www.ransomfeed.it/index.php?page=post_details&id_post=13961	ransomfeed	ransom;lockbit3;	1	2024-03-27	tmt- mcjp 平方公尺
692	THESAFIRCHOICECOM	http://www.ransomfeed.it/index.php?page=post_details&id_post=13574	ransomfeed	ransom;clop;	1	2024-03-03	嘉宾
691	THAISUMMITUS	http://www.ransomfeed.it/index.php?page=post_details&id_post=13573	ransomfeed	ransom;clop;	1	2024-03-03	东京
693	Prompt-Financial-Solutions-	http://www.ransomfeed.it/index.php?page=post_details&id_post=13575	ransomfeed	ransom;medusa;	1	2024-03-03	即时金融解决办法
694	Sophiahemmet-University-	http://www.ransomfeed.it/index.php?page=post_details&id_post=13576	ransomfeed	ransom;medusa;	1	2024-03-03	索菲亚赫梅特大学
747	elsapspa	http://www.ransomfeed.it/index.php?page=post_details&id_post=13632	ransomfeed	ransom;donex;	1	2024-03-08	螺旋藻
748	SIEA-	http://www.ransomfeed.it/index.php?page=post_details&id_post=13633	ransomfeed	ransom;ransomhub;	1	2024-03-08	SIEA - SIEA -
749	Hozzify-	http://www.ransomfeed.it/index.php?page=post_details&id_post=13634	ransomfeed	ransom;ransomhub;	1	2024-03-08	震动 -
750	Denningers-	http://www.ransomfeed.it/index.php?page=post_details&id_post=13635	ransomfeed	ransom;medusa;	1	2024-03-08	丹宁纳斯...
751	PowerRail-Distribution	http://www.ransomfeed.it/index.php?page=post_details&id_post=13637	ransomfeed	ransom;blacksuit;	1	2024-03-08	PowerRail 分配
752	redwoodcoastrcorg	http://www.ransomfeed.it/index.php?page=post_details&id_post=13638	ransomfeed	ransom;lockbit3;	1	2024-03-08	红木coastrcorg
754	Watsoncliniccom	http://www.ransomfeed.it/index.php?page=post_details&id_post=13640	ransomfeed	ransom;donutleaks;	1	2024-03-09	华氏诊所
755	ACE-Air-Cargo	http://www.ransomfeed.it/index.php?page=post_details&id_post=13641	ransomfeed	ransom;hunters;	1	2024-03-09	ACE-Air-卡尔戈
756	Group-Health-Cooperative---Rev-500kk	http://www.ransomfeed.it/index.php?page=post_details&id_post=13644	ransomfeed	ransom;blacksuit;	1	2024-03-09	健康-合作-Rev-500kk小组
9993	Worldwide Agenda Ransomware Wave Targets VMware ESXi Servers	https://www.darkreading.com/cloud-security/agenda-ransomware-vmware-esxi-servers	darkreading	news;	2	2024-03-26	VMware ESXi服务器
758	Lindsay-Municipal-Hospital	http://www.ransomfeed.it/index.php?page=post_details&id_post=13646	ransomfeed	ransom;bianlian;	1	2024-03-09	Lindsay-Munisi市-医院
759	H--G-EDV-Vertriebs	http://www.ransomfeed.it/index.php?page=post_details&id_post=13647	ransomfeed	ransom;blacksuit;	1	2024-03-09	H-G-EDV-异丁酯
760	Rekamy-	http://www.ransomfeed.it/index.php?page=post_details&id_post=13648	ransomfeed	ransom;ransomhub;	1	2024-03-09	礼卡米...
762	DVT-	http://www.ransomfeed.it/index.php?page=post_details&id_post=13651	ransomfeed	ransom;ransomhub;	1	2024-03-09	DVT - 电磁脉冲
763	httpswwwconsorzioinnovait	http://www.ransomfeed.it/index.php?page=post_details&id_post=13652	ransomfeed	ransom;mydata;	1	2024-03-09	httpswwwconsorzioinnovait
764	Scadea-Solutions-	http://www.ransomfeed.it/index.php?page=post_details&id_post=13654	ransomfeed	ransom;ransomhub;	1	2024-03-11	剧本解决方案...
765	ammegacom	http://www.ransomfeed.it/index.php?page=post_details&id_post=13656	ransomfeed	ransom;cactus;	1	2024-03-11	亚美加( Amegacom)
766	renypicotes	http://www.ransomfeed.it/index.php?page=post_details&id_post=13657	ransomfeed	ransom;cactus;	1	2024-03-11	重显式
767	gpaagovza	http://www.ransomfeed.it/index.php?page=post_details&id_post=13658	ransomfeed	ransom;lockbit3;	1	2024-03-11	gpaagovza (千人)
768	NetVigour	http://www.ransomfeed.it/index.php?page=post_details&id_post=13659	ransomfeed	ransom;hunters;	1	2024-03-11	网网
769	clesharcouk	http://www.ransomfeed.it/index.php?page=post_details&id_post=13660	ransomfeed	ransom;cactus;	1	2024-03-11	Clesharcouk( 立方体)
770	neigccom	http://www.ransomfeed.it/index.php?page=post_details&id_post=13661	ransomfeed	ransom;abyss;	1	2024-03-11	内基氯
771	plymouthcom	http://www.ransomfeed.it/index.php?page=post_details&id_post=13663	ransomfeed	ransom;cactus;	1	2024-03-11	普利茅斯康
772	Computan-	http://www.ransomfeed.it/index.php?page=post_details&id_post=13665	ransomfeed	ransom;ransomhub;	1	2024-03-11	费用 -
774	londonvisioncliniccom	http://www.ransomfeed.it/index.php?page=post_details&id_post=13667	ransomfeed	ransom;lockbit3;	1	2024-03-11	伦敦市立诊所
761	go4kora-	http://www.ransomfeed.it/index.php?page=post_details&id_post=13649	ransomfeed	ransom;ransomhub;	1	2024-03-09	歌 - 歌 - 歌 - 歌 - 歌 - 歌
776	SREE-Hotels	http://www.ransomfeed.it/index.php?page=post_details&id_post=13669	ransomfeed	ransom;play;	1	2024-03-11	SREE-旅馆
778	QI-Group	http://www.ransomfeed.it/index.php?page=post_details&id_post=13671	ransomfeed	ransom;play;	1	2024-03-11	QI小组
777	Q-o	http://www.ransomfeed.it/index.php?page=post_details&id_post=13670	ransomfeed	ransom;play;	1	2024-03-11	Q - o Q - o
9974	HIPAA Compliance: Why It Matters and How to Obtain It	https://securityboulevard.com/2024/03/hipaa-compliance-why-it-matters-and-how-to-obtain-it-2/	securityboulevard	news;Data Security;Security Bloggers Network;Blog Posts;Cybersecurity;Data Privacy;	1	2024-03-26	HIPAA 遵约:为何重要和如何获得
779	BiTec	http://www.ransomfeed.it/index.php?page=post_details&id_post=13672	ransomfeed	ransom;play;	1	2024-03-11	Bitec 比特克
733	US-1364-Federal-Credit-Union	http://www.ransomfeed.it/index.php?page=post_details&id_post=13616	ransomfeed	ransom;medusa;	1	2024-03-06	US-1364-联邦-信贷联盟
734	MainVest	http://www.ransomfeed.it/index.php?page=post_details&id_post=13617	ransomfeed	ransom;play;	1	2024-03-06	主要大小
735	wwwloghmanpharmacom	http://www.ransomfeed.it/index.php?page=post_details&id_post=13620	ransomfeed	ransom;stormous;	1	2024-03-07	wwwloghmanpharmacom
738	SP-Mundi-	http://www.ransomfeed.it/index.php?page=post_details&id_post=13623	ransomfeed	ransom;ransomhub;	1	2024-03-07	SP - Mundi - 苏 - 蒙迪 -
739	en-act-architecture	http://www.ransomfeed.it/index.php?page=post_details&id_post=13624	ransomfeed	ransom;qilin;	1	2024-03-07	enact- 结构
742	rmhfranchisecom	http://www.ransomfeed.it/index.php?page=post_details&id_post=13627	ransomfeed	ransom;lockbit3;	1	2024-03-07	rmhhfranchisecom( rmhfnixiscom) 中
740	Palmer-Construction-Co-Inc	http://www.ransomfeed.it/index.php?page=post_details&id_post=13625	ransomfeed	ransom;bianlian;	1	2024-03-07	帕尔默建筑公司
743	CHOCOTOPIA	http://www.ransomfeed.it/index.php?page=post_details&id_post=13628	ransomfeed	ransom;donex;	1	2024-03-08	查 哥 比 亚
744	mirel	http://www.ransomfeed.it/index.php?page=post_details&id_post=13629	ransomfeed	ransom;donex;	1	2024-03-08	美日
745	vdhelm	http://www.ransomfeed.it/index.php?page=post_details&id_post=13630	ransomfeed	ransom;donex;	1	2024-03-08	摆
746	PFLEET	http://www.ransomfeed.it/index.php?page=post_details&id_post=13631	ransomfeed	ransom;donex;	1	2024-03-08	方 法
431	BianLian Hackers Hijacked TeamCity Servers To Install GO Backdoor	https://gbhackers.com/bianlians-go-backdoor/	GBHacker	news;Cyber Attack;cyber security;Cyber Security News;Malware;	1	2024-03-12	BianLian Hackers 劫持团队城市服务器安装 GO 后门
10218	 Mind the Patch Gap: Exploiting an io_uring Vulnerability in Ubuntu 	https://blog.exodusintel.com/2024/03/27/mind-the-patch-gap-exploiting-an-io_uring-vulnerability-in-ubuntu/	exodusintel	vuln; Exodus Intel VRT ;By Oriol Castejón Overview In early January 2024, a Project Zero issue for a recently fixed io_uring use-after-free (UAF) vulnerability (CVE-2024-0582) was made public. Reading the; Read More ;	1	2024-03-27	注意补差:利用乌邦图的脆弱程度
627	Hypertension-Nephrology-Associates-PC	http://www.ransomfeed.it/index.php?page=post_details&id_post=13488	ransomfeed	ransom;bianlian;	1	2024-02-28	超高电超-肾上腺学-联合-PC
792	Sprimoglass	http://www.ransomfeed.it/index.php?page=post_details&id_post=13685	ransomfeed	ransom;8base;	1	2024-03-12	螺旋玻璃
10001	How New-Age Hackers Are Ditching Old Ethics	https://www.darkreading.com/cyberattacks-data-breaches/how-new-age-hackers-are-ditching-old-ethics	darkreading	news;	1	2024-03-26	新时代黑客如何抛弃旧道德
10002	Abstract Security Brings AI to Next-Gen SIEM	https://www.darkreading.com/cybersecurity-analytics/abstract-security-brings-ai-to-next-gen-siem	darkreading	news;	1	2024-03-26	安全摘要将AI带入下Gen SIEM
38	Over 100 Malicious AI/ML Models Found on Hugging Face Platform	https://thehackernews.com/2024/03/over-100-malicious-aiml-models-found-on.html	feedburner	news;	1	2024-03-04	在 " 拥抱脸面平台 " 上发现的100多个恶意的AI/ML模型
782	Fashion-UK	http://www.ransomfeed.it/index.php?page=post_details&id_post=13675	ransomfeed	ransom;play;	1	2024-03-11	联合王国时装公司
9	Alert: GhostSec and Stormous Launch Joint Ransomware Attacks in Over 15 Countries	https://thehackernews.com/2024/03/alert-ghostsec-and-stormous-launch.html	feedburner	news;	2	2024-03-06	警报:在超过15个国家进行 " 幽灵安全 " 和 " 风暴联合发射 " 联合核磁器袭击
31	Meta Details WhatsApp and Messenger Interoperability to Comply with EU's DMA Regulations	https://thehackernews.com/2024/03/meta-details-whatsapp-and-messenger.html	feedburner	news;	1	2024-03-08	符合欧盟《目的地管理条例》的Metet Detact whatsApp和信使互操作性
25	Hackers Exploit Misconfigured YARN, Docker, Confluence, Redis Servers for Crypto Mining	https://thehackernews.com/2024/03/hackers-exploit-misconfigured-yarn.html	feedburner	news;	1	2024-03-06	Hackers Hackers 开发错误配置为YARN、Docker、Copplus、Redis 加密采矿服务器
785	Ruda-Auto	http://www.ransomfeed.it/index.php?page=post_details&id_post=13678	ransomfeed	ransom;play;	1	2024-03-11	鲁达自动
41	Proof-of-Concept Exploit Released for Progress Software OpenEdge Vulnerability	https://thehackernews.com/2024/03/proof-of-concept-exploit-released-for.html	feedburner	news;	1	2024-03-11	用于进步软件开放电子脆弱性的开发概念证据
83	The Week in Ransomware - March 8th 2024 - Waiting for the BlackCat rebrand	https://www.bleepingcomputer.com/news/security/the-week-in-ransomware-march-8th-2024-waiting-for-the-blackcat-rebrand/	bleepingcomputer	news;Security;	2	2024-03-08	Ransomware的周 - 2024年3月8日 - 等待黑Cat的重命名
20	Five Eyes Agencies Warn of Active Exploitation of Ivanti Gateway Vulnerabilities	https://thehackernews.com/2024/03/five-eyes-agencies-warn-of-active.html	feedburner	news;	1	2024-03-01	五眼机构积极利用Ivanti网关脆弱性的警告
60	Network tunneling with… QEMU?	https://securelist.com/network-tunneling-with-qemu/111803/	securelist	news;Research;Malware Technologies;RDP;Virtualization;Internal threats;	1	2024-03-05	与... QEMU联网隧道?
36	New Phishing Kit Leverages SMS, Voice Calls to Target Cryptocurrency Users	https://thehackernews.com/2024/03/new-phishing-kit-leverages-sms-voice.html	feedburner	news;	1	2024-03-01	新的幻影工具包使用短讯、语音呼叫以锁定加密货币用户
786	Image-Pointe	http://www.ransomfeed.it/index.php?page=post_details&id_post=13679	ransomfeed	ransom;play;	1	2024-03-11	图像点
14	Critical JetBrains TeamCity On-Premises Flaws Could Lead to Server Takeovers	https://thehackernews.com/2024/03/critical-jetbrains-teamcity-on-premises.html	feedburner	news;	1	2024-03-05	至关重要的喷气引擎团队 City On-Primes Flaws 能够导致服务器接管
4755	AT&T says leaked data of 70 million people is not from its systems	https://www.bleepingcomputer.com/news/security/att-says-leaked-data-of-70-million-people-is-not-from-its-systems/	bleepingcomputer	news;Security;	1	2024-03-17	截止时间
47	U.S. Cracks Down on Predatory Spyware Firm for Targeting Officials and Journalists	https://thehackernews.com/2024/03/us-cracks-down-on-predatory-spyware.html	feedburner	news;	1	2024-03-06	美国打击攻击目标官员和记者的掠夺性间谍间谍企业
4756	Former telecom manager admits to doing SIM swaps for $1,000	https://www.bleepingcomputer.com/news/security/former-telecom-manager-admits-to-doing-sim-swaps-for-1-000/	bleepingcomputer	news;Security;Legal;	1	2024-03-15	前电信经理承认 做SIM换价1000美元
53	USB 设备开发：从入门到实践指南（三）	https://paper.seebug.org/3124/	seebug	news;安全工具&安全开发;经验心得;404专栏;	1	2024-02-29	USB 设备开发：从入门到实践指南（三）
4757	Hackers exploit Aiohttp bug to find vulnerable networks	https://www.bleepingcomputer.com/news/security/hackers-exploit-aiohttp-bug-to-find-vulnerable-networks/	bleepingcomputer	news;Security;	1	2024-03-16	黑客利用Aiohttpbug来寻找脆弱的网络
784	White-Oak-Partners	http://www.ransomfeed.it/index.php?page=post_details&id_post=13677	ransomfeed	ransom;play;	1	2024-03-11	白橡白伙伴
787	Schokinag	http://www.ransomfeed.it/index.php?page=post_details&id_post=13680	ransomfeed	ransom;play;	1	2024-03-11	Schokinag 方形
781	Grassmid-Transport	http://www.ransomfeed.it/index.php?page=post_details&id_post=13674	ransomfeed	ransom;play;	1	2024-03-11	草 草 运
788	Zips-Car-Wash	http://www.ransomfeed.it/index.php?page=post_details&id_post=13681	ransomfeed	ransom;play;	1	2024-03-11	Zips-car-Wash
790	Federchimica	http://www.ransomfeed.it/index.php?page=post_details&id_post=13683	ransomfeed	ransom;8base;	1	2024-03-12	费德奇米卡
789	Bechtold	http://www.ransomfeed.it/index.php?page=post_details&id_post=13682	ransomfeed	ransom;play;	1	2024-03-11	贝赫图尔德
101	China-Linked Cyber Spies Blend Watering Hole, Supply Chain Attacks	https://www.darkreading.com/cyberattacks-data-breaches/china-linked-cyber-spies-blend-watering-hole-supply-chain-attacks	darkreading	news;	4	2024-03-07	中国连连连的网络间谍连结水洞、供应链袭击
7113	听不清，别乱传！	https://www.freebuf.com/articles/395151.html	freebuf	news;	1	2024-03-18	听不清，别乱传！
9987	Hackers exploit Ray framework flaw to breach servers, hijack resources	https://www.bleepingcomputer.com/news/security/hackers-exploit-ray-framework-flaw-to-breach-servers-hijack-resources/	bleepingcomputer	news;Security;Artificial Intelligence;	1	2024-03-26	黑客利用雷框架缺陷 破坏服务器 劫持资源
224	利用Zoom的零接触配置（ Zero Touch Provision）进行远程攻击：针对桌面电话的入侵方法	https://xz.aliyun.com/t/13948	阿里先知实验室	news;	1	2024-02-29	利用Zoom的零接触配置（ Zero Touch Provision）进行远程攻击：针对桌面电话的入侵方法
234	[翻译]-通过EDR预加载来绕过EDR	https://xz.aliyun.com/t/13971	阿里先知实验室	news;	1	2024-02-29	[翻译]-通过EDR预加载来绕过EDR
237	一款使用邮件发送受害者信息的蠕虫病毒分析	https://xz.aliyun.com/t/13979	阿里先知实验室	news;	1	2024-03-01	一款使用邮件发送受害者信息的蠕虫病毒分析
4759	New acoustic attack determines keystrokes from typing patterns	https://www.bleepingcomputer.com/news/security/new-acoustic-attack-determines-keystrokes-from-typing-patterns/	bleepingcomputer	news;Security;	1	2024-03-17	新的声学攻击决定了打字模式的按键
678	starkpowerde	http://www.ransomfeed.it/index.php?page=post_details&id_post=13560	ransomfeed	ransom;lockbit3;	1	2024-03-02	赤电
100	BlackCat Goes Dark After Ripping Off Change Healthcare Ransom	https://www.darkreading.com/cyberattacks-data-breaches/blackcat-goes-dark-again-reportedly-rips-off-change-healthcare-ransom	darkreading	news;	2	2024-03-05	改变医疗疗养疗养疗养疗养所后,
9043	KIUP	http://www.ransomfeed.it/index.php?page=post_details&id_post=13855	ransomfeed	ransom;raworld;	1	2024-03-21	木 木 木 木 木
9044	Stnc	http://www.ransomfeed.it/index.php?page=post_details&id_post=13856	ransomfeed	ransom;raworld;	1	2024-03-21	Stnc 点记
10872	为阻止恶意软件活动蔓延，PyPI 暂停新用户注册	https://www.freebuf.com/news/396434.html	freebuf	news;资讯;	2	2024-03-29	为阻止恶意软件活动蔓延，PyPI 暂停新用户注册
115	Horizon3.ai Unveils Pentesting Services for Compliance Ahead of PCI DSS v4.0 Rollout	https://www.darkreading.com/cybersecurity-operations/horizon3-ai-unveils-pentesting-services-for-compliance-ahead-of-pci-dss-v4-0-rollout	darkreading	news;	1	2024-03-05	在PCI DSS v4.0 推出之前为合规服务提供Unveils Pen测试服务
10877	How much does cloud-based identity expand your attack surface?	https://www.helpnetsecurity.com/2024/03/29/cloud-based-identity-management/	helpnetsecurity	news;Don't miss;Expert analysis;Expert corner;Hot stuff;News;access management;credentials;cybersecurity;identity;identity management;IS Decisions;opinion;risk management;	1	2024-03-29	云基身份能增加多少攻击面?
131	South Korean Police Deploy Deepfake Detection Tool in Run-up to Elections	https://www.darkreading.com/threat-intelligence/south-korean-police-deepfake-detection-tool-run-up-elections	darkreading	news;	3	2024-03-08	韩国警察部署深假侦查工具
133	Don't Give Your Business Data to AI Companies	https://www.darkreading.com/vulnerabilities-threats/dont-give-your-business-data-to-ai-companies	darkreading	news;	1	2024-03-07	不要把你的商业数据给AI公司
134	Nigerian National Pleads Guilty of Conspiracy in BEC Operation	https://www.darkreading.com/vulnerabilities-threats/nigerian-national-pleads-guilty-conspiracy-bec-operation	darkreading	news;	1	2024-03-08	尼日利亚国家被告在BEC行动中犯有共谋阴谋罪
142	FBI's 2023 Internet Crime Report Highlights Alarming Trends on Ransomware	https://blog.knowbe4.com/fbi-2023-internet-crime-report-highlights-ransomware	knowbe4	news;Phishing;Security Awareness Training;Cybercrime;Ransomware;	2	2024-03-11	FBI2023年的互联网犯罪报告 突出地揭露了兰索姆软件的警示趋势
10003	It's Time to Stop Measuring Security in Absolutes	https://www.darkreading.com/cybersecurity-analytics/time-to-stop-measuring-security-in-absolutes	darkreading	news;	1	2024-03-25	现在是停止测量绝对安全的时候了
10005	Apple Security Bug Opens iPhone, iPad to RCE	https://www.darkreading.com/endpoint-security/apple-security-bug-opens-iphone-ipad-rce	darkreading	news;	2	2024-03-26	苹果安全错误 打开iPhone, iPad to RCE
10006	Dubious NuGet Package May Portend Chinese Industrial Espionage	https://www.darkreading.com/ics-ot-security/dubious-nuget-package-chinese-industrial-espionage	darkreading	news;	4	2024-03-26	Dubious Nuget 软件包 5 : 中国工业间谍
163	FreeBuf 早报 | Midjourney封禁Stability AI；Rhysida勒索团伙已出售儿童患者数据	https://www.freebuf.com/news/393832.html	freebuf	news;资讯;	1	2024-03-08	FreeBuf 早报 | Midjourney封禁Stability AI；Rhysida勒索团伙已出售儿童患者数据
155	driftingbules:5 靶场解析及复现	https://www.freebuf.com/articles/web/387370.html	freebuf	news;Web安全;	1	2024-03-08	driftingbules:5 靶场解析及复现
5872	APT28 Hacker Group Targeting Europe, Americas, Asia in Widespread Phishing Scheme	https://buaq.net/go-228717.html	buaq	newscopy;	0	2024-03-18	APT28 以欧洲、美洲、亚洲为对象的黑客集团
5873	/r/ReverseEngineering's Weekly Questions Thread	https://buaq.net/go-228721.html	buaq	newscopy;	0	2024-03-18	/r/反反工程周刊问题线索
5874	Top things that you might not be doing (yet) in Entra Conditional Access – Advanced Edition	https://buaq.net/go-228722.html	buaq	newscopy;	0	2024-03-18	在有条件访问 — 高级版中,你可能没有做(尚未)的顶级工作
723	Medical-Billing-Specialists	http://www.ransomfeed.it/index.php?page=post_details&id_post=13606	ransomfeed	ransom;akira;	1	2024-03-06	医药 -- -- 自行车 -- -- 专家
171	网安并购 | 拟出资19亿元，控股国盾量子	https://www.freebuf.com/news/394070.html	freebuf	news;资讯;	1	2024-03-12	网安并购 | 拟出资19亿元，控股国盾量子
219	java原生反序列化OverlongEncoding分析及实战	https://xz.aliyun.com/t/13932	阿里先知实验室	news;	1	2024-02-29	java原生反序列化OverlongEncoding分析及实战
292	Airbnb Bans All Indoor Security Cameras	https://www.wired.com/story/airbnb-indoor-security-camera-ban/	wired	news;Security;Security / Privacy;Business / Startups;	1	2024-03-11	禁止所有室内安保摄像头
324	elFinder Web file manager Version 2.1.53 Remote Command Execution	https://cxsecurity.com/issue/WLB-2024030012	cxsecurity	vuln;	1	2024-03-06	elFinderWeb 文件管理器 2.1.53 版本 2.1.53 远程指令执行
341	WordPress IDonate Blood Request Management System 1.8.1 Cross Site Scripting	https://cxsecurity.com/issue/WLB-2024020096	cxsecurity	vuln;	1	2024-02-29	WordPress 捐赠血液请求管理系统 1.8.1 跨站点脚本
349	Membership Management System 1.0 SQL Injection	https://cxsecurity.com/issue/WLB-2024030001	cxsecurity	vuln;	1	2024-03-01	成员管理系统1.0 SQL 注射
286	AI安全：生成式AI原理与应用分析	https://xz.aliyun.com/t/14078	阿里先知实验室	news;	1	2024-03-11	AI安全：生成式AI原理与应用分析
253	Apache OFBiz 路径遍历致权限绕过漏洞分析(CVE-2024-25065)	https://xz.aliyun.com/t/14017	阿里先知实验室	news;	5	2024-03-01	Apache OFBiz 路径遍历致权限绕过漏洞分析(CVE-2024-25065)
277	【翻译】GhostSec的联合勒索活动及其武器库的演变	https://xz.aliyun.com/t/14067	阿里先知实验室	news;	1	2024-03-10	【翻译】GhostSec的联合勒索活动及其武器库的演变
374	Ubuntu Security Notice USN-6684-1	https://packetstormsecurity.com/files/177510/USN-6684-1.txt	packetstorm	vuln;;	1	2024-03-08	Ubuntu Ubuntu 安全通知 USN6684-1
405	Kali Linux 2024.1 - Penetration Testing and Ethical Hacking Linux Distribution	http://www.kitploit.com/2024/03/kali-linux-20241-penetration-testing.html	kitploit	tool;Distribution;Distro;Kali;Kali Linux;Linux;Penetration Testing Distribution;Pentesting Distribution;	1	2024-03-03	Kali Linux 20244.1 - 渗透测试和伦理黑客Linux分发
309	Russian Hackers Stole Microsoft Source Code—and the Attack Isn’t Over	https://www.wired.com/story/russia-hackers-microsoft-source-code/	wired	news;Security;Security / Cyberattacks and Hacks;Security / National Security;Security / Privacy;Security / Security News;	3	2024-03-09	俄罗斯黑客偷走微软源代码——攻击没有结束
357	Artica Proxy 4.40 / 4.50 Local File Inclusion / Traversal	https://cxsecurity.com/issue/WLB-2024030010	cxsecurity	vuln;	1	2024-03-06	Artica 代理代理 4.40 / 4.50 本地文件包容/Traversal
4761	McDonald's: Global outage was caused by 'configuration change'	https://www.bleepingcomputer.com/news/technology/mcdonalds-global-outage-was-caused-by-configuration-change/	bleepingcomputer	news;Technology;	1	2024-03-15	麦当劳:全球停电是由“配置变化”引起的。
373	Ubuntu Security Notice USN-6682-1	https://packetstormsecurity.com/files/177509/USN-6682-1.txt	packetstorm	vuln;;	1	2024-03-08	Ubuntu Ubuntu 安全通知 USN6682-1
246	基于TLS回调的PE文件导入表项混淆 - 混淆部分	https://xz.aliyun.com/t/13998	阿里先知实验室	news;	1	2024-03-01	基于TLS回调的PE文件导入表项混淆 - 混淆部分
367	Backdoor.Win32.Beastdoor.oq / Unauthenticated Remote Command Execution	https://cxsecurity.com/issue/WLB-2024030023	cxsecurity	vuln;	1	2024-03-11	Win32. 野兽门.oq/未经认证的远程指令执行
380	Hitachi NAS SMU Backup And Restore Insecure Direct Object Reference	https://packetstormsecurity.com/files/177516/hnassmubr148782501-idor.txt	packetstorm	vuln;;	1	2024-03-11	Hitachi NAS SMU SMU 备份和恢复不安全的直接物体参考
317	Deceptive AI content and 2024 elections – Week in security with Tony Anscombe	https://www.welivesecurity.com/en/videos/deceptive-ai-content-2024-elections-week-security-tony-anscombe/	eset	news;	1	2024-03-01	与托尼·安斯科姆(Tony Ascombe)的“安全周”
3846	New DOD cyber policy office opening soon, sources say	https://therecord.media/new-top-pentagon-cyber-policy-office-opening-soon	therecord	ransom;Government;Leadership;News;	1	2024-03-14	消息人士说,新的国防部网络政策办公室即将开张
9924	Beware of New ‘HelloFire’ Ransomware Actor Mimic as a Pentester	https://gbhackers.com/beware-new-hellofire-ransomware/	GBHacker	news;cyber security;Cyber Security News;Malware;Ransomware;ransomware;	2	2024-03-25	当心新`Hello Fire' 的兰索莫软件动作器像彭太斯特那样的 Mimimimic
4762	McDonald's IT systems outage impacts restaurants worldwide	https://www.bleepingcomputer.com/news/technology/mcdonalds-it-systems-outage-impacts-restaurants-worldwide/	bleepingcomputer	news;Technology;	1	2024-03-15	麦当劳信息技术系统失灵对全世界餐馆的影响
330	Hitachi NAS SMU Backup And Restore Insecure Direct Object Reference	https://cxsecurity.com/issue/WLB-2024030020	cxsecurity	vuln;	1	2024-03-11	Hitachi NAS SMU SMU 备份和恢复不安全的直接物体参考
9995	Patch Now: Critical Fortinet RCE Bug Under Active Attack	https://www.darkreading.com/cloud-security/patch-critical-fortinet-rce-bug-active-attack	darkreading	news;	1	2024-03-26	现在的补丁: 关键要塞 RCE 臭虫在主动攻击中
321	Ficus Global - Blind Sql Injection	https://cxsecurity.com/issue/WLB-2024020094	cxsecurity	vuln;	1	2024-02-28	全球光学 -- -- 盲人Sql注射
791	CHRG	http://www.ransomfeed.it/index.php?page=post_details&id_post=13684	ransomfeed	ransom;8base;	1	2024-03-12	CHRG
775	lec-londonuk	http://www.ransomfeed.it/index.php?page=post_details&id_post=13668	ransomfeed	ransom;lockbit3;	1	2024-03-11	莱克- 隆多努克
301	Here Are the Google and Microsoft Security Updates You Need Right Now	https://www.wired.com/story/here-are-the-microsoft-and-google-security-updates-you-need-right-now/	wired	news;Security;Security / Cyberattacks and Hacks;Security / Security Advice;	1	2024-02-29	这是谷歌和微软安全最新消息 你现在需要的
398	British authorities have never detected a breach of ransomware sanctions — but is that good or bad news?	https://therecord.media/uk-authorities-have-never-detected-ransomware-payment-sanction-violation	therecord	ransom;Cybercrime;Government;News;	2	2024-03-11	英国当局从未发现违反赎金软件制裁的情况,但这是好消息还是坏消息?
8039	听不清，别乱传！	https://buaq.net/go-228733.html	buaq	newscopy;	0	2024-03-18	听不清，别乱传！
1477	Russian independent media outlet Meduza faces ‘most intense cyber campaign’ ever	https://therecord.media/meduza-independent-russian-media-organization-cyberattacks	therecord	ransom;Nation-state;Elections;News;	3	2024-03-12	俄国独立媒体网友Meduza面临「有史以来最激烈的网络运动」,
5875	黑客声称从 Viber 消息应用程序访问了 740GB 数据	https://buaq.net/go-228723.html	buaq	newscopy;	0	2024-03-18	黑客声称从 Viber 消息应用程序访问了 740GB 数据
644	scullionlawcom	http://www.ransomfeed.it/index.php?page=post_details&id_post=13520	ransomfeed	ransom;blackbasta;	1	2024-02-29	Scillionlawcom( 立方公尺)
637	gapsolutionscomau	http://www.ransomfeed.it/index.php?page=post_details&id_post=13500	ransomfeed	ransom;lockbit3;	1	2024-02-29	清空
633	Hotel-Avenida-Hostal-Espoz-y-Mina-Hostal-Arriazu-Pension-Alemana	http://www.ransomfeed.it/index.php?page=post_details&id_post=13495	ransomfeed	ransom;trigona;	1	2024-02-28	Avenida-Hostal-Espoz-y-Mina-Hostal-Arriazu-Pension-Alemana旅馆
664	Winona-Pattern--Mold	http://www.ransomfeed.it/index.php?page=post_details&id_post=13544	ransomfeed	ransom;play;	1	2024-03-01	Winona- 父亲- 父亲- 摩尔多瓦
686	Stoney-Creek-Furniture	http://www.ransomfeed.it/index.php?page=post_details&id_post=13568	ransomfeed	ransom;medusa;	1	2024-03-03	石化石化石化石化石化石化石
4333	lostlb	http://www.ransomfeed.it/index.php?page=post_details&id_post=13738	ransomfeed	ransom;stormous;	1	2024-03-15	损失lb
3676	gfadde	http://www.ransomfeed.it/index.php?page=post_details&id_post=13725	ransomfeed	ransom;blackbasta;	1	2024-03-14	gfadde gfadde gfadde 键, gfadde 键, gfadde 键, gfadde 键, gfadde 键, gfadde 键, gfadde
4332	sbmandcocom	http://www.ransomfeed.it/index.php?page=post_details&id_post=13737	ransomfeed	ransom;lockbit3;	1	2024-03-15	ibmandcocom( sbmandcocom) 中
4334	educationeeb-lost	http://www.ransomfeed.it/index.php?page=post_details&id_post=13739	ransomfeed	ransom;stormous;	1	2024-03-15	教育损失
4353	TikTok禁令引发数据安全和控制问题	https://www.freebuf.com/news/394901.html	freebuf	news;资讯;	1	2024-03-15	TikTok禁令引发数据安全和控制问题
701	America-Chung-Nam-orACN	http://www.ransomfeed.it/index.php?page=post_details&id_post=13583	ransomfeed	ransom;akira;	1	2024-03-04	美洲-中-中-南-亚CN
732	American-Renal-Associates-	http://www.ransomfeed.it/index.php?page=post_details&id_post=13615	ransomfeed	ransom;medusa;	1	2024-03-06	美利坚-雷纳尔协会
18900	FCC opens rulemaking to probe connected car stalking	https://therecord.media/fcc-connected-car-stalking-rulemaking	therecord	ransom;Industry;Government;News;News Briefs;Privacy;	1	2024-04-09	公平竞争委员会开放规则制定 以调查相关车辆跟踪
18901	'They’re lying': Palau denies claims by ransomware gang over recent cyberattack	https://therecord.media/palau-denies-ransomware-gang-claims	therecord	ransom;Cybercrime;Government;News;	2	2024-04-08	“他们在说谎”:帕劳否认赎金软件团伙最近网络攻击的主张。
736	wwwduvelcom	http://www.ransomfeed.it/index.php?page=post_details&id_post=13621	ransomfeed	ransom;stormous;	1	2024-03-07	wwwduvelcom(www.duvelcom) www.www.duvelcom www. kgm www.induvelcom www. kgm www.induvelcom www. kgm
753	Continental-Aerospace-Technologies	http://www.ransomfeed.it/index.php?page=post_details&id_post=13639	ransomfeed	ransom;play;	1	2024-03-09	大陆 -- -- 空气空间 -- -- 技术
773	Premier-Technology	http://www.ransomfeed.it/index.php?page=post_details&id_post=13666	ransomfeed	ransom;play;	1	2024-03-11	总理技术
780	Bridger-Insurance	http://www.ransomfeed.it/index.php?page=post_details&id_post=13673	ransomfeed	ransom;play;	1	2024-03-11	桥梁保险
783	Canada-Revenue-Agency	http://www.ransomfeed.it/index.php?page=post_details&id_post=13676	ransomfeed	ransom;play;	1	2024-03-11	加拿大 -- -- 新闻机构
200	Microsoft Secure: Learn expert AI strategy at our online event	https://www.microsoft.com/en-us/security/blog/2024/03/04/microsoft-secure-learn-expert-ai-strategy-at-our-online-event/	microsoft	news;	1	2024-03-04	微软安全:在网上活动中学习专家AI战略
437	Multiple QNAP Vulnerabilities Let Attackers Inject Malicious Codes	https://gbhackers.com/multiple-qnap-vulnerabilities/	GBHacker	news;Cyber Security News;Vulnerability;	1	2024-03-11	QNAP 多重易变性 让攻击者输入恶意守则
323	GL.iNet AR300M v3.216 Remote Code Execution CVE-2023-46456 Exploit	https://cxsecurity.com/issue/WLB-2024030005	cxsecurity	vuln;	3	2024-03-03	GL.iNet AR300M v3.216 远程代码执行 CVE-2023-46456 开发
92	10 Essential Processes for Reducing the Top 11 Cloud Risks	https://www.darkreading.com/cyber-risk/10-essential-processes-for-reducing-top-11-cloud-risks	darkreading	news;	1	2024-03-06	10 减少最大的11个云层风险的基本程序
415	10.3 Lab: SSRF with blacklist-based input filter | 2024	https://infosecwriteups.com/10-3-lab-ssrf-with-blacklist-based-input-filter-2024-9a7972ab7e8f?source=rss----7b722bfd1b8d---4	infosecwriteups	tech;cybersecurity;security;careers;hacking;bug-bounty;	1	2024-03-04	10.3 实验室:具有基于黑名单的输入过滤器的SSRF = 2024
438	PoC Exploit Released for OpenEdge Authentication Gateway & AdminServer Vulnerability	https://gbhackers.com/poc-exploit-released/	GBHacker	news;Cyber Security News;Vulnerability;	1	2024-03-11	OpenEdge 验证网关的PoC 开发开发
439	WordPress Builder Plugin Flaw Exposes 3,300+ Websites To XSS Attack	https://gbhackers.com/wordpress-builder-plugin-flaw/	GBHacker	news;Cross site Scripting;CVE/vulnerability;Cyber Security News;Plugin Vulnerability;WordPress security;XSS Attacks;	1	2024-03-11	WordPress 构建器插件插件 Flaw 展览 3300 网站
448	Magnet Goblin 组织：利用公共服务器在 Windows 和Linux上部署恶意软件	https://buaq.net/go-227530.html	buaq	newscopy;	0	2024-03-12	Magnet Goblin 组织：利用公共服务器在 Windows 和Linux上部署恶意软件
451	《Large Language Models are Few-shot Generators: Proposing Hybrid Prompt Algorithm To Generate Webshell Escape Samples》论文学习 - 郑瀚Andrew	https://buaq.net/go-227535.html	buaq	newscopy;	0	2024-03-12	《Large Language Models are Few-shot Generators: Proposing Hybrid Prompt Algorithm To Generate Webshell Escape Samples》论文学习 - 郑瀚Andrew
626	Medall-Healthcare-Pvt-Ltd	http://www.ransomfeed.it/index.php?page=post_details&id_post=13487	ransomfeed	ransom;bianlian;	1	2024-02-28	勋章-保健-Pvt-Ltd
18919	Google Adds Security Command Center Enterprise to Mandiant Portfolio	https://securityboulevard.com/2024/04/google-adds-security-command-center-enterprise-to-mandiant-portfolio/	securityboulevard	news;Cybersecurity;Data Security;DevSecOps;Featured;News;Securing the Cloud;Security Boulevard (Original);Social - Facebook;Social - X;google;Mandiant;secops;Security Command Center Enterprise;Threat Intelligence;	1	2024-04-08	Google 将安全指挥中心企业企业添加到Mandiant组合中
18902	Russia seeks criminal charges against executives at flight booking service accused of failing to protect consumer data	https://therecord.media/russia-seeks-criminal-charges-against-flight-booking-executives-leonardo	therecord	ransom;News;News Briefs;Cybercrime;People;	3	2024-04-08	俄罗斯寻求对飞行预订服务公司主管提出刑事指控,指控他们未能保护消费者数据。
199	Defend against human-operated ransomware attacks with Microsoft Copilot for Security​​	https://www.microsoft.com/en-us/security/blog/2024/03/04/defend-against-human-operated-ransomware-attacks-with-microsoft-copilot-for-security/	microsoft	news;	2	2024-03-04	与微软安保事务副驾驶员一道,防御人类操作的赎金软件攻击
23473	PVML raises $8 million to offer protection for enterprise data	https://www.helpnetsecurity.com/2024/04/11/pvml-funding-8-million/	helpnetsecurity	news;Industry news;PVML;	1	2024-04-11	PVML筹集800万美元,为企业数据提供保护
10018	数据安全、AI安全与移动应用安全 | FreeBuf 企业安全俱乐部·广州站议题前瞻	https://www.freebuf.com/articles/395889.html	freebuf	news;	1	2024-03-26	数据安全、AI安全与移动应用安全 | FreeBuf 企业安全俱乐部·广州站议题前瞻
18908	Google Chrome Adds V8 Sandbox - A New Defense Against Browser Attacks	https://thehackernews.com/2024/04/google-chrome-adds-v8-sandbox-new.html	feedburner	news;	1	2024-04-08	Google Chrome Adds V8 Sandbox - 防止浏览器攻击的新防御
10012	[New Research] KnowBe4's Report is a Call to Action for Global Organizations to Improve Their Security Culture	https://blog.knowbe4.com/knowbe4-security-culture-report-2024-new-research	knowbe4	news;Security Awareness Training;Security Culture;	1	2024-03-26	[新研究]Knowbe4的报告呼吁全球组织采取行动改善其安全文化。
18915	Anticipated Cyber Threats During the 2024 Olympics & How to Proactively Secure Your Business	https://securityboulevard.com/2024/04/anticipated-cyber-threats-during-the-2024-olympics-how-to-proactively-secure-your-business/	securityboulevard	news;Security Bloggers Network;Bot & Fraud Protection;learning center;	1	2024-04-08	2024年奥运会期间的预期网络威胁及如何积极保障商业安全
18918	Coro Grabs Spot on Fortune Cyber 60 List	https://securityboulevard.com/2024/04/coro-grabs-spot-on-fortune-cyber-60-list/	securityboulevard	news;Security Bloggers Network;Blog;Business of Cyber;cyber60;fortune;SBN News;	1	2024-04-08	《财富》60号网路名单的Coro Grabs点点
18914	10 Million Devices Were Infected by Data-Stealing Malware in 2023	https://securityboulevard.com/2024/04/10-million-devices-were-infected-by-data-stealing-malware-in-2023/	securityboulevard	news;Cybersecurity;Data Security;Featured;Insider Threats;News;Ransomware;Security Boulevard (Original);Social - Facebook;Social - X;Social Engineering;Threats & Breaches;cyberattacks;Malware;research;	1	2024-04-09	2023年,1 000万个设备被数据追踪的恶意软件感染
411	Some-Tweak-To-Hide-Jwt-Payload-Values - A Handful Of Tweaks And Ideas To Safeguard The JWT Payload	http://www.kitploit.com/2024/03/some-tweak-to-hide-jwt-payload-values.html	kitploit	tool;Encrypting Jwt Payload;Jwt Payload;Jwt Payload Easy Obfuscation;Jwt Payload Encrypt Tweaks;Jwt Token Encrypt;Some-Tweak-To-Hide-Jwt-Payload-Values;	1	2024-03-10	某种节能到隐藏,jwt-payload-values -- -- 一套精巧的节能和理念来保障JWT有效载荷
10879	Advanced cybersecurity strategies boost shareholder returns	https://www.helpnetsecurity.com/2024/03/29/cybersecurity-board-oversight/	helpnetsecurity	news;News;BitSight;boardroom;cyber risk;cybersecurity;data breach;Diligent;regulation;report;strategy;	1	2024-03-29	先进的网络安全战略促进股东回报
24379	Apple Warns Users in 150 Countries of Mercenary Spyware Attacks	https://www.darkreading.com/vulnerabilities-threats/apple-warns-users-targeted-by-mercenary-spyware	darkreading	news;	1	2024-04-11	150个国家的苹果警告用户 Merceenary Spywares袭击
11073	Week in review: Backdoor found in XZ utilities, weaponized iMessages, Exchange servers at risk	https://www.helpnetsecurity.com/2024/03/31/week-in-review-17000-german-microsoft-exchange-servers-at-risk-scammers-weaponize-imessages/	helpnetsecurity	news;News;Week in review;	1	2024-03-31	审查周: XZ 公用事业、武器化iMessages、面临风险的交换服务器发现后门
20444	EPA continuing investigation into leaked data that ‘appears’ to be public info	https://therecord.media/epa-investigation-leaked-data	therecord	ransom;Government;Cybercrime;News;News Briefs;	1	2024-04-09	EPEPA继续调查 " 似乎 " 是公开信息的泄漏数据
18917	Barracuda Report Provides Insight into Cybersecurity Threat Severity Levels	https://securityboulevard.com/2024/04/barracuda-report-provides-insight-into-cybersecurity-threat-severity-levels/	securityboulevard	news;Analytics & Intelligence;Cybersecurity;Featured;Incident Response;News;Security Boulevard (Original);Social - Facebook;Social - X;Threat Intelligence;Uncategorized;research;secops;threats;XDR;	1	2024-04-08	Barracuda报告提供了对网络安全威胁程度的深入了解。
1175	Windows 10 KB5035845 update released with 9 new changes, fixes	https://www.bleepingcomputer.com/news/microsoft/windows-10-kb5035845-update-released-with-9-new-changes-fixes/	bleepingcomputer	news;Microsoft;	1	2024-03-12	Windows 10 KB50355845 更新已发布, 有9个新更改, 修正
18903	Sweeping bipartisan comprehensive data privacy bill to be introduced by congressional leaders	https://therecord.media/sweeping-bipartisan-privacy-bill-to-be-introduced-congress	therecord	ransom;Government;Leadership;News;People;Privacy;	1	2024-04-08	由国会领导人推出的跨党派全面数据隐私法案
18920	Hashicorp Versus OpenTofu Gets Ugly	https://securityboulevard.com/2024/04/hashicorp-versus-opentofu-gets-ugly/	securityboulevard	news;Cyberlaw;Featured;News;Securing Open Source;Security Boulevard (Original);Uncategorized;HashiCorp;IaC;Law;legal;open source;opentofu;Terraform;	1	2024-04-08	哈什军团 开放豆腐会变得丑陋
267	谷堕大盗黑产组织最新攻击样本详细分析	https://xz.aliyun.com/t/14049	阿里先知实验室	news;	1	2024-03-06	谷堕大盗黑产组织最新攻击样本详细分析
1237	CyberheistNews Vol 14 #11 Microsoft and OpenAI Team Up to Block Threat Actor Access to AI	https://blog.knowbe4.com/cyberheistnews-vol-14-11-microsoft-and-openai-team-up-to-block-threat-actor-access-to-ai	knowbe4	news;Cybercrime;KnowBe4;	1	2024-03-12	网络新闻第14卷
202	Enhancing protection: Updates on Microsoft’s Secure Future Initiative	https://www.microsoft.com/en-us/security/blog/2024/03/06/enhancing-protection-updates-on-microsofts-secure-future-initiative/	microsoft	news;	1	2024-03-06	加强保护:微软安全未来倡议的最新情况
17780	SERVICES-INFORMATIQUES-POUR-PROFESSIONNELSSIP	http://www.ransomfeed.it/index.php?page=post_details&id_post=14146	ransomfeed	ransom;blacksuit;	1	2024-04-07	服务 -- -- 信息化设备
18923	USENIX Security ’23 – Lukas Seidel, Dominik Maier, Marius Muench – Forming Faster Firmware Fuzzers	https://securityboulevard.com/2024/04/usenix-security-23-lukas-seidel-dominik-maier-marius-muench-forming-faster-firmware-fuzzers/	securityboulevard	news;Security Bloggers Network;Security Conference;Security Conferences;USENIX;USENIX Security 2023;	1	2024-04-08	USENIX 安全 23 — — Lukas Seidel, Dominik Maier, Marius Muench — — 组建更快速的硬软件引信
17779	Ellsworth-Cooperative-Creamery	http://www.ransomfeed.it/index.php?page=post_details&id_post=14145	ransomfeed	ransom;blacksuit;	1	2024-04-07	埃尔斯沃斯-合作-啤酒
1241	How Much Will AI Help Cybercriminals?	https://blog.knowbe4.com/how-much-will-ai-help-cybercriminals	knowbe4	news;Social Engineering;Phishing;	1	2024-03-12	AI能帮网络罪犯多少?
1257	Mimikyu靶场 CTF入门之基础练习题	https://www.freebuf.com/articles/web/387246.html	freebuf	news;Web安全;	1	2024-03-10	Mimikyu靶场 CTF入门之基础练习题
1254	揭秘智能化安全运营新趋势 | 阿里云 X FreeBuf 技术沙龙	https://www.freebuf.com/articles/393897.html	freebuf	news;	1	2024-03-12	揭秘智能化安全运营新趋势 | 阿里云 X FreeBuf 技术沙龙
1259	Vulhub 练习 DC-4靶机完整复现	https://www.freebuf.com/articles/web/390958.html	freebuf	news;Web安全;	1	2024-03-11	Vulhub 练习 DC-4靶机完整复现
8857	AceCryptor malware has surged in Europe, researchers say	https://therecord.media/acecryptor-malware-surge-europe-remcos	therecord	ransom;Malware;News;	1	2024-03-20	研究人员说,欧洲的加密软件已经涌出
2558	Codezero Raises $3.5M Seed Funding From Ballistic Ventures to Secure Multicloud Application Development	https://www.darkreading.com/cloud-security/codezero-raises-3-5m-seed-funding-from-ballistic-ventures-to-secure-multicloud-application-development	darkreading	news;	1	2024-03-13	代码零增加3.5M种子资金,从弹道导弹风险中获取,以保障多球应用开发
18922	Randall Munroe’s XKCD ‘Greenland Size’	https://securityboulevard.com/2024/04/randall-munroes-xkcd-greenland-size/	securityboulevard	news;Security Bloggers Network;Randall Munroe;XKCD;	1	2024-04-08	Randall Munroe的 XKCD “绿地大小”
9956	Crafting Shields: Defending Minecraft Servers Against DDoS Attacks	https://thehackernews.com/2024/03/crafting-shields-defending-minecraft.html	feedburner	news;	1	2024-03-26	编造盾盾:保护手雷服务器免受DDoS攻击
17778	Malaysian-Industrial-Development-Finance	http://www.ransomfeed.it/index.php?page=post_details&id_post=14142	ransomfeed	ransom;rhysida;	1	2024-04-07	马来西亚-工业发展-金融
26170	华为nova12发布 	https://s.weibo.com/weibo?q=%23华为nova12发布 %23	sina.weibo	hotsearch;weibo	1	2023-12-26	华为nova12发布
26171	华为三折屏手机最早第二季度发布 	https://s.weibo.com/weibo?q=%23华为三折屏手机最早第二季度发布 %23	sina.weibo	hotsearch;weibo	1	2024-04-02	华为三折屏手机最早第二季度发布
8813	Kryo-UTF8-Overlong-Encoding	https://xz.aliyun.com/t/14124	阿里先知实验室	news;	1	2024-03-18	Kryo- UTF8 - 超长编码
1276	Claroty Advanced ATD Module provides continuous monitoring of healthcare network risks	https://www.helpnetsecurity.com/2024/03/12/claroty-advanced-atd-module/	helpnetsecurity	news;Industry news;Claroty;	1	2024-03-12	Claroty高级ATD模块提供对保健网络风险的持续监测
26172	华为与懂车帝停止合作 	https://s.weibo.com/weibo?q=%23华为与懂车帝停止合作 %23	sina.weibo	hotsearch;weibo	1	2024-01-03	华为与懂车帝停止合作
1242	I am announcing AIDA: Artificial Intelligence Defense Agents!	https://blog.knowbe4.com/i-am-announcing-aida-artificial-intelligence-defense-agents	knowbe4	news;Artificial Intelligence;	1	2024-03-12	我要宣布AIDA: 人工情报防卫特工!
26174	华为凭什么重新定义汽车底盘 	https://s.weibo.com/weibo?q=%23华为凭什么重新定义汽车底盘 %23	sina.weibo	hotsearch;weibo	1	2023-11-28	华为凭什么重新定义汽车底盘
26178	华为发布全球首个5.5G智能核心网 	https://s.weibo.com/weibo?q=%23华为发布全球首个5.5G智能核心网 %23	sina.weibo	hotsearch;weibo	1	2024-02-27	华为发布全球首个5.5G智能核心网
1244	Generative AI Results In 1760% Increase in BEC Attacks	https://blog.knowbe4.com/phishing-use-generative-ai-increases	knowbe4	news;Social Engineering;Phishing;Security Culture;	1	2024-03-12	1760%的BEC袭击增加
26173	华为与长安汽车成立新公司 	https://s.weibo.com/weibo?q=%23华为与长安汽车成立新公司 %23	sina.weibo	hotsearch;weibo	1	2024-01-16	华为与长安汽车成立新公司
1261	venom打靶思路详解（vulnhub）	https://www.freebuf.com/defense/394169.html	freebuf	news;攻防演练;	1	2024-03-12	venom打靶思路详解（vulnhub）
26175	华为分红770亿元 	https://s.weibo.com/weibo?q=%23华为分红770亿元 %23	sina.weibo	hotsearch;weibo	1	2024-02-06	华为分红770亿元
1255	网安标委印发《网络安全标准实践指南——车外画面局部轮廓化处理效果验证》	https://www.freebuf.com/articles/394148.html	freebuf	news;	1	2024-03-12	网安标委印发《网络安全标准实践指南——车外画面局部轮廓化处理效果验证》
26180	华为回应P70延期发布 	https://s.weibo.com/weibo?q=%23华为回应P70延期发布 %23	sina.weibo	hotsearch;weibo	1	2024-03-08	华为回应P70延期发布
26181	华为回应智界S7交付困难 	https://s.weibo.com/weibo?q=%23华为回应智界S7交付困难 %23	sina.weibo	hotsearch;weibo	1	2024-01-16	华为回应智界S7交付困难
26182	华为在三亚开了一场很新的party 	https://s.weibo.com/weibo?q=%23华为在三亚开了一场很新的party %23	sina.weibo	hotsearch;weibo	1	2024-02-22	华为在三亚开了一场很新的party
10882	New infosec products of the week: March 29, 2024	https://www.helpnetsecurity.com/2024/03/29/new-infosec-products-of-the-week-march-29-2024/	helpnetsecurity	news;News;Bedrock Security;CyberArk;GitGuardian;Legit Security;Malwarebytes;	1	2024-03-29	2024年3月29日 2024年3月29日
1464	Red Hat Security Advisory 2024-1268-03	https://packetstormsecurity.com/files/177539/RHSA-2024-1268-03.txt	packetstorm	vuln;;	1	2024-03-12	Red Hat Security Advisory 2024-1268-03
1467	NorthStar C2 Agent 1.0 Cross Site Scripting / Remote Command Execution	https://packetstormsecurity.com/files/177542/northstarc210-xssexec.txt	packetstorm	vuln;;	1	2024-03-12	NorthStar C2 Agent 1. 0 跨站点脚本/远程命令执行
1468	Ubuntu Security Notice USN-6658-2	https://packetstormsecurity.com/files/177543/USN-6658-2.txt	packetstorm	vuln;;	1	2024-03-12	Ubuntu Ubuntu 安全通知 USN6658-2
1469	Ubuntu Security Notice USN-6681-2	https://packetstormsecurity.com/files/177544/USN-6681-2.txt	packetstorm	vuln;;	1	2024-03-12	Ubuntu Ubuntu 安全通知 USN6681-2
1522	[2024]新的一年,新的开始	https://buaq.net/go-227694.html	buaq	newscopy;	0	2024-03-13	[2024]新的一年,新的开始
1470	Ubuntu Security Notice USN-6688-1	https://packetstormsecurity.com/files/177545/USN-6688-1.txt	packetstorm	vuln;;	1	2024-03-12	Ubuntu Ubuntu 安全通知 USN6688-1
1472	Ubuntu Security Notice USN-6689-1	https://packetstormsecurity.com/files/177547/USN-6689-1.txt	packetstorm	vuln;;	1	2024-03-12	Ubuntu Ubuntu 安全通知 USN-6689-1
1473	Ubuntu Security Notice USN-6656-2	https://packetstormsecurity.com/files/177548/USN-6656-2.txt	packetstorm	vuln;;	1	2024-03-12	Ubuntu Ubuntu 安全通知 USN6656-2
1476	LockBit takes credit for February shutdown of South African pension fund	https://therecord.media/lockbit-ransomware-takes-credit-for-south-african-pension-fund-attack	therecord	ransom;Government;News;	2	2024-03-12	LockBit为南非养恤基金2月停用收取信用
1478	Stanford says data from 27,000 people leaked in September ransomware attack	https://therecord.media/stanford-data-leaked-Akira-ransomware-attack	therecord	ransom;News;Cybercrime;	2	2024-03-12	斯坦福说数据 来自27000人 在9月的赎金软件袭击中泄漏
1512	CloudGrappler: Open Source Tool that Detects Hacking Activity	https://gbhackers.com/cloudgrappler/	GBHacker	news;Cloud;Cyber Security News;computer security;	1	2024-03-12	CloudGrappler: 检测洗劫活动的开放源码工具
1514	Hackers Advertising FUD APK Crypter that Runs on all Android Devices	https://gbhackers.com/hackers-advertising-fud-apk-crypter/	GBHacker	news;cyber security;Cyber security Course;Cyber Security News;	2	2024-03-12	Hackers广告FUD APK加密器 运行所有安非他明装置
1518	Muddled Libra Hackers Using Pentesting Tools To Gain Admin Access	https://gbhackers.com/muddled-libra-pentesting-admin/	GBHacker	news;Cyber Attack;cyber security;Penetration Testing;Muddled Libra Hackers;Pentesting Tools;	1	2024-03-12	利用笔试工具获得管理权
1523	[2024]基于C++的混淆壳(三) shellcode与oep编写	https://buaq.net/go-227695.html	buaq	newscopy;	0	2024-03-13	[2024]基于C++的混淆壳(三) shellcode与oep编写
1521	Ransomware review: March 2024	https://buaq.net/go-227676.html	buaq	newscopy;	0	2024-03-13	Ransom软件审查:2024年3月
1524	DOJ Warns Using AI in Crimes Will Mean Harsher Sentences	https://buaq.net/go-227698.html	buaq	newscopy;	0	2024-03-13	DOJ Warns Warns 在犯罪中使用AI
4797	South-St-Paul-Public-Schools	http://www.ransomfeed.it/index.php?page=post_details&id_post=13742	ransomfeed	ransom;blacksuit;	1	2024-03-15	南-圣保罗-公立学校
1525	Need help with decompiling mobile game Micro Machines files	https://buaq.net/go-227701.html	buaq	newscopy;	0	2024-03-13	需要帮助解压缩移动游戏游戏微机文件
1527	Patch Tuesday, March 2024 Edition	https://buaq.net/go-227704.html	buaq	newscopy;	0	2024-03-13	2024年3月, 2024年3月,
10026	GitHub遭遇严重供应链“投毒”攻击	https://www.freebuf.com/news/395869.html	freebuf	news;资讯;	1	2024-03-26	GitHub遭遇严重供应链“投毒”攻击
10027	新型 ZenHammer 内存攻击影响 AMD Zen CPU	https://www.freebuf.com/news/395926.html	freebuf	news;资讯;	1	2024-03-26	新型 ZenHammer 内存攻击影响 AMD Zen CPU
1529	Stanford: Data of 27,000 people stolen in September ransomware attack	https://buaq.net/go-227706.html	buaq	newscopy;	0	2024-03-13	斯坦福:27,000人的数据 在9月赎金软件袭击中被盗
1532	Tweaks Stealer Targets Roblox Users Through YouTube and Discord	https://buaq.net/go-227711.html	buaq	newscopy;	0	2024-03-13	透过YouTube 和 Discoord,
1534	FakeBat delivered via several active malvertising campaigns	https://buaq.net/go-227716.html	buaq	newscopy;	0	2024-03-13	通过若干积极的错误广告宣传运动提供的假冒Bat
1531	Microsoft Patch Tuesday security updates for March 2024 fixed 59 flaws	https://buaq.net/go-227708.html	buaq	newscopy;	0	2024-03-13	2024年3月的 2024年3月安全更新 固定了59个缺陷
1535	Windows KB5035849 update failing to install with 0xd000034 errors	https://buaq.net/go-227718.html	buaq	newscopy;	0	2024-03-13	Windows KB50355849 更新未安装 0xd000034 错误
1536	Brave: Sharp increase in installs after iOS DMA update in EU	https://buaq.net/go-227719.html	buaq	newscopy;	0	2024-03-13	勇敢:欧盟对iOS DMA进行更新后,安装量急剧增加
1538	Frax Finance's New Layer 2: Everything You Need to Know About Fraxtal	https://buaq.net/go-227721.html	buaq	newscopy;	0	2024-03-13	Frax Finance 的新图层 2: 你需要知道的关于Fraxtal的一切
1466	Red Hat Security Advisory 2024-1270-03	https://packetstormsecurity.com/files/177541/RHSA-2024-1270-03.txt	packetstorm	vuln;;	1	2024-03-12	红帽子安保咨询 2024-1270-03
26183	华为官宣Pocket2发布会 	https://s.weibo.com/weibo?q=%23华为官宣Pocket2发布会 %23	sina.weibo	hotsearch;weibo	1	2024-02-19	华为官宣Pocket2发布会
26185	华为将在2030年实现卫星宽带计划 	https://s.weibo.com/weibo?q=%23华为将在2030年实现卫星宽带计划 %23	sina.weibo	hotsearch;weibo	1	2024-01-16	华为将在2030年实现卫星宽带计划
20480	Tips for Securing the Software Supply Chain	https://www.darkreading.com/cyber-risk/tips-for-securing-the-software-supply-chain	darkreading	news;	1	2024-04-08	保障软件供应链安全提示
26186	华为已撤回遥遥领先商标申请 	https://s.weibo.com/weibo?q=%23华为已撤回遥遥领先商标申请 %23	sina.weibo	hotsearch;weibo	1	2024-04-02	华为已撤回遥遥领先商标申请
26187	华为希望一汽集团加入 	https://s.weibo.com/weibo?q=%23华为希望一汽集团加入 %23	sina.weibo	hotsearch;weibo	1	2023-11-28	华为希望一汽集团加入
1471	Ubuntu Security Notice USN-6690-1	https://packetstormsecurity.com/files/177546/USN-6690-1.txt	packetstorm	vuln;;	1	2024-03-12	Ubuntu Ubuntu 安全通知 USN-6690-1
1275	Aviatrix  releases Distributed Cloud Firewall for Kubernetes	https://www.helpnetsecurity.com/2024/03/12/aviatrix-distributed-cloud-firewall-for-kubernetes/	helpnetsecurity	news;Industry news;Aviatrix;	1	2024-03-12	Aviatrix  releases Distributed Cloud Firewall for Kubernetes
311	Dictators Used Sandvine Tech to Censor the Internet. The US Finally Did Something About It	https://www.wired.com/story/sandvine-us-sanctions-egypt-internet-censorship/	wired	news;Security;Security / National Security;Security / Security News;Security / Privacy;	1	2024-02-28	独裁者利用桑德维内科技来检查互联网。美国最终对此做了一些事情
1463	Red Hat Security Advisory 2024-1253-03	https://packetstormsecurity.com/files/177538/RHSA-2024-1253-03.txt	packetstorm	vuln;;	1	2024-03-12	红色帽子安保咨询 2024-1253-03
10028	MuddyWater借助Atera向以色列员工发起钓鱼攻击	https://www.freebuf.com/news/395927.html	freebuf	news;资讯;	1	2024-03-26	MuddyWater借助Atera向以色列员工发起钓鱼攻击
1279	March 2024 Patch Tuesday: Microsoft fixes critical bugs in Windows Hyper-V	https://www.helpnetsecurity.com/2024/03/12/march-2024-patch-tuesday/	helpnetsecurity	news;Don't miss;Hot stuff;News;Automox;Microsoft;Microsoft Exchange;Patch Tuesday;security update;Tenable;Trend Micro;Windows;	1	2024-03-12	2024年3月 2024年3月 补丁: 星期二:微软修补Windows Hyper-V 中的关键虫
1643	Brooks-Tropicals	http://www.ransomfeed.it/index.php?page=post_details&id_post=13689	ransomfeed	ransom;rhysida;	1	2024-03-12	布鲁克斯热带
10030	ArmorCode Risk Prioritization provides visibility into security findings with business context	https://www.helpnetsecurity.com/2024/03/26/armorcode-risk-prioritization/	helpnetsecurity	news;Industry news;ArmorCode;	1	2024-03-26	ArmorCode风险优先排序在业务背景下在安全结论中提供能见度
10031	BackBox platform update enhances CVE mitigation and risk scoring	https://www.helpnetsecurity.com/2024/03/26/backbox-platform-update/	helpnetsecurity	news;Industry news;BackBox;	3	2024-03-26	BackBox平台更新更新后台平台可增强CVE的缓解和风险评分
1641	Withall	http://www.ransomfeed.it/index.php?page=post_details&id_post=13687	ransomfeed	ransom;blacksuit;	1	2024-03-12	与所有
4801	Acculabs-Inc	http://www.ransomfeed.it/index.php?page=post_details&id_post=13746	ransomfeed	ransom;incransom;	1	2024-03-16	Acculabs- Inc 计算器
1150	Watch Out: These PyPI Python Packages Can Drain Your Crypto Wallets	https://thehackernews.com/2024/03/watch-out-these-pypi-python-packages.html	feedburner	news;	1	2024-03-12	注意 注意: 这些 PyPI Python 软件包可以排入您的加密钱包
4798	elezabypharmacycom	http://www.ransomfeed.it/index.php?page=post_details&id_post=13743	ransomfeed	ransom;lockbit3;	1	2024-03-15	elezabypryharycycom( elezaby- 爆炸性合成器)
4769	NHS Breach, HSE Bug Expose Healthcare Data in the British Isles	https://www.darkreading.com/cyberattacks-data-breaches/nhs-breach-hse-bug-expose-healthcare-data-british-isles	darkreading	news;	1	2024-03-15	NHS 突破,HSE 错误披露不列颠各岛的保健数据
4800	oyaksgscomtr	http://www.ransomfeed.it/index.php?page=post_details&id_post=13745	ransomfeed	ransom;lockbit3;	1	2024-03-15	oyaksgscomtr
1646	creativeenvironmentscom	http://www.ransomfeed.it/index.php?page=post_details&id_post=13692	ransomfeed	ransom;blackbasta;	1	2024-03-12	创意环境委员会
1645	linksunlimitedcom	http://www.ransomfeed.it/index.php?page=post_details&id_post=13691	ransomfeed	ransom;blackbasta;	1	2024-03-12	链接“无限制”
1460	Red Hat Security Advisory 2024-1249-03	https://packetstormsecurity.com/files/177535/RHSA-2024-1249-03.txt	packetstorm	vuln;;	1	2024-03-12	红色帽子安保咨询 2024-1249-03
1647	contechscouk	http://www.ransomfeed.it/index.php?page=post_details&id_post=13693	ransomfeed	ransom;blackbasta;	1	2024-03-12	Centechscouk 国家理工学院
1462	Red Hat Security Advisory 2024-1251-03	https://packetstormsecurity.com/files/177537/RHSA-2024-1251-03.txt	packetstorm	vuln;;	1	2024-03-12	红色帽子安保咨询 2024-1251-03
727	Liquid-Environmental-Solutions	http://www.ransomfeed.it/index.php?page=post_details&id_post=13610	ransomfeed	ransom;incransom;	1	2024-03-06	液-环境解决办法
1642	WALKERSANDFORD	http://www.ransomfeed.it/index.php?page=post_details&id_post=13688	ransomfeed	ransom;blacksuit;	1	2024-03-12	滑行和
1113	CTEM 101 - Go Beyond Vulnerability Management with Continuous Threat Exposure Management	https://thehackernews.com/2024/03/ctem-101-go-beyond-vulnerability.html	feedburner	news;	1	2024-03-12	CTEM 101 - 超越脆弱性管理,继续威胁接触管理
10883	Stream.Security unveils threat investigation and AI-powered remediation capabilities	https://www.helpnetsecurity.com/2024/03/29/stream-security-remediation-capabilities/	helpnetsecurity	news;Industry news;Stream.Security;	1	2024-03-29	安全流披露威胁调查和AI-how补救能力
10893	ADMS-PHP-by:oretnom23-v1.0 Multiple-SQLi	https://www.nu11secur1ty.com/2024/03/adms-php-byoretnom23-v10-multiple-sqli.html	nu11security	vuln;	1	2024-03-29	ADMS-PHP-by:oretnom23-v1.0 多SQLi
4799	ATMCo	http://www.ransomfeed.it/index.php?page=post_details&id_post=13744	ransomfeed	ransom;trigona;	1	2024-03-15	亚TMCo
10895	WBCE_CMS-1.6.2-File-Upload-RCE	https://www.nu11secur1ty.com/2024/03/wbcecms-162-file-upload-rce.html	nu11security	vuln;	1	2024-03-29	WBCE_CMS-1.6.6-2-装货箱-RCE
1644	imperialtradingcom	http://www.ransomfeed.it/index.php?page=post_details&id_post=13690	ransomfeed	ransom;blackbasta;	1	2024-03-12	帝国贸易委员会
1221	GAO: CISA's OT Teams Inadequately Staffed	https://www.darkreading.com/ics-ot-security/cisa-ot-teams-are-inadequately-staffed-reports-gao	darkreading	news;	1	2024-03-12	GAO: CISA的OT小组人员配备不足
26188	华为手环9 	https://s.weibo.com/weibo?q=%23华为手环9 %23	sina.weibo	hotsearch;weibo	1	2024-04-08	华为手环9
26189	华为承诺不从事整车业务 	https://s.weibo.com/weibo?q=%23华为承诺不从事整车业务 %23	sina.weibo	hotsearch;weibo	1	2024-01-16	华为承诺不从事整车业务
2577	Claroty Launches Advanced Anomaly Threat Detection for Medigate	https://www.darkreading.com/ics-ot-security/claroty-launches-advanced-anomaly-threat-detection-for-medigate	darkreading	news;	1	2024-03-13	Claroty 发射 高级异形威胁探测 用于医疗
1653	xcelbrandscom	http://www.ransomfeed.it/index.php?page=post_details&id_post=13699	ransomfeed	ransom;blackbasta;	1	2024-03-12	xcelbrandscom 组合键
4808	duttonbrockcom	http://www.ransomfeed.it/index.php?page=post_details&id_post=13753	ransomfeed	ransom;lockbit3;	1	2024-03-16	杜顿火箭
1649	dutyfreeamericascom	http://www.ransomfeed.it/index.php?page=post_details&id_post=13695	ransomfeed	ransom;blackbasta;	1	2024-03-12	经济、经济、经济、经济、
4802	certifiedcollectioncom	http://www.ransomfeed.it/index.php?page=post_details&id_post=13747	ransomfeed	ransom;lockbit3;	1	2024-03-16	认证回收共
3677	iamdesigncom	http://www.ransomfeed.it/index.php?page=post_details&id_post=13726	ransomfeed	ransom;abyss;	1	2024-03-14	iamdesigncom( iamdesigncom )
1655	Kenneth-Young-Center	http://www.ransomfeed.it/index.php?page=post_details&id_post=13701	ransomfeed	ransom;medusa;	1	2024-03-12	肯尼思·英英中心
2530	USB 设备开发：从入门到实践指南（四）	https://paper.seebug.org/3131/	seebug	news;安全工具&安全开发;404专栏;	1	2024-03-13	USB 设备开发：从入门到实践指南（四）
4804	triellacom	http://www.ransomfeed.it/index.php?page=post_details&id_post=13749	ransomfeed	ransom;lockbit3;	1	2024-03-16	三角体
1652	cpacsystemsse	http://www.ransomfeed.it/index.php?page=post_details&id_post=13698	ransomfeed	ransom;blackbasta;	1	2024-03-12	cpacsystems 计算机系统
1656	Huca	http://www.ransomfeed.it/index.php?page=post_details&id_post=13702	ransomfeed	ransom;cloak;	1	2024-03-12	胡卡
4806	newmans-onlinecouk	http://www.ransomfeed.it/index.php?page=post_details&id_post=13751	ransomfeed	ransom;lockbit3;	1	2024-03-16	新曼斯- 线性库
4807	hdstradingcom	http://www.ransomfeed.it/index.php?page=post_details&id_post=13752	ransomfeed	ransom;lockbit3;	1	2024-03-16	hdstradingcom
2525	Researchers Highlight Google's Gemini AI Susceptibility to LLM Threats	https://thehackernews.com/2024/03/researchers-highlight-googles-gemini-ai.html	feedburner	news;	1	2024-03-13	高亮GoogleGoogle的Gemini AI AI 高亮地展示了LLM威胁的能感
1475	JetBrains vulnerability exploitation highlights debate over 'silent patching'	https://therecord.media/jetbrains-rapid7-silent-patching-dispute	therecord	ransom;Cybercrime;Industry;News;Technology;	1	2024-03-12	Jeffbrains 脆弱性开发凸显了对“沉默补丁”的争论。
2517	Demystifying a Common Cybersecurity Myth	https://thehackernews.com/2024/03/demystifying-common-cybersecurity-myth.html	feedburner	news;	1	2024-03-13	解开共同网络安全神话的神秘
1668	FreeBuf 早报 | 法国多个政府机构遭遇网络攻击；意大利数据监管机构对Sora展开调查	https://www.freebuf.com/news/394069.html	freebuf	news;资讯;	1	2024-03-12	FreeBuf 早报 | 法国多个政府机构遭遇网络攻击；意大利数据监管机构对Sora展开调查
1654	sunholdingsnet	http://www.ransomfeed.it/index.php?page=post_details&id_post=13700	ransomfeed	ransom;lockbit3;	1	2024-03-12	遮阳网
4809	colefabricscom	http://www.ransomfeed.it/index.php?page=post_details&id_post=13754	ransomfeed	ransom;lockbit3;	1	2024-03-16	cleefabricscom 计算器
1650	keystonetechcom	http://www.ransomfeed.it/index.php?page=post_details&id_post=13696	ransomfeed	ransom;blackbasta;	1	2024-03-12	关键石技术
1651	elmaticde	http://www.ransomfeed.it/index.php?page=post_details&id_post=13697	ransomfeed	ransom;blackbasta;	1	2024-03-12	外 外 地 文 地 地 体
1648	sierralobocom	http://www.ransomfeed.it/index.php?page=post_details&id_post=13694	ransomfeed	ransom;blackbasta;	1	2024-03-12	西里拉罗洛博哥
2534	Don’t Miss These Emerging Trends in Cloud Application Security	https://securityboulevard.com/2024/03/dont-miss-these-emerging-trends-in-cloud-application-security/	securityboulevard	news;Security Bloggers Network;AppSec;Best Practices;	1	2024-03-13	不要错过这些云应用安全的新趋势
2533	What’s in your notepad? Infected text editors target Chinese users	https://securelist.com/trojanized-text-editor-apps/112167/	securelist	news;Malware descriptions;Apple MacOS;Backdoor;Linux;Malware;Malware Descriptions;Malware Technologies;Trojan;Unix and macOS malware;	4	2024-03-13	你笔记本上写了些什么?
2523	PixPirate Android Banking Trojan Using New Evasion Tactic to Target Brazilian Users	https://thehackernews.com/2024/03/pixpirate-android-banking-trojan-using.html	feedburner	news;	2	2024-03-13	使用新疏散策略针对巴西用户进行像素Android Bank Trojan
2521	Microsoft's March Updates Fix 61 Vulnerabilities, Including Critical Hyper-V Flaws	https://thehackernews.com/2024/03/microsofts-march-updates-fix-61.html	feedburner	news;	1	2024-03-13	微软的三月更新Fix 61脆弱性,包括临界超V法律
4803	Miki-Travel	http://www.ransomfeed.it/index.php?page=post_details&id_post=13748	ransomfeed	ransom;hunters;	1	2024-03-16	Miki- 旅行
4805	rribcom	http://www.ransomfeed.it/index.php?page=post_details&id_post=13750	ransomfeed	ransom;lockbit3;	1	2024-03-16	罗姆人
2542	Summoning RAGnarok With Your Nemesis	https://securityboulevard.com/2024/03/summoning-ragnarok-with-your-nemesis/	securityboulevard	news;Security Bloggers Network;Infosec;LLM;Nemesis;	1	2024-03-13	正在用你的宿命负负号传回 RAGNAROK
2545	Windows 11 gets single Teams app for work and personal accounts	https://www.bleepingcomputer.com/news/microsoft/windows-11-gets-single-teams-app-for-work-and-personal-accounts/	bleepingcomputer	news;Microsoft;	1	2024-03-13	视窗11获得单队工作和个人账户应用程序
2570	Yacht Retailer MarineMax Files 'Cyber Incident' with SEC	https://www.darkreading.com/cyberattacks-data-breaches/yacht-retailer-marinemax-files-cyber-incident-sec	darkreading	news;	1	2024-03-13	与SEC合作的Yacht 游艇零售商 MarineMax 文件“赛事事件”
4811	automotionshadecom	http://www.ransomfeed.it/index.php?page=post_details&id_post=13756	ransomfeed	ransom;lockbit3;	1	2024-03-16	自动移动阴影网络
2549	Hackers exploit Windows SmartScreen flaw to drop DarkGate malware	https://www.bleepingcomputer.com/news/security/hackers-exploit-windows-smartscreen-flaw-to-drop-darkgate-malware/	bleepingcomputer	news;Security;Microsoft;	1	2024-03-13	黑客利用 Windows SmartScreen 瑕疵来降低 DarkGate 恶意软件
2543	The Macros Playbook: Maximizing Benefits, Minimizing Risks	https://securityboulevard.com/2024/03/the-macros-playbook-maximizing-benefits-minimizing-risks/	securityboulevard	news;Security Bloggers Network;Blog;	1	2024-03-13	《宏观游戏手册:最大限度地增加效益,尽量减少风险》
2551	Pen test vendor rotation: do you need to change annually?	https://www.bleepingcomputer.com/news/security/pen-test-vendor-rotation-do-you-need-to-change-annually/	bleepingcomputer	news;Security;	1	2024-03-13	笔试供应商轮换:你是否需要每年更换一次?
2567	Israeli Universities Hit by Supply Chain Cyberattack Campaign	https://www.darkreading.com/cyberattacks-data-breaches/israeli-universities-hit-by-supply-chain-cyberattack-campaign	darkreading	news;	1	2024-03-13	供应链网络攻击运动打击以色列大学
4814	Desco-Steel	http://www.ransomfeed.it/index.php?page=post_details&id_post=13759	ransomfeed	ransom;medusa;	1	2024-03-16	DESEE 电磁
4812	agribankcomna	http://www.ransomfeed.it/index.php?page=post_details&id_post=13757	ransomfeed	ransom;lockbit3;	1	2024-03-16	农业银行
10266	UNDP	http://www.ransomfeed.it/index.php?page=post_details&id_post=13962	ransomfeed	ransom;8base;	1	2024-03-27	开发署 开发署 开发署 开发署 开发署
10267	Lindos-Group-Of-Companies	http://www.ransomfeed.it/index.php?page=post_details&id_post=13963	ransomfeed	ransom;8base;	1	2024-03-27	林多公司集团
2550	LockBit ransomware affiliate gets four years in jail, to pay $860k	https://www.bleepingcomputer.com/news/security/lockbit-ransomware-affiliate-gets-four-years-in-jail-to-pay-860k/	bleepingcomputer	news;Security;Legal;	3	2024-03-13	Lock Bit 赎金软件附属公司 被判4年监禁 支付860k美元
10268	isophon-glas-GmbH	http://www.ransomfeed.it/index.php?page=post_details&id_post=13964	ransomfeed	ransom;8base;	1	2024-03-27	异己-glas-GmbH
3847	Supporters of Russian anti-war politician arrested for posting LGBT emoji and political memes	https://therecord.media/russian-anti-war-politician-supporters-arrested-social-media	therecord	ransom;Government;Leadership;News;	3	2024-03-14	俄罗斯反战政治家支持者因张贴LGBT emoji与政治迷因被捕
10269	contenderboatscom	http://www.ransomfeed.it/index.php?page=post_details&id_post=13965	ransomfeed	ransom;cactus;	1	2024-03-27	竞争船运公司
4815	Metzger-Veterinary-Services	http://www.ransomfeed.it/index.php?page=post_details&id_post=13760	ransomfeed	ransom;medusa;	1	2024-03-16	兽医-兽医-服务
2569	Nissan Oceania Breached; 100K People Affected Down Under	https://www.darkreading.com/cyberattacks-data-breaches/nissan-oceania-breached-100k-customers-employees-dealers-affected	darkreading	news;	1	2024-03-13	尼桑大洋洲
10034	Legit Security launches enterprise secrets scanning solution	https://www.helpnetsecurity.com/2024/03/26/legit-security-secrets-scanner/	helpnetsecurity	news;Industry news;Legit Security;	1	2024-03-26	合法安全系统启动企业机密扫描解决方案
2554	US govt probes if ransomware gang stole Change Healthcare data	https://www.bleepingcomputer.com/news/security/us-govt-probes-if-ransomware-gang-stole-change-healthcare-data/	bleepingcomputer	news;Security;Healthcare;	2	2024-03-13	如果美国政府调查赎金软件 黑帮盗取改变医疗数据
2559	Google's Post-Quantum Upgrade Doesn't Mean We're All Protected Yet	https://www.darkreading.com/cloud-security/google-s-post-quantum-upgrade-doesn-t-mean-we-re-all-protected-yet	darkreading	news;	1	2024-03-13	谷歌的量子升级后 并不代表我们都得到了保护
2552	PixPirate Android malware uses new tactic to hide on phones	https://www.bleepingcomputer.com/news/security/pixpirate-android-malware-uses-new-tactic-to-hide-on-phones/	bleepingcomputer	news;Security;Google;Mobile;	2	2024-03-13	PixPiratate Android 恶意软件使用新的策略隐藏在手机上
2564	ChatGPT Spills Secrets in Novel PoC Attack	https://www.darkreading.com/cyber-risk/researchers-develop-new-attack-for-extracting-secrets-from-chatgpt-other-genai-tools	darkreading	news;	1	2024-03-13	在新波谱攻击中聊天的溢漏秘密
2548	Fortinet warns of critical RCE bug in endpoint management software	https://www.bleepingcomputer.com/news/security/fortinet-warns-of-critical-rce-bug-in-endpoint-management-software/	bleepingcomputer	news;Security;	1	2024-03-13	Fortinet 警告终端管理软件中严重的 RCE 错误
10032	DataVisor’s AML solution helps combat sophisticated financial crimes	https://www.helpnetsecurity.com/2024/03/26/datavisor-aml-solution/	helpnetsecurity	news;Industry news;DataVisor;	1	2024-03-26	Datavisor的反洗钱解决方案有助于打击复杂的金融犯罪
2540	Randall Munroe’s XKCD ‘Physics vs. Magic’	https://securityboulevard.com/2024/03/randall-munroes-xkcd-physics-vs-magic/	securityboulevard	news;Humor;Security Bloggers Network;Randall Munroe;Sarcasm;satire;XKCD;	1	2024-03-13	Randall Munroe的 XKCD “物理对魔术”
2544	Bitcoin Fog mixer operator convicted for laundering $400 million	https://www.bleepingcomputer.com/news/legal/bitcoin-fog-mixer-operator-convicted-for-laundering-400-million/	bleepingcomputer	news;Legal;CryptoCurrency;	1	2024-03-13	Bittcoin雾搅拌器经营者因洗钱4亿美元被定罪
2654	Summit-Almonds	http://www.ransomfeed.it/index.php?page=post_details&id_post=13721	ransomfeed	ransom;akira;	1	2024-03-13	首脑会议 -- -- 首脑会议
2658	浅谈企业数据安全治理与保障框架	https://www.freebuf.com/articles/es/393967.html	freebuf	news;企业安全;	1	2024-03-11	浅谈企业数据安全治理与保障框架
2659	[实战]API防护破解之签名验签	https://www.freebuf.com/articles/network/394725.html	freebuf	news;网络安全;	1	2024-03-13	[实战]API防护破解之签名验签
10927	Red Hat Security Advisory 2024-1570-03	https://packetstormsecurity.com/files/177845/RHSA-2024-1570-03.txt	packetstorm	vuln;;	1	2024-03-29	红帽子安保咨询2024-1570-03
10928	Intel PowerGadget 3.6 Local Privilege Escalation	https://packetstormsecurity.com/files/177846/intelpowergadget36-escalate.txt	packetstorm	vuln;;	1	2024-03-29	英特尔 PowerGadget 3.6 地方特权升级
2671	欧盟地区 iOS DMA 更新后，Brave浏览器安装量激增	https://www.freebuf.com/news/394645.html	freebuf	news;资讯;	1	2024-03-13	欧盟地区 iOS DMA 更新后，Brave浏览器安装量激增
2672	印度一金融公司泄露用户信息，数据量超过3TB	https://www.freebuf.com/news/394649.html	freebuf	news;资讯;	1	2024-03-13	印度一金融公司泄露用户信息，数据量超过3TB
2680	Nozomi Networks raises $100 million to help secure critical infrastructure	https://www.helpnetsecurity.com/2024/03/13/nozomi-networks-funding-100-million/	helpnetsecurity	news;Industry news;Nozomi Networks;	1	2024-03-13	Nozomi网络筹集1亿美元,帮助保障关键基础设施的安全
2681	Regula 4205D updates help border control authorities fight identity document fraud	https://www.helpnetsecurity.com/2024/03/13/regula-4205d/	helpnetsecurity	news;Industry news;Regula;	1	2024-03-13	4205D更新更新条例,帮助边境管制当局打击身份文件欺诈
2682	Stellar Cyber and Torq join forces to deliver automation-driven security operations platform	https://www.helpnetsecurity.com/2024/03/13/stellar-cyber-torq-partnership/	helpnetsecurity	news;Industry news;Stellar Cyber;Torq;	1	2024-03-13	Stellar网络和Torq联手提供自动化驱动的安全行动平台
2678	Mirantis enhances Lens Desktop to improve Kubernetes operations	https://www.helpnetsecurity.com/2024/03/13/mirantis-lens-desktop/	helpnetsecurity	news;Industry news;Mirantis;	3	2024-03-13	Mirantis 增强镜头桌面,以改善Kubernetes 业务
2579	Heated Seats? Advanced Telematics? Software-Defined Cars Drive Risk	https://www.darkreading.com/ics-ot-security/heated-seats-advanced-telematics-software-defined-cars-drive-risk	darkreading	news;	1	2024-03-13	高温座椅? 先进远程信息学? 软件定义的汽车驱动风险
2582	Critical ChatGPT Plug-in Vulnerabilities Expose Sensitive Data	https://www.darkreading.com/vulnerabilities-threats/critical-chatgpt-plugin-vulnerabilities-expose-sensitive-data	darkreading	news;	1	2024-03-13	关键聊天插插插插插插插插插插插插插插插插插插插插插插插插插插插插插插插插插插孔敏感数据
2584	Why You Need to Know Your AI's Ancestry	https://www.darkreading.com/vulnerabilities-threats/why-you-need-to-know-your-ai-ancestry	darkreading	news;	1	2024-03-13	为什么你需要知道你的AI的祖先
2594	AI-Driven Voice Cloning Tech Used in Vishing Campaigns	https://blog.knowbe4.com/voice-cloning-tech-used-in-vishing-campaigns	knowbe4	news;Phishing;Security Culture;MFA;	1	2024-03-13	AI-Driven Viishing 运动中使用的AI-Driven 语音克隆技术
2595	Meson Network Cryptojacking Campaign	https://threats.wiz.io/all-incidents/meson-network-cryptojacking-campaign	wizio	incident;	1	2024-03-13	Meson网络密码侵入运动
4819	Bwizer	http://www.ransomfeed.it/index.php?page=post_details&id_post=13764	ransomfeed	ransom;trigona;	1	2024-03-16	闪盘
4817	Topa-Partners	http://www.ransomfeed.it/index.php?page=post_details&id_post=13762	ransomfeed	ransom;trigona;	1	2024-03-16	托帕伙伴
4818	Indoarsip	http://www.ransomfeed.it/index.php?page=post_details&id_post=13763	ransomfeed	ransom;trigona;	1	2024-03-16	Indoarsip 印多尔西普
2641	duvelcom--boulevardcom	http://www.ransomfeed.it/index.php?page=post_details&id_post=13706	ransomfeed	ransom;blackbasta;	1	2024-03-12	杜维科-大道
2642	QEO-Group	http://www.ransomfeed.it/index.php?page=post_details&id_post=13708	ransomfeed	ransom;play;	1	2024-03-12	QEO小组
2643	ATL	http://www.ransomfeed.it/index.php?page=post_details&id_post=13709	ransomfeed	ransom;hunters;	1	2024-03-12	卫星
2645	Brewer-Davidson	http://www.ransomfeed.it/index.php?page=post_details&id_post=13711	ransomfeed	ransom;8base;	1	2024-03-13	布鲁尔-达维德森
10036	Swimlane partners with Dragos  to automate threat detection across both IT and OT environments	https://www.helpnetsecurity.com/2024/03/26/swimlane-dragos-partnership/	helpnetsecurity	news;Industry news;Dragos;Swimlane;	1	2024-03-26	与德拉戈斯公司建立游泳伙伴,使在信息技术和 OT 环境中探测威胁的自动化
2646	Forstinger-sterreich-GmbH	http://www.ransomfeed.it/index.php?page=post_details&id_post=13712	ransomfeed	ransom;8base;	1	2024-03-13	施舍者-施舍者-GmbH
10037	Vercara UltraAPI offers protection against malicious bots and fraudulent activity	https://www.helpnetsecurity.com/2024/03/26/vercara-ultraapi/	helpnetsecurity	news;Industry news;Cequence Security;Vercara;	1	2024-03-26	Vercara UltraAPI提供保护,防止恶意机器人和欺诈活动
2648	Drr-Group	http://www.ransomfeed.it/index.php?page=post_details&id_post=13714	ransomfeed	ransom;snatch;	1	2024-03-13	卓组
2647	Kovra-	http://www.ransomfeed.it/index.php?page=post_details&id_post=13713	ransomfeed	ransom;ransomhub;	1	2024-03-13	科夫拉...
2649	SBM--Co	http://www.ransomfeed.it/index.php?page=post_details&id_post=13716	ransomfeed	ransom;ransomhub;	1	2024-03-13	SPBM-Co 建立信任措施(SBM-Co)
2651	geruestbaucom	http://www.ransomfeed.it/index.php?page=post_details&id_post=13718	ransomfeed	ransom;lockbit3;	1	2024-03-13	格鲁斯特博康语Name
26190	华为折叠屏销量蝉联第一 	https://s.weibo.com/weibo?q=%23华为折叠屏销量蝉联第一 %23	sina.weibo	hotsearch;weibo	1	2024-01-09	华为折叠屏销量蝉联第一
2652	Judge-Rotenberg-Center	http://www.ransomfeed.it/index.php?page=post_details&id_post=13719	ransomfeed	ransom;blacksuit;	1	2024-03-13	罗滕贝格-中心法官
26191	华为折叠屏首次支持2米IPX8抗水 	https://s.weibo.com/weibo?q=%23华为折叠屏首次支持2米IPX8抗水 %23	sina.weibo	hotsearch;weibo	1	2024-02-22	华为折叠屏首次支持2米IPX8抗水
2734	OSGi 3.18 Remote Code Execution	https://packetstormsecurity.com/files/177549/osgi38318-exec.txt	packetstorm	vuln;;	1	2024-03-13	3.18 远距离法典执行
2735	OSGi 3.7.2 Remote Code Execution	https://packetstormsecurity.com/files/177550/osgi372-exec.txt	packetstorm	vuln;;	1	2024-03-13	3.7.2 远程代码执行
20490	Sicat - The Useful Exploit Finder	http://www.kitploit.com/2024/04/sicat-useful-exploit-finder.html	kitploit	tool;Exploit Finder;Metasploit Modules;Reconnaissance;Sicat;	1	2024-04-09	Sicat - 有用的探索发现者
2736	Karaf 4.4.3 Remote Code Execution	https://packetstormsecurity.com/files/177551/karaf443-exec.zip	packetstorm	vuln;;	1	2024-03-13	Karaf 4.4.3 远程代码执行
2729	SnipeIT 6.2.1 Stored Cross Site Scripting	https://cxsecurity.com/issue/WLB-2024030030	cxsecurity	vuln;	1	2024-03-13	SnipeIT 6.2.1 存储的跨网站脚本
2737	Red Hat Security Advisory 2024-1278-03	https://packetstormsecurity.com/files/177552/RHSA-2024-1278-03.txt	packetstorm	vuln;;	1	2024-03-13	红色帽子安保咨询 2024-1278-03
2739	VMware Cloud Director 10.5 Authentication Bypass	https://packetstormsecurity.com/files/177554/vmwarecd105-bypass.txt	packetstorm	vuln;;	1	2024-03-13	10.5 身份验证密码
2740	Red Hat Security Advisory 2024-1304-03	https://packetstormsecurity.com/files/177555/RHSA-2024-1304-03.txt	packetstorm	vuln;;	1	2024-03-13	红色帽子安保咨询 2024-1304-03
2741	Red Hat Security Advisory 2024-1305-03	https://packetstormsecurity.com/files/177556/RHSA-2024-1305-03.txt	packetstorm	vuln;;	1	2024-03-13	2024-13005-03红色帽子安保咨询
2743	MSMS-PHP 1.0 Shell Upload	https://packetstormsecurity.com/files/177558/msmsphp10-shell.txt	packetstorm	vuln;;	1	2024-03-13	MSMS-PHP 1.0 壳牌上传
2744	SnipeIT 6.2.1 Cross Site Scripting	https://packetstormsecurity.com/files/177559/snipeit621-xss.txt	packetstorm	vuln;;	1	2024-03-13	SnipeIT 6.2.1 跨站点脚本
2745	Ubuntu Security Notice USN-6691-1	https://packetstormsecurity.com/files/177560/USN-6691-1.txt	packetstorm	vuln;;	1	2024-03-13	Ubuntu Untuntu 安全通知 USN-6691-1
2746	Fabric AI Integration Tool	https://packetstormsecurity.com/files/177561/fabric-main-20240313.zip	packetstorm	vuln;;	1	2024-03-13	AI 一体化工具
2748	Ubuntu Security Notice USN-6692-1	https://packetstormsecurity.com/files/177563/USN-6692-1.txt	packetstorm	vuln;;	1	2024-03-13	Ubuntu Ubuntu 安全通知 USN6692-1
10930	FoF Pretty Mail 1.1.2 Server-Side Template Injection	https://packetstormsecurity.com/files/177848/fofpm112-ssti.txt	packetstorm	vuln;;	1	2024-03-29	FF 漂亮邮件 1.1.2 服务器平台模板喷射
10931	FoF Pretty Mail 1.1.2 Local File Inclusion	https://packetstormsecurity.com/files/177849/fofpm112-lfi.txt	packetstorm	vuln;;	1	2024-03-29	FF 漂亮邮件 1.1.2 本地文件包含
10929	FoF Pretty Mail 1.1.2 Command Injection	https://packetstormsecurity.com/files/177847/fofpm112-exec.txt	packetstorm	vuln;;	1	2024-03-29	FF 漂亮邮件 1.1.2 命令注射
2750	Client Details System 1.0 SQL Injection	https://packetstormsecurity.com/files/177565/cds10-sql.txt	packetstorm	vuln;;	1	2024-03-13	客户详细信息系统1.0 SQL 输入
2752	Stealing Part Of A Production Language Model	https://packetstormsecurity.com/files/177567/2403.06634.pdf	packetstorm	vuln;;	1	2024-03-13	制作语言模式的偷盗部分
2753	GhostRace: Exploiting And Mitigating Speculative Race Conditions	https://packetstormsecurity.com/files/177568/ghostrace_sec24.pdf	packetstorm	vuln;;	1	2024-03-13	鬼雷:剥削和减轻投机种族条件
2751	Ubuntu Security Notice USN-6663-2	https://packetstormsecurity.com/files/177566/USN-6663-2.txt	packetstorm	vuln;;	1	2024-03-13	Ubuntu Ubuntu 安全通知 USN6663-2
4821	Elior-UK-	http://www.ransomfeed.it/index.php?page=post_details&id_post=13766	ransomfeed	ransom;medusa;	1	2024-03-17	埃利奥 -联合王国
4822	highfashioncomhk	http://www.ransomfeed.it/index.php?page=post_details&id_post=13767	ransomfeed	ransom;mallox;	1	2024-03-17	高时装
2754	Ubuntu Security Notice USN-6693-1	https://packetstormsecurity.com/files/177569/USN-6693-1.txt	packetstorm	vuln;;	1	2024-03-13	Ubuntu Ubuntu 安全通知 USN6693-1
2699	网络空间指纹：新型网络犯罪研判的关键路径	https://xz.aliyun.com/t/14079	阿里先知实验室	news;	1	2024-03-11	网络空间指纹：新型网络犯罪研判的关键路径
2700	Wappalyzer的分析和欺骗	https://xz.aliyun.com/t/14082	阿里先知实验室	news;	1	2024-03-11	Wappalyzer的分析和欺骗
2701	Quaser RAT入侵检测，通讯流量特征分析及自动化检测实现	https://xz.aliyun.com/t/14083	阿里先知实验室	news;	1	2024-03-11	Quaser RAT入侵检测，通讯流量特征分析及自动化检测实现
2703	SSRF防护绕过思路与Gopher利用浅析	https://xz.aliyun.com/t/14086	阿里先知实验室	news;	1	2024-03-12	SSRF防护绕过思路与Gopher利用浅析
2702	Pwn2Own & RWCTF 6th - Let’s party in the house	https://xz.aliyun.com/t/14085	阿里先知实验室	news;	1	2024-03-12	Pwn2Own
2705	MSMS-PHP (by: oretnom23 ) v1.0 Multiple-SQLi	https://www.nu11secur1ty.com/2024/03/msms-php-by-oretnom23-v10-multiple-sqli.html	nu11security	vuln;	1	2024-03-13	MSMS-PHP (按: oretnom23) v1.0 多SQLi
2709	The ‘Emergency Powers’ Risk of a Second Trump Presidency	https://www.wired.com/story/donald-trump-emergency-powers/	wired	news;Security;Security / National Security;Politics / Policy;	1	2024-03-13	第二任特朗普总统的 " 紧急权力 " 风险
2713	Porn Sites Need Age-Verification Systems in Texas, Court Rules	https://www.wired.com/story/texas-porn-sites-age-verification/	wired	news;Security;Security / Privacy;	1	2024-03-13	得克萨斯州需要年龄核查系统的色情点,《法院规则》
2719	OSGi 3.18 Remote Code Execution	https://cxsecurity.com/issue/WLB-2024030026	cxsecurity	vuln;	1	2024-03-13	3.18 远距离法典执行
2726	MSMS-PHP (by: oretnom23 ) v1.0 File Upload - RCE browser using	https://cxsecurity.com/issue/WLB-2024030027	cxsecurity	vuln;	1	2024-03-13	MSMS-PHPP (按: oretnom23) v1.0 文件上传 - RCE 浏览器
2727	MSMS-PHP (by: oretnom23 - 2024) v1.0 Multiple-SQLi	https://cxsecurity.com/issue/WLB-2024030028	cxsecurity	vuln;	1	2024-03-13	MSMS-PHP (按: oretnom23 - 2024) v1.0 多SQLi
2728	Human Resource Management System 1.0 SQL Injection	https://cxsecurity.com/issue/WLB-2024030029	cxsecurity	vuln;	1	2024-03-13	人力资源管理系统1.0 SQL 注射
10933	Ubuntu Security Notice USN-6707-4	https://packetstormsecurity.com/files/177851/USN-6707-4.txt	packetstorm	vuln;;	1	2024-03-29	Ubuntu Ubuntu 安全通知 USN-6707-4
2774	New Fortinet FortiOS Flaw Lets Attacker Execute Arbitrary Code	https://gbhackers.com/new-fortinet-fortios-flaw/	GBHacker	news;Cyber Security News;Vulnerability;	1	2024-03-13	New Fortinnet FortiOS Flaw Les Les Les Les 攻击者执行任意法
2776	Sharp Increase in Akira Ransomware Attack Following LockBit Takedown	https://gbhackers.com/sharp-akira-ransomware-attack/	GBHacker	news;Cyber Attack;cyber security;Cyber Security News;	3	2024-03-13	Akira Ransomware在洛克比上缴后攻击事件急剧增加
2777	Stanford University Hack Exposes Over 27K People’s Data	https://gbhackers.com/stanford-university-hack/	GBHacker	news;Cyber Attack;Cyber Security News;Hacks;	1	2024-03-13	斯坦福大学哈克博览会 超过27K人民数据
2778	US govt probes if ransomware gang stole Change Healthcare data	https://buaq.net/go-227948.html	buaq	newscopy;	0	2024-03-14	如果美国政府调查赎金软件 黑帮盗取改变医疗数据
2780	Footage Captures Moment that 12-year-old Palestinian is Fatally Shot in Shuafat Refugee Camp	https://buaq.net/go-227952.html	buaq	newscopy;	0	2024-03-14	Shuafat难民营12岁的巴勒斯坦人是Fatally Shatatat难民营中Fatly shot
2782	SnipeIT 6.2.1 Stored Cross Site Scripting	https://buaq.net/go-227954.html	buaq	newscopy;	0	2024-03-14	SnipeIT 6.2.1 存储的跨网站脚本
2783	Human Resource Management System 1.0 SQL Injection	https://buaq.net/go-227955.html	buaq	newscopy;	0	2024-03-14	人力资源管理系统1.0 SQL 注射
2786	OSGi 3.18 Remote Code Execution	https://buaq.net/go-227958.html	buaq	newscopy;	0	2024-03-14	3.18 远距离法典执行
10159	Microsoft Edge Bug Could Have Allowed Attackers to Silently Install Malicious Extensions	https://thehackernews.com/2024/03/microsoft-edge-bug-could-have-allowed.html	feedburner	news;	1	2024-03-27	微软边缘虫本可以允许攻击者静静安装恶意扩展
2787	Edgeless Systems Brings Confidential Computing to AI	https://buaq.net/go-227968.html	buaq	newscopy;	0	2024-03-14	无脊椎系统将保密计算机带到AI
2781	Personal AIs Will Mediate Everything	https://buaq.net/go-227953.html	buaq	newscopy;	0	2024-03-14	个人AIs 个人AIs 愿意调解一切
10162	SASE Solutions Fall Short Without Enterprise Browser Extensions, New Report Reveals	https://thehackernews.com/2024/03/sase-solutions-fall-short-without.html	feedburner	news;	1	2024-03-27	SASE 解决方案没有企业浏览器扩展功能便短,新报告节录
10270	kruethde	http://www.ransomfeed.it/index.php?page=post_details&id_post=13966	ransomfeed	ransom;lockbit3;	1	2024-03-27	kruethde 混结
2789	Malwarebytes Premium blocks 100% of malware during external AVLab test	https://buaq.net/go-227970.html	buaq	newscopy;	0	2024-03-14	外部 AVLab 测试期间100%的恶意软件
2788	HHS to Investigate Change’s Security in Wake of Crippling Cyberattack	https://buaq.net/go-227969.html	buaq	newscopy;	0	2024-03-14	HHS 调查网络攻击震醒后变化安全情况
2790	Smashing Security podcast #363: Stuck streaming sticks, TikTok conspiracies, and spying cars	https://buaq.net/go-227971.html	buaq	newscopy;	0	2024-03-14	粉碎安全播客
2792	Windows 11 gets single Teams app for work and personal accounts	https://buaq.net/go-227973.html	buaq	newscopy;	0	2024-03-14	视窗11获得单队工作和个人账户应用程序
3678	Keboda-Technology-Co-Ltd	http://www.ransomfeed.it/index.php?page=post_details&id_post=13727	ransomfeed	ransom;bianlian;	1	2024-03-14	Keboda- 技术- 联合Ltd
2793	Hackers abuse Windows SmartScreen flaw to drop DarkGate malware	https://buaq.net/go-227974.html	buaq	newscopy;	0	2024-03-14	黑客滥用 Windows SmartScreen 瑕疵来降低 DarkGate 恶意软件
2794	From Institutional Feast to Community Ownership: The Billion Journey of ZKFair	https://buaq.net/go-227975.html	buaq	newscopy;	0	2024-03-14	从机构食物到社区所有权:ZKFair的十亿条旅程
2796	wav2vec2 for Automatic Speech Recognition In Plain English	https://buaq.net/go-227977.html	buaq	newscopy;	0	2024-03-14	wev2vec2 用普通英语自动语音识别
2797	How AI Is Transforming the Insurance Industry	https://buaq.net/go-227978.html	buaq	newscopy;	0	2024-03-14	AI 如何改变保险业
2759	Russian-Swedish national behind $400 million crypto mixer convicted of money laundering	https://therecord.media/russian-swedish-national-behind-bitcoin-fog-mixer-convicted-of-money-laundering	therecord	ransom;Cybercrime;Industry;News;News Briefs;	3	2024-03-13	俄罗斯-瑞典国民在4亿美元加密混音器背后
2765	对《关于在欧盟全境实现高度统一网络安全措施的指令》 的分析和思考	https://blog.nsfocus.net/directive-on-measures-for-a-high-common-level-of-cybersecurity-across-the-union/	绿盟	news;安全分享;	1	2024-03-13	对《关于在欧盟全境实现高度统一网络安全措施的指令》 的分析和思考
4824	Rafum-Group	http://www.ransomfeed.it/index.php?page=post_details&id_post=13769	ransomfeed	ransom;mallox;	1	2024-03-17	Rafum- 组
2769	Beware! Disguised Adobe Reader Installer That Installs Infostealer Malware	https://gbhackers.com/disguised-adobe-reader-malware-alert/	GBHacker	news;cyber security;Malware;Phishing;Malware analysis;Phishing Attack;	1	2024-03-13	当心! 安装Infostealer Maware 的伪装的 Adobe 阅读器安装程序
2770	Google’s Gemini AI Vulnerability Lets Attackers Gain Control Over Users’ Queries	https://gbhackers.com/googles-gemini-ai-vulnerability/	GBHacker	news;Cyber Security News;Google;Vulnerability;computer security;Cyber Attack;	1	2024-03-13	谷歌的Geomini AI 脆弱性让攻击者获得对用户查询的控制
2771	Andariel Hackers Attacking Asset Management Companies to Inject Malicious Code	https://gbhackers.com/hackers-attacking-asset-management/	GBHacker	news;Cyber Attack;Cyber Security News;	1	2024-03-13	Andairiel Hackers 袭击资产管理公司以注入恶意守则
2772	Magnet-Goblin Hackers Attack Public Services Using 1-Day Exploits	https://gbhackers.com/magnet-goblin/	GBHacker	news;Cyber Security News;Linux malware;Malware;computer security;cyber security;	1	2024-03-13	使用1天爆炸手段攻击公共服务
2773	Beware Of New Malicious PyPI Packages That Steal Wallet Passwords	https://gbhackers.com/malicious-pypi-packages-crypto-wallets/	GBHacker	news;cryptocurrency;cyber security;Malware;supply chain attacks;	1	2024-03-13	小心新的恶意的PyPI套件 窃取钱包密码
10932	Ubuntu Security Notice USN-6704-4	https://packetstormsecurity.com/files/177850/USN-6704-4.txt	packetstorm	vuln;;	1	2024-03-29	Ubuntu Ubuntu 安全通知 USN-6704-4
10936	Debian Security Advisory 5649-1	https://packetstormsecurity.com/files/177854/dsa-5649-1.txt	packetstorm	vuln;;	1	2024-03-29	Debian安全咨询 5649-1
2657	宏碁又遭网络袭击，菲律宾分公司大量数据被盗	https://www.freebuf.com/articles/394654.html	freebuf	news;	1	2024-03-13	宏碁又遭网络袭击，菲律宾分公司大量数据被盗
4849	Week in review: Cybersecurity job openings, hackers use 1-day flaws to drop custom Linux malware	https://www.helpnetsecurity.com/2024/03/17/week-in-review-cybersecurity-job-openings-hackers-use-1-day-flaws-to-drop-custom-linux-malware/	helpnetsecurity	news;News;Week in review;	1	2024-03-17	网络安全职位空缺, 黑客使用1天的缺陷, 丢掉定制 Linux 恶意软件
2683	Tenable enhances ExposureAI capabilities to directly query AI engine and reduce risk	https://www.helpnetsecurity.com/2024/03/13/tenable-exposureai/	helpnetsecurity	news;Industry news;Tenable;	1	2024-03-13	可租可增强IFEAI直接询问AI 引擎和减少风险的能力
2673	CrowdStrike业绩、股价狂飙，“AI+网络安全”成为资本的新宠？	https://www.freebuf.com/news/topnews/394170.html	freebuf	news;头条;	1	2024-03-12	CrowdStrike业绩、股价狂飙，“AI+网络安全”成为资本的新宠？
2686	5 Things About Doxing You Should Know	https://www.mcafee.com/blogs/internet-security/5-things-about-doxing-you-should-know/	mcafee	news;Internet Security;Doxing;What is doxing?;Is doxing illegal?;How to prevent doxing?;	1	2024-03-13	5件关于你应该知道的服毒的事情
4834	FreeBuf 周报 | Airbnb将禁止在房源内安装监控摄像头；宏碁又遭网络袭击	https://www.freebuf.com/news/394863.html	freebuf	news;资讯;	1	2024-03-14	FreeBuf 周报 | Airbnb将禁止在房源内安装监控摄像头；宏碁又遭网络袭击
2756	HHS to investigate UnitedHealth and ransomware attack on Change Healthcare	https://therecord.media/hhs-investigating-unitedhealth-after-ransomware-attack	therecord	ransom;News;Government;Cybercrime;Privacy;	2	2024-03-13	HHS 调查联合健康和赎金软件对变化保健的攻击
2738	Red Hat Security Advisory 2024-1303-03	https://packetstormsecurity.com/files/177553/RHSA-2024-1303-03.txt	packetstorm	vuln;;	1	2024-03-13	红色帽子安保咨询 2024-11303-03
4830	攻击者常用的五个数据中转网站	https://www.freebuf.com/articles/network/394937.html	freebuf	news;网络安全;	1	2024-03-15	攻击者常用的五个数据中转网站
10040	Avoid Making Costly Mistakes with Your Mobile Payment Apps	https://www.mcafee.com/blogs/mobile-security/avoid-making-costly-mistakes-with-your-mobile-payment-apps/	mcafee	news;Mobile Security;mobile payment apps;mobile payment;electronic payment apps;	1	2024-03-26	避免与您的移动支付应用程序发生代价高昂的错误
10041	Quizzes and Other Identity Theft Schemes to Avoid on Social Media	https://www.mcafee.com/blogs/privacy-identity-protection/quizzes-and-other-identity-theft-schemes-to-avoid-on-social-media/	mcafee	news;Privacy & Identity Protection;social media scams;Identity theft schemes;	1	2024-03-26	避免社会媒体上的私隐和其他身份盗窃计划
2578	Claroty Team82: 63% of Known Exploited Vulnerabilities Tracked by CISA Are on Healthcare Organization Networks	https://www.darkreading.com/ics-ot-security/claroty-team-82-63-of-known-exploited-vulnerabilities-tracked-by-cisa-are-on-healthcare-organization-networks	darkreading	news;	1	2024-03-13	Clararoty小组82:63%的CISA追踪到的已知被剥削的脆弱人群进入保健组织网络
4831	从 VNCTF2024 的一道题学习QEMU Escape	https://www.freebuf.com/defense/394960.html	freebuf	news;攻防演练;	1	2024-03-15	从 VNCTF2024 的一道题学习QEMU Escape
2747	Cisco Firepower Management Center Remote Command Execution	https://packetstormsecurity.com/files/177562/ciscofpmc-exec.txt	packetstorm	vuln;;	1	2024-03-13	Cisco 烟火管理中心远程指令执行
10043	​​Frost & Sullivan names Microsoft a Leader in the Frost Radar™: Managed Detection and Response, 2024	https://www.microsoft.com/en-us/security/blog/2024/03/25/frost-sullivan-names-microsoft-a-leader-in-the-frost-radar-managed-detection-and-response-2024/	microsoft	news;	1	2024-03-25	Frost & Sullivan 命名微软为Frost RadarTM的领袖:管理式探测和反应,2024年
4838	一周网安优质PDF资源推荐丨FreeBuf知识大陆	https://www.freebuf.com/news/394924.html	freebuf	news;资讯;	1	2024-03-15	一周网安优质PDF资源推荐丨FreeBuf知识大陆
2560	Patch Now: Kubernetes RCE Flaw Allows Full Takeover of Windows Nodes	https://www.darkreading.com/cloud-security/patch-now-kubernetes-flaw-allows-for-full-takeover-of-windows-nodes	darkreading	news;	1	2024-03-13	现在的补丁: Kubernetes RCE Flaw 允许完全接管 Windows 节点
2535	Edgeless Systems Brings Confidential Computing to AI	https://securityboulevard.com/2024/03/edgeless-systems-brings-confidential-computing-to-ai/	securityboulevard	news;Application Security;Cloud Security;Cybersecurity;Data Security;Featured;Governance, Risk & Compliance;Network Security;News;Security Boulevard (Original);Social - X;Spotlight;AI;Artificial Intelligence;confidential computing;Edgeless Systems;encryption;	1	2024-03-13	无脊椎系统将保密计算机带到AI
4853	GASMARK PRO-1.0 File Upload RCE	https://www.nu11secur1ty.com/2024/03/gasmark-pro-10-file-upload-rce.html	nu11security	vuln;	1	2024-03-17	GASMARK PRO-1.0 文件上传 RCE
4829	FOFA资产拓线实战系列：COLDRIVER	https://www.freebuf.com/articles/network/394829.html	freebuf	news;网络安全;	1	2024-03-14	FOFA资产拓线实战系列：COLDRIVER
2779	HHS to investigate UnitedHealth and ransomware attack on Change Healthcare	https://buaq.net/go-227949.html	buaq	newscopy;	0	2024-03-14	HHS 调查联合健康和赎金软件对变化保健的攻击
2755	EU Parliament passes AI Act in world’s first attempt at regulating the technology	https://therecord.media/eu-parliament-passes-ai-act-regulation	therecord	ransom;News;Technology;Government;	1	2024-03-13	欧盟议会通过《AI法案》,
10934	Soholaunch 4.9.4 r44 Shell Upload	https://packetstormsecurity.com/files/177852/soholaunch494r44-shell.txt	packetstorm	vuln;;	1	2024-03-29	Soho 发射系统 4.9.4 r44 Shell 上传
10935	Debian Security Advisory 5648-1	https://packetstormsecurity.com/files/177853/dsa-5648-1.txt	packetstorm	vuln;;	1	2024-03-29	Debian安全咨询 5648-1
3078	美洲免税店遭 Black Basta 勒索软件攻击，1.5TB 数据泄露	https://buaq.net/go-228017.html	buaq	newscopy;	0	2024-03-14	美洲免税店遭 Black Basta 勒索软件攻击，1.5TB 数据泄露
3090	两会之声 | 全国人大代表、小米集团创始人雷军：力推前沿科技产业落地 探索智能制造中国范式	https://buaq.net/go-228036.html	buaq	newscopy;	0	2024-03-14	两会之声 | 全国人大代表、小米集团创始人雷军：力推前沿科技产业落地 探索智能制造中国范式
4813	Consolidated-Benefits-Resources	http://www.ransomfeed.it/index.php?page=post_details&id_post=13758	ransomfeed	ransom;bianlian;	1	2024-03-16	合并福利资源
10044	Windows环境下病毒逆向分析，常见反调试技术手法梳理	https://xz.aliyun.com/t/14169	阿里先知实验室	news;	1	2024-03-24	Windows环境下病毒逆向分析，常见反调试技术手法梳理
3081	OPENAI的视频生成模型Sora还需要几个月才会向所有用户推出	https://buaq.net/go-228020.html	buaq	newscopy;	0	2024-03-14	OPENAI的视频生成模型Sora还需要几个月才会向所有用户推出
10045	二进制漏洞入门基础原理分析	https://xz.aliyun.com/t/14173	阿里先知实验室	news;	3	2024-03-24	二进制漏洞入门基础原理分析
10046	Miaoo 朋友圈程序审计	https://xz.aliyun.com/t/14174	阿里先知实验室	news;	1	2024-03-24	Miaoo 朋友圈程序审计
3075	NSA发布云环境应用10大安全策略	https://buaq.net/go-228012.html	buaq	newscopy;	0	2024-03-14	NSA发布云环境应用10大安全策略
4860	SiteOmat Fueling System - Default Password	https://cxsecurity.com/issue/WLB-2024030031	cxsecurity	vuln;	1	2024-03-16	站点 Omat 燃料系统 - 默认密码
4861	Schneider Electric v1.0 - Directory traversal & Broken Authentication	https://cxsecurity.com/issue/WLB-2024030032	cxsecurity	vuln;	1	2024-03-16	Schneider Electrical v1.0 - 笔记本
3091	两会之声｜两会代表委员建言网络安全：加强顶层设计 创新发展“AI+安全”	https://buaq.net/go-228037.html	buaq	newscopy;	0	2024-03-14	两会之声｜两会代表委员建言网络安全：加强顶层设计 创新发展“AI+安全”
4854	HALO-2.13.1 Cross-origin resource sharing: arbitrary origin trusted - EXPLOIT	https://www.nu11secur1ty.com/2024/03/halo-2131-cross-origin-resource-sharing.html	nu11security	vuln;	1	2024-03-15	HALO-2.13.1 跨来源资源分享:任意来源:信任的任意来源 -- -- 勘探
3088	深信服安全GPT助力用户构建安全运营的「新质生产力」	https://buaq.net/go-228029.html	buaq	newscopy;	0	2024-03-14	深信服安全GPT助力用户构建安全运营的「新质生产力」
3084	sd-web	https://buaq.net/go-228023.html	buaq	newscopy;	0	2024-03-14	sd-web 网络
3082	DarkGate Malware Exploits Recently Patched Microsoft Flaw in Zero-Day Attack	https://buaq.net/go-228021.html	buaq	newscopy;	0	2024-03-14	在零日攻击中被补封的微软法劳
3089	App+1 | 自己动手解决 Pixel 启动器的图标问题：不规则图标补全计划	https://buaq.net/go-228030.html	buaq	newscopy;	0	2024-03-14	App+1 | 自己动手解决 Pixel 启动器的图标问题：不规则图标补全计划
3092	薄荷输入法（oh-my-rime）- 跨平台 Rime 输入法配置套件：无隐私追踪、完全开源、高自定义	https://buaq.net/go-228039.html	buaq	newscopy;	0	2024-03-14	薄荷输入法（oh-my-rime）- 跨平台 Rime 输入法配置套件：无隐私追踪、完全开源、高自定义
3418	Keeping Customer Data Safe: AI’s Privacy Paradox	https://securityboulevard.com/2024/03/keeping-customer-data-safe-ais-privacy-paradox/	securityboulevard	news;Security Bloggers Network;	1	2024-03-14	维护客户数据安全:大赦国际的隐私悖论
3079	简析基于自适应学习的AI加密流量检测技术	https://buaq.net/go-228018.html	buaq	newscopy;	0	2024-03-14	简析基于自适应学习的AI加密流量检测技术
3085	NSA发布云环境应用10大安全策略	https://buaq.net/go-228026.html	buaq	newscopy;	0	2024-03-14	NSA发布云环境应用10大安全策略
3077	Great Scott Gadgets URTI: Phase Two Progress Report	https://buaq.net/go-228015.html	buaq	newscopy;	0	2024-03-14	Great Scott Godgets URTI:第二阶段进度报告
2868	150K+ UAE Network Devices &amp; Apps Found Exposed Online	https://www.darkreading.com/threat-intelligence/150kplus-uae-network-devices-apps-exposed-online	darkreading	news;	1	2024-03-14	150K UAE 网络设备
3074	小塔科技 | 2月防火墙产品市场排名	https://buaq.net/go-228003.html	buaq	newscopy;	0	2024-03-14	小塔科技 | 2月防火墙产品市场排名
2795	Demystifying Blockchain Data Access: Interview With Stateless Solutions Founder Jessica Daugherty	https://buaq.net/go-227976.html	buaq	newscopy;	0	2024-03-14	解密链链数据存取:采访无国籍者解决方案创始人Jessica Daugerty
3086	简析基于自适应学习的AI加密流量检测技术	https://buaq.net/go-228027.html	buaq	newscopy;	0	2024-03-14	简析基于自适应学习的AI加密流量检测技术
3087	已发布PoC，神秘GhostRace攻击可窃取Intel、AMD等CPU数据	https://buaq.net/go-228028.html	buaq	newscopy;	0	2024-03-14	已发布PoC，神秘GhostRace攻击可窃取Intel、AMD等CPU数据
2785	MSMS-PHP (by: oretnom23 ) v1.0 File Upload - RCE browser using	https://buaq.net/go-227957.html	buaq	newscopy;	0	2024-03-14	MSMS-PHPP (按: oretnom23) v1.0 文件上传 - RCE 浏览器
20502	All The Ways the Internet is Surveilling You	https://blog.knowbe4.com/all-the-ways-the-internet-is-surveilling-you	knowbe4	news;KnowBe4;	1	2024-04-09	互联网上的所有方式 都在拯救你
20510	Google Adds V8 Sandbox To Chrome To Fight Against Browser Attacks	https://gbhackers.com/google-v8-sandbox-chrome-security/	GBHacker	news;Chrome;CVE/vulnerability;cyber security;Browser Security;V8 Sandbox;	1	2024-04-09	Google 添加 V8 沙箱到 Chrome 对抗浏览器攻击
3083	Fortinet Warns of Severe SQLi Vulnerability in FortiClientEMS Software	https://buaq.net/go-228022.html	buaq	newscopy;	0	2024-03-14	FortiClientEMS软件中严重SQLi脆弱性的Fortnet Warns
410	SharpCovertTube - Youtube As Covert-Channel - Control Windows Systems Remotely And Execute Commands By Uploading Videos To Youtube	http://www.kitploit.com/2024/03/sharpcoverttube-youtube-as-covert.html	kitploit	tool;Command And Control;Covert Channel;SharpCovertTube;Thumbnail Images;	1	2024-03-06	SharpCoververTube - 将视频上传到 Youtube - 将Youtube 改为隐蔽通道 - 控制视窗系统,通过将视频上传到 Youtube 远程执行命令
2799	Ande Loader Malware Targets Manufacturing Sector in North America	https://thehackernews.com/2024/03/ande-loader-malware-targets.html	feedburner	news;	1	2024-03-14	北美制造部门
2802	DarkGate Malware Exploits Recently Patched Microsoft Flaw in Zero-Day Attack	https://thehackernews.com/2024/03/darkgate-malware-exploits-recently.html	feedburner	news;	1	2024-03-14	在零日攻击中被补封的微软法劳
2948	已发布PoC，神秘GhostRace攻击可窃取Intel、AMD等CPU数据	https://www.freebuf.com/articles/394821.html	freebuf	news;	1	2024-03-14	已发布PoC，神秘GhostRace攻击可窃取Intel、AMD等CPU数据
2541	Security Flaws within ChatGPT Ecosystem Allowed Access to Accounts On Third-Party Websites and Sensitive Data	https://securityboulevard.com/2024/03/security-flaws-within-chatgpt-ecosystem-allowed-access-to-accounts-on-third-party-websites-and-sensitive-data/	securityboulevard	news;Security Bloggers Network;	1	2024-03-13	允许进入第三方网站和敏感数据的账户
2944	McKim--Creed-	http://www.ransomfeed.it/index.php?page=post_details&id_post=13723	ransomfeed	ransom;ransomhub;	1	2024-03-13	麦金... 麦金... 麦金...
2805	Fortinet Warns of Severe SQLi Vulnerability in FortiClientEMS Software	https://thehackernews.com/2024/03/fortinet-warns-of-severe-sqli.html	feedburner	news;	1	2024-03-14	FortiClientEMS软件中严重SQLi脆弱性的Fortnet Warns
3073	GeoGebra-免费且功能强大的动态数学软件 可视化绘图计算器	https://buaq.net/go-228001.html	buaq	newscopy;	0	2024-03-14	GeoGebra-免费且功能强大的动态数学软件 可视化绘图计算器
2999	春秋云镜-Tsclienet	https://xz.aliyun.com/t/14093	阿里先知实验室	news;	1	2024-03-14	春秋云镜-Tsclienet
2996	春秋云境-ThermalPower	https://xz.aliyun.com/t/14088	阿里先知实验室	news;	1	2024-03-13	春秋云境-ThermalPower
2949	网络空间指纹：新型网络犯罪研判的关键路径	https://www.freebuf.com/articles/network/394688.html	freebuf	news;网络安全;	1	2024-03-13	网络空间指纹：新型网络犯罪研判的关键路径
3413	A patched Windows attack surface is still exploitable	https://securelist.com/windows-vulnerabilities/112232/	securelist	news;SOC, TI and IR posts;Microsoft Windows;Vulnerabilities;Vulnerabilities and exploits;Vulnerabilities and exploits;	1	2024-03-14	修补的 Windows 攻击表面仍然可用
2993	【翻译】apt 组织Evasive Panda（在逃熊猫）利用祈愿节来针对藏人	https://xz.aliyun.com/t/14084	阿里先知实验室	news;	2	2024-03-12	【翻译】apt 组织Evasive Panda（在逃熊猫）利用祈愿节来针对藏人
4868	Financials By Coda Authorization Bypass	https://cxsecurity.com/issue/WLB-2024030036	cxsecurity	vuln;	1	2024-03-16	以 Coda 授权的密钥
3063	150K+ Networking Devices & Apps Exposed Online With Critical Vulnerabilities	https://gbhackers.com/150k-networking-devices-apps/	GBHacker	news;Cyber Attack;Cyber Security News;Vulnerability;	1	2024-03-14	150K 联网设备
2998	PbootCMS-3.2.4代码审计	https://xz.aliyun.com/t/14090	阿里先知实验室	news;	1	2024-03-13	PbootCMS-3.2.4代码审计
4867	Financials By Coda Cross Site Scripting	https://cxsecurity.com/issue/WLB-2024030035	cxsecurity	vuln;	1	2024-03-16	通过 Coda 跨站点脚本财务
3406	Researchers Detail Kubernetes Vulnerability That Enables Windows Node Takeover	https://thehackernews.com/2024/03/researchers-detail-kubernetes.html	feedburner	news;	1	2024-03-14	使Windows节点接管的库伯网脆弱性
2997	从历史漏洞学习漏洞挖掘	https://xz.aliyun.com/t/14089	阿里先知实验室	news;	3	2024-03-13	从历史漏洞学习漏洞挖掘
2823	DCIM Software is the Key to Uptime and Performance	https://securityboulevard.com/2024/03/dcim-software-is-the-key-to-uptime-and-performance/	securityboulevard	news;Security Bloggers Network;DCIM Tools;	1	2024-03-13	DCIM 软件是更新和性能的关键
10048	[ATT&CK系列-工具使用类]使用Navigator的所有姿势~（ATT&CK框架可视化与DIY）	https://xz.aliyun.com/t/14176	阿里先知实验室	news;	1	2024-03-25	[ATT&CK系列-工具使用类]使用Navigator的所有姿势~（ATT&CK框架可视化与DIY）
10937	WatchGuard XTM Firebox Unauthenticated Remote Command Execution	https://packetstormsecurity.com/files/177855/watchguard_firebox_unauth_rce_cve_2022_26318.rb.txt	packetstorm	vuln;;	1	2024-03-29	WatchGuard XTM Firebox 未认证远程命令执行
10938	xz/liblzma Backdoored	https://packetstormsecurity.com/files/177856/liblzma-backdoor.tgz	packetstorm	vuln;;	1	2024-03-29	xz/liblzma 后门
10939	New Defense Department cyber policy office has opened	https://therecord.media/defense-department-cyber-policy-office-opens	therecord	ransom;News Briefs;Government;Leadership;	1	2024-03-29	新国防部网络政策办公室已经成立
8870	Andariel Hackers Leveraging Remote Tools To Exploit Organizations	https://gbhackers.com/andariel-hackers-remote-tools/	GBHacker	news;Cyber Attack;Cyber Security News;Malware;Asset Management Security;cyber security;Malware analysis;	1	2024-03-20	Andairiel Hackers利用远程工具到开发组织
2825	Envisioning a mobile-powered government workforce	https://securityboulevard.com/2024/03/envisioning-a-mobile-powered-government-workforce/	securityboulevard	news;Security Bloggers Network;secure mobility;Secure Spaces;	1	2024-03-13	设想一支流动动力政府劳动力队伍
2962	现已修复！微软 SmartScreen 漏洞被用于分发 DarkGate 恶意软件	https://www.freebuf.com/news/394773.html	freebuf	news;资讯;	4	2024-03-14	现已修复！微软 SmartScreen 漏洞被用于分发 DarkGate 恶意软件
3066	Hackers Abuse Amazon & GitHub to Deploy Java-based Malware	https://gbhackers.com/hackers-abuse-amazon-github/	GBHacker	news;Cyber Security News;Malware;	1	2024-03-14	亚马逊
2972	How teams can improve incident recovery time to minimize damages	https://www.helpnetsecurity.com/2024/03/14/improve-incident-recovery-time-video/	helpnetsecurity	news;Don't miss;Hot stuff;Video;automation;communication;cyberattacks;cybersecurity;disaster recovery;incident response;ShadowHQ;video;	1	2024-03-14	各小组如何改进事故恢复时间,以尽量减少损害
12617	Vultur 安卓银行木马“卷土重来”，新增远程控制功能	https://www.freebuf.com/news/396732.html	freebuf	news;资讯;	1	2024-04-02	Vultur 安卓银行木马“卷土重来”，新增远程控制功能
10049	[ATT&CK系列-学习理解类]ATT&CK威胁框架各战术、技术详解(一)  <侦察战术>	https://xz.aliyun.com/t/14179	阿里先知实验室	news;	1	2024-03-25	[ATT&CK系列-学习理解类]ATT&CK威胁框架各战术、技术详解(一) <侦察战术>
3381	315在行动｜嘶吼呼吁：提升个人信息安全意识 共建安全数字生活	https://buaq.net/go-228049.html	buaq	newscopy;	0	2024-03-14	315在行动｜嘶吼呼吁：提升个人信息安全意识 共建安全数字生活
3378	那些违法违规企业被315晚会曝光后的现状	https://buaq.net/go-228046.html	buaq	newscopy;	0	2024-03-14	那些违法违规企业被315晚会曝光后的现状
3382	大考在即，“315”前夕哪些信息安全问题最受关注？	https://buaq.net/go-228050.html	buaq	newscopy;	0	2024-03-14	大考在即，“315”前夕哪些信息安全问题最受关注？
10940	Ransomware gang leaks stolen Scottish healthcare patient data in extortion bid	https://therecord.media/healthcare-ransomware-data-breach-nhs-scotland	therecord	ransom;Cybercrime;News;	2	2024-03-29	Ransomware 黑帮泄漏窃取苏格兰医疗病人的数据
3379	央视315晚会当日节目单公布：晚8点开始，持续两小时，将关注消防、食品、金融、数据安全等	https://buaq.net/go-228047.html	buaq	newscopy;	0	2024-03-14	央视315晚会当日节目单公布：晚8点开始，持续两小时，将关注消防、食品、金融、数据安全等
10941	Malicious backdoor code embedded in popular Linux tool, CISA and Red Hat warn	https://therecord.media/malicious-backdoor-code-linux-red-hat-cisa	therecord	ransom;News;	1	2024-03-29	Linux 工具、 CISA 和Red Hat 警告
4889	Red Hat Security Advisory 2024-1334-03	https://packetstormsecurity.com/files/177616/RHSA-2024-1334-03.txt	packetstorm	vuln;;	1	2024-03-15	红帽子安保咨询2024-1334-03
4869	StimulusReflex 3.5.0 Arbitrary Code Execution	https://cxsecurity.com/issue/WLB-2024030037	cxsecurity	vuln;	1	2024-03-16	3.5.0 任意处决
4882	HALO 2.13.1 CORS Issue	https://packetstormsecurity.com/files/177609/halo2131-cors.txt	packetstorm	vuln;;	1	2024-03-15	HALO 2.13.1 CORS 问题
2585	Compromised Credentials Postings on the Dark Web Increase 20% in Just One Year	https://blog.knowbe4.com/compromised-credentials-postings-on-dark-web-increase-20-in-one-year	knowbe4	news;Social Engineering;Phishing;Security Culture;	1	2024-03-13	黑暗网络上折叠的认证海报仅在一年就增加20%
12618	智能冰箱变身加密货币矿工，导致全球厨房崩溃	https://www.freebuf.com/news/396741.html	freebuf	news;资讯;	1	2024-04-02	智能冰箱变身加密货币矿工，导致全球厨房崩溃
4884	Debian Security Advisory 5640-1	https://packetstormsecurity.com/files/177611/dsa-5640-1.txt	packetstorm	vuln;;	1	2024-03-15	Debian安全咨询 5640-1
4885	Red Hat Security Advisory 2024-1327-03	https://packetstormsecurity.com/files/177612/RHSA-2024-1327-03.txt	packetstorm	vuln;;	1	2024-03-15	2024-1327-03红色帽子安保咨询
4886	Red Hat Security Advisory 2024-1328-03	https://packetstormsecurity.com/files/177613/RHSA-2024-1328-03.txt	packetstorm	vuln;;	1	2024-03-15	2024-1328-03红色帽子安保咨询
4887	Red Hat Security Advisory 2024-1332-03	https://packetstormsecurity.com/files/177614/RHSA-2024-1332-03.txt	packetstorm	vuln;;	1	2024-03-15	红帽子安保咨询2024-1332-03
4888	Red Hat Security Advisory 2024-1333-03	https://packetstormsecurity.com/files/177615/RHSA-2024-1333-03.txt	packetstorm	vuln;;	1	2024-03-15	红帽子安保咨询2024-1333-03
4890	Red Hat Security Advisory 2024-1335-03	https://packetstormsecurity.com/files/177617/RHSA-2024-1335-03.txt	packetstorm	vuln;;	1	2024-03-15	2024-1335-03红色帽子安保咨询
4891	Ubuntu Security Notice USN-6695-1	https://packetstormsecurity.com/files/177618/USN-6695-1.txt	packetstorm	vuln;;	1	2024-03-15	Ubuntu Ubuntu 安全通知 USN6695-1
4892	Financials By Coda Cross Site Scripting	https://packetstormsecurity.com/files/177619/financialsbycoda-xss.txt	packetstorm	vuln;;	1	2024-03-15	通过 Coda 跨站点脚本财务
3386	Researchers found multiple flaws in ChatGPT plugins	https://buaq.net/go-228055.html	buaq	newscopy;	0	2024-03-14	研究者发现聊天GPT插件中存在多重缺陷
3417	Introducing Escape rules – Rules that adapt for you	https://securityboulevard.com/2024/03/introducing-escape-rules-rules-that-adapt-for-you/	securityboulevard	news;Security Bloggers Network;API security;Product updates;	2	2024-03-14	引入逃脱规则 — — 适合你的规则
3376	大洋洲日产汽车疑遭勒索攻击，约 10 万用户信息泄露	https://buaq.net/go-228044.html	buaq	newscopy;	0	2024-03-14	大洋洲日产汽车疑遭勒索攻击，约 10 万用户信息泄露
3387	每日安全动态推送(3-14)	https://buaq.net/go-228063.html	buaq	newscopy;	0	2024-03-14	每日安全动态推送(3-14)
3415	Beware the Ides of March 2024: Analyzing CISA KEV Data to Understand Danger	https://securityboulevard.com/2024/03/beware-the-ides-of-march-2024-analyzing-cisa-kev-data-to-understand-danger/	securityboulevard	news;Security Bloggers Network;Blog;	1	2024-03-14	当心2024年3月的IDdes:分析 CISA KEV 数据以了解危险
10050	一次多版本.net系统代码审计	https://xz.aliyun.com/t/14180	阿里先知实验室	news;	1	2024-03-25	一次多版本.net系统代码审计
10051	推陈出新！Kimsuky组织最新远控组件攻击场景复现	https://xz.aliyun.com/t/14181	阿里先知实验室	news;	1	2024-03-25	推陈出新！Kimsuky组织最新远控组件攻击场景复现
10057	【翻译】Python信息窃取程序利用通讯程序传播诱饵	https://xz.aliyun.com/t/14188	阿里先知实验室	news;	1	2024-03-25	【翻译】Python信息窃取程序利用通讯程序传播诱饵
3380	去年315晚会被曝光的企业咋样了 有涉事企业被罚款555万	https://buaq.net/go-228048.html	buaq	newscopy;	0	2024-03-14	去年315晚会被曝光的企业咋样了 有涉事企业被罚款555万
4870	Checkmk Agent 2.0.0 / 2.1.0 / 2.2.0 Local Privilege Escalation	https://cxsecurity.com/issue/WLB-2024030038	cxsecurity	vuln;	1	2024-03-16	2.0.0 / 2.1.0 / 2.2.0 地方特权升级
3385	Ande Loader Malware Targets Manufacturing Sector in North America	https://buaq.net/go-228054.html	buaq	newscopy;	0	2024-03-14	北美制造部门
3375	南非公务员养老基金遭 LockBit 攻击已中断发放	https://buaq.net/go-228043.html	buaq	newscopy;	0	2024-03-14	南非公务员养老基金遭 LockBit 攻击已中断发放
3240	yarcocom	http://www.ransomfeed.it/index.php?page=post_details&id_post=13724	ransomfeed	ransom;abyss;	1	2024-03-14	亚尔科康
3374	西班牙房屋租赁服务 300 万客户数据泄露	https://buaq.net/go-228042.html	buaq	newscopy;	0	2024-03-14	西班牙房屋租赁服务 300 万客户数据泄露
4906	HTB — Netmon	https://infosecwriteups.com/htb-netmon-5951e2a46486?source=rss----7b722bfd1b8d---4	infosecwriteups	tech;technology;learning;writing;hackthebox;medium;	1	2024-03-17	HTB-网网
4899	Network outages in Birmingham persist as city officials stay tight-lipped	https://therecord.media/network-outage-birmingham-alabama-ongoing-cyberattack	therecord	ransom;News;Government;Cybercrime;	1	2024-03-15	伯明翰的网络停机,
4907	LLM AI Security Checklist	https://infosecwriteups.com/llm-ai-security-checklist-06ce587d42fa?source=rss----7b722bfd1b8d---4	infosecwriteups	tech;bug-bounty;security;hacking;cybersecurity;technology;	1	2024-03-15	LLM AI 安全检查清单
4908	Mastering WordPress Penetration Testing: A Step-by-Step Guide	https://infosecwriteups.com/mastering-wordpress-penetration-testing-a-step-by-step-guide-d99a06487486?source=rss----7b722bfd1b8d---4	infosecwriteups	tech;wordpress;cybersecurity;security;bug-bounty;technology;	1	2024-03-15	万能的WordPress穿透测试:一步一步指南
4909	MRS #2: Bypassing premium features by checking “premium validation” parameters (€€€)	https://infosecwriteups.com/mrs-2-bypassing-premium-features-by-checking-premium-validation-parameters-f2e211fad160?source=rss----7b722bfd1b8d---4	infosecwriteups	tech;infosec;business-logic;bug-bounty-tips;bug-bounty;cybersecurity;	1	2024-03-15	MRS 多
4910	Penetration Testing Microsoft Copilot 365	https://infosecwriteups.com/penetration-testing-microsoft-copilot-365-910301660dac?source=rss----7b722bfd1b8d---4	infosecwriteups	tech;penetration-testing;productivity;aritificial-intelligence;ethical-hacking;microsoft;	1	2024-03-16	微软穿透测试
10942	Prisma Finance crypto theft caps strange week of platform breaches	https://therecord.media/prisma-finance-theft-caps-strange-crypto-week	therecord	ransom;News;Cybercrime;Technology;	1	2024-03-29	普里斯马金融秘密偷盗上限 奇异的一周 破坏平台的一周
10943	Ross Anderson, professor and famed author of ‘Security Engineering,’ passes away	https://therecord.media/ross-anderson-cambridge-professor-passes-away	therecord	ransom;Leadership;News;News Briefs;People;Privacy;Technology;	1	2024-03-29	Ross Anderson, 教授兼著名的 " 安全工程 " 作者,
4911	Practical Exploitation of XXE(CVE-2018–8033) and Mitigating in Apache OFBiz	https://infosecwriteups.com/practical-exploitation-of-xxe-cve-2018-8033-and-mitigating-in-apache-ofbiz-56ae8233c2b4?source=rss----7b722bfd1b8d---4	infosecwriteups	tech;exploit;	3	2024-03-15	20E(CVE-2018-8033)和Apache Opbiz的缓解措施的实际利用
10271	pcscivilinccom	http://www.ransomfeed.it/index.php?page=post_details&id_post=13967	ransomfeed	ransom;lockbit3;	1	2024-03-27	社会文明
10058	第二届AliyunCTF官方writeup	https://xz.aliyun.com/t/14190	阿里先知实验室	news;	1	2024-03-26	第二届AliyunCTF官方writeup
10272	countryvillahealthservicescom	http://www.ransomfeed.it/index.php?page=post_details&id_post=13968	ransomfeed	ransom;lockbit3;	1	2024-03-27	国家卫生服务委员会
10273	lindquistinsurancecom	http://www.ransomfeed.it/index.php?page=post_details&id_post=13969	ransomfeed	ransom;abyss;	1	2024-03-27	linquist 保险公司
4917	Google Chrome to Roll Out Real-time Phishing Protection	https://gbhackers.com/google-chrome-phishing-protection/	GBHacker	news;Cyber Security News;Google;cyber security;	1	2024-03-15	Google Chrome 推出实时幻影保护
4919	Hackers Trick Users to Install Malware Via Weaponized PDF	https://gbhackers.com/hackers-trick-users-to-install-malware-via-weaponized-pdf/	GBHacker	news;Malware;	1	2024-03-16	安装 Maware Via 武器化 PDF 的黑客骗骗骗用户
4920	Kubernetes Vulnerability Let Attackers Take Full System Control	https://gbhackers.com/kubernetes-vulnerability-full-system-control/	GBHacker	news;CVE/vulnerability;cyber security;Exploit;Command Injection;Kubernetes Vulnerability;System Security;	1	2024-03-16	Kubernetes 脆弱性
10060	ORANGE STATION-1.0 Multiple File Upload RCE	https://www.nu11secur1ty.com/2024/03/orange-station-10-multiple-file-upload.html	nu11security	vuln;	1	2024-03-26	ORANGE Statation- 1.0 多文件上传 RCE
4921	OpenCTI: OSINT Platform to SOC & MDR Teams for Malware Analysis	https://gbhackers.com/opencti/	GBHacker	news;Cyber AI;Cyber Attack;cyber security;What is;computer security;Cyber Security News;	1	2024-03-16	OpenCTI: SOC OSINT 平台
4894	Debian Security Advisory 5632-1	https://packetstormsecurity.com/files/177621/dsa-5632-1.txt	packetstorm	vuln;;	1	2024-03-15	Debian安全咨询5632-1
4732	GhostRace – New Data Leak Vulnerability Affects Modern CPUs	https://thehackernews.com/2024/03/ghostrace-new-data-leak-vulnerability.html	feedburner	news;	1	2024-03-15	鬼雷 — — 新的数据泄漏脆弱性影响现代CPU
4896	IMF says February cyberattack involved compromise of 11 email accounts	https://therecord.media/imf-february-cyberattack-email-accounts-compromised	therecord	ransom;News Briefs;News;Government;Cybercrime;	1	2024-03-15	IMF说2月的网络攻击 涉及折折折11个电子邮件账户
3388	3 Things CISOs Achieve with Cato	https://thehackernews.com/2024/03/3-things-cisos-achieve-with-cato.html	feedburner	news;	1	2024-03-14	3项CISO与Cato的CISO成就
3405	RedCurl Cybercrime Group Abuses Windows PCA Tool for Corporate Espionage	https://thehackernews.com/2024/03/redcurl-cybercrime-group-abuses-windows.html	feedburner	news;	1	2024-03-14	RedCurl网络犯罪集团滥用Windows PCC 公司间谍工具
4898	Meta loses court bid seeking to stop FTC from reopening privacy order	https://therecord.media/meta-loses-court-bid-ftc-privacy-settlement	therecord	ransom;Government;News;Privacy;	1	2024-03-15	Meta输了法院为阻止公平贸易委员会重新发布隐私令而提出的诉讼
285	基于 OPSEC 的 CobaltStrike 后渗透自动化链	https://xz.aliyun.com/t/14076	阿里先知实验室	news;	1	2024-03-11	基于 OPSEC 的 CobaltStrike 后渗透自动化链
4901	Dorkish - Chrome Extension Tool For OSINT & Recon	http://www.kitploit.com/2024/03/dorkish-chrome-extension-tool-for-osint.html	kitploit	tool;Dorkish;OSINT;Reconaissance;Reconnaissance;Shodan;Sign;Tool;	1	2024-03-16	Dorkish - OSINT 的铬扩展工具
307	The 4 Big Questions the Pentagon’s New UFO Report Fails to Answer	https://www.wired.com/story/questions-pentagon-ufo-report/	wired	news;Security;Security / National Security;Science / Space;	1	2024-03-11	五角大楼的新UFO报告无法回答的4大问题
4904	Pyradm - Python Remote Administration Tool Via Telegram	http://www.kitploit.com/2024/03/pyradm-python-remote-administration.html	kitploit	tool;Pyradm;Remote Access Tool;Telegram Rat;TelegramRAT;	1	2024-03-15	Pyradm - Python 远程管理工具 Via 电报
4922	Multistage RA World Ransomware Exploits Group Policy Infrastructure	https://gbhackers.com/ra-world-ransomware-exploits/	GBHacker	news;cyber security;Cyber Security News;ransomware;	2	2024-03-15	World Ransomwar World Ransomware 开发集团政策基础设施
4923	RedLine Malware Takes Lead in Hijacking Over 170M+ Passwords in 6 Months	https://gbhackers.com/redline-malware-hijacking-passwords/	GBHacker	news;Cyber Security News;Malware;	1	2024-03-15	6个月内 红线马拉威领先 劫持超过170米密码
3421	Revolutionizing Legal Data Security and Compliance	https://securityboulevard.com/2024/03/revolutionizing-legal-data-security-and-compliance/	securityboulevard	news;Security Bloggers Network;	1	2024-03-14	使法律数据安全与合规革命化
3449	French unemployment agency data breach impacts 43 million people	https://www.bleepingcomputer.com/news/security/french-unemployment-agency-data-breach-impacts-43-million-people/	bleepingcomputer	news;Security;	1	2024-03-14	法国失业机构数据违约情况对4 300万人造成影响
3606	Cado Security enables organizations to investigate and respond to potential M365 threats	https://www.helpnetsecurity.com/2024/03/14/cado-security-microsoft-365/	helpnetsecurity	news;Industry news;Cado Security;	1	2024-03-14	卡多安全使各组织能够调查和应对潜在的M365型M365型威胁
3494	Expel Releases Updated Toolkit in Response to NIST 2.0	https://www.darkreading.com/vulnerabilities-threats/expel-releases-updated-toolkit-in-response-to-nist-2-0	darkreading	news;	1	2024-03-14	针对NIST 2.0,更新的工具包
3487	FCC Approves Voluntary Cyber Trust Labels for Consumer IoT Products	https://www.darkreading.com/ics-ot-security/fcc-approves-voluntary-cyber-trust-labels-iot-products	darkreading	news;	1	2024-03-14	FCC 核准为消费者IoT产品提供自愿网络信托基金标签
10063	Judges Block US Extradition of WikiLeaks Founder Julian Assange—for Now	https://www.wired.com/story/julian-assange-extradite-court-decision-wikileaks/	wired	news;Security;Security / National Security;Security / Security News;	1	2024-03-26	Wikileaks Wikileaks 创始人Julian Assange(现名)
3607	Concentric AI introduces Copilot data risk module	https://www.helpnetsecurity.com/2024/03/14/concentric-ai-copilot-data-risk-module/	helpnetsecurity	news;Industry news;Concentric AI;	1	2024-03-14	同心AI引入了协同试验数据风险模块
3455	StopCrypt: Most widely distributed ransomware now evades detection	https://www.bleepingcomputer.com/news/security/stopcrypt-most-widely-distributed-ransomware-now-evades-detection/	bleepingcomputer	news;Security;	2	2024-03-14	StopCrypt:最广泛分发的赎金软件现在无法被发现
3462	Red Canary Announces Full Coverage of All Major Cloud Providers	https://www.darkreading.com/cloud-security/red-canary-announces-full-coverage-of-all-major-cloud-providers	darkreading	news;	1	2024-03-14	红运河宣布全部覆盖所有主要云源
3483	Windows SmartScreen Bypass Flaw Exploited to Drop DarkGate RAT	https://www.darkreading.com/endpoint-security/windows-smartscreen-bypass-flaw-exploited-to-drop-darkgate-rat	darkreading	news;	1	2024-03-14	Windows SmartScreen bypass Flaw 被利用以丢弃 DarkGate RAT 。
11750	Vultur Android Banking Trojan Returns with Upgraded Remote Control Capabilities	https://thehackernews.com/2024/04/vultur-android-banking-trojan-returns.html	feedburner	news;	2	2024-04-01	Vultur Vultur Android Bank Trojan 返回,并提升遥控能力
10163	Two Chinese APT Groups Ramp Up Cyber Espionage Against ASEAN Countries	https://thehackernews.com/2024/03/two-chinese-apt-groups-ramp-up-cyber.html	feedburner	news;	5	2024-03-27	反东盟国家的两个中国APT团体
3495	Fortinet Warns of Yet Another Critical RCE Flaw	https://www.darkreading.com/vulnerabilities-threats/fortinet-warns-of-yet-another-critical-rce-flaw	darkreading	news;	1	2024-03-14	" 另一危急的RCE Flaw " 的Fortnet Warns of Veet Warns of Veet Warns "
3474	Malawi Passport System Back Online After Debilitating Cyberattack	https://www.darkreading.com/cyberattacks-data-breaches/malawi-passport-system-back-online-after-cyberattack	darkreading	news;	1	2024-03-14	马拉维护照系统在对网络攻击进行破坏后返回网上
3419	Manage Access Control Lists Easily with Runtime Lists API | Impart Security	https://securityboulevard.com/2024/03/manage-access-control-lists-easily-with-runtime-lists-api-impart-security/	securityboulevard	news;Security Bloggers Network;	1	2024-03-14	使用运行时间列表 API Impart security 管理访问控制列表
3477	10 Tips for Better Security Data Management	https://www.darkreading.com/cybersecurity-analytics/10-tips-for-better-security-data-management	darkreading	news;	1	2024-03-13	改进安全数据管理10个提示
3422	Three Mechanisms to Protect Your Git Repositories	https://securityboulevard.com/2024/03/three-mechanisms-to-protect-your-git-repositories/	securityboulevard	news;Security Bloggers Network;git;supply chain security;	1	2024-03-14	保护贵地储存库的三个机制
4883	Faraday 5.2.0	https://packetstormsecurity.com/files/177610/faraday-5.2.0.tar.gz	packetstorm	vuln;;	1	2024-03-15	法拉第 5.2.0
3446	Google Chrome gets real-time phishing protection later this month	https://www.bleepingcomputer.com/news/google/google-chrome-gets-real-time-phishing-protection-later-this-month/	bleepingcomputer	news;Google;Security;	1	2024-03-14	Google Chrome本月晚些时候得到实时网络钓网保护
10047	[ATT&CK系列-应用实践类]通过ATT&CK框架完成恶意样本行为映射与WannaCry勒索病毒实践	https://xz.aliyun.com/t/14175	阿里先知实验室	news;	1	2024-03-25	[ATT&CK系列-应用实践类]通过ATT&CK框架完成恶意样本行为映射与WannaCry勒索病毒实践
10274	dkpvlawcom	http://www.ransomfeed.it/index.php?page=post_details&id_post=13970	ransomfeed	ransom;lockbit3;	1	2024-03-27	dkpvlawcom , dkpvlawcom , dkpvlawcom , dkpvlawcom 中
3610	Halo Security Dark Web Monitoring identifies and mitigates potential exposures	https://www.helpnetsecurity.com/2024/03/14/halo-security-dark-web-monitoring-feature/	helpnetsecurity	news;Industry news;Halo Security;	1	2024-03-14	光环安全暗网监测查明并减轻潜在暴露
3468	Alabama Under DDoS Cyberattack by Russian-Backed Hacktivists	https://www.darkreading.com/cyberattacks-data-breaches/alabama-targeted-by-russian-backed-ddos-cyberattack	darkreading	news;	3	2024-03-14	亚拉巴马在DDoS的网络攻击下,
26192	华为拟分红770.95亿 	https://s.weibo.com/weibo?q=%23华为拟分红770.95亿 %23	sina.weibo	hotsearch;weibo	1	2024-04-02	华为拟分红770.95亿
26193	华为新公司已向四界发出邀请 	https://s.weibo.com/weibo?q=%23华为新公司已向四界发出邀请 %23	sina.weibo	hotsearch;weibo	1	2023-11-28	华为新公司已向四界发出邀请
3786	Red Hat Security Advisory 2024-1309-03	https://packetstormsecurity.com/files/177584/RHSA-2024-1309-03.txt	packetstorm	vuln;;	1	2024-03-14	红帽子安保咨询2024-13009-03
3791	Red Hat Security Advisory 2024-1315-03	https://packetstormsecurity.com/files/177589/RHSA-2024-1315-03.txt	packetstorm	vuln;;	1	2024-03-14	2024-1315-03红色帽子安保咨询
3792	Red Hat Security Advisory 2024-1321-03	https://packetstormsecurity.com/files/177590/RHSA-2024-1321-03.txt	packetstorm	vuln;;	1	2024-03-14	2024-1321-03红色帽子安保咨询
3793	Red Hat Security Advisory 2024-1323-03	https://packetstormsecurity.com/files/177591/RHSA-2024-1323-03.txt	packetstorm	vuln;;	1	2024-03-14	2024-1323-03红色帽子安保咨询
11844	crypto-背包密码（Backpack Cryptography）	https://xz.aliyun.com/t/14209	阿里先知实验室	news;	1	2024-03-31	crypto-背包密码（Backpack Cryptography）
10064	Cybersecurity starts at home: Help your children stay safe online with open conversations	https://www.welivesecurity.com/en/kids-online/cybersecurity-starts-home-children-open-conversations/	eset	news;	1	2024-03-25	网络安全从家里开始:帮助孩子通过公开对话安全上网
11813	Xenwerx-Initiatives-LLC	http://www.ransomfeed.it/index.php?page=post_details&id_post=14047	ransomfeed	ransom;incransom;	1	2024-04-01	Xenwerx- 倡议- LLC
11815	Sisu-Healthcare	http://www.ransomfeed.it/index.php?page=post_details&id_post=14049	ransomfeed	ransom;incransom;	1	2024-04-01	Sisu-医疗保健
3384	蓝色巨人IBM也宣布裁员 并且IBM认为约30%的员工可以被人工智能取代	https://buaq.net/go-228052.html	buaq	newscopy;	0	2024-03-14	蓝色巨人IBM也宣布裁员 并且IBM认为约30%的员工可以被人工智能取代
13378	Veracode Announces Acquisition of Longbow Security	https://gbhackers.com/veracode-announces-acquisition/	GBHacker	news;cyber security;Cyber Security News;	1	2024-04-02	宣布获得长弓安全
4900	Pennsylvania’s Scranton School District dealing with ransomware attack	https://therecord.media/pennsylvania-scranton-school-district-ransomware-attack	therecord	ransom;News;Cybercrime;Government;	2	2024-03-15	宾夕法尼亚州Scranton学校区处理赎金软件袭击问题
3681	dhanisisdnet	http://www.ransomfeed.it/index.php?page=post_details&id_post=13730	ransomfeed	ransom;lockbit3;	1	2024-03-14	Dhanisisdnet 数据库
11828	DinodasRAT 恶意软件针对多国政府发起攻击	https://www.freebuf.com/news/396583.html	freebuf	news;资讯;	2	2024-04-01	DinodasRAT 恶意软件针对多国政府发起攻击
11829	俄罗斯称利用WinRAR 漏洞的攻击活动与乌克兰有关	https://www.freebuf.com/news/396604.html	freebuf	news;资讯;	3	2024-04-01	俄罗斯称利用WinRAR 漏洞的攻击活动与乌克兰有关
11830	平均每月2万起，俗套的BEC攻击成为企业的“噩梦”？	https://www.freebuf.com/news/topnews/396620.html	freebuf	news;头条;	1	2024-04-01	平均每月2万起，俗套的BEC攻击成为企业的“噩梦”？
11814	Blueline-Associates	http://www.ransomfeed.it/index.php?page=post_details&id_post=14048	ransomfeed	ransom;incransom;	1	2024-04-01	蓝线协会
3683	moperrycom	http://www.ransomfeed.it/index.php?page=post_details&id_post=13732	ransomfeed	ransom;lockbit3;	1	2024-03-14	缩略语
3789	GitLab CE/EE Password Reset	https://packetstormsecurity.com/files/177587/gitlabceee-passwordreset.txt	packetstorm	vuln;;	1	2024-03-14	GitLab CE/ EEE 密码重置
11845	src挖掘技巧总结分享	https://xz.aliyun.com/t/14211	阿里先知实验室	news;	1	2024-04-01	src挖掘技巧总结分享
11849	A Ghost Ship’s Doomed Journey Through the Gate of Tears	https://www.wired.com/story/houthi-internet-cables-ship-anchor-path/	wired	news;Security;Security / National Security;Security / Security News;	1	2024-04-01	鬼船的末日之旅穿越眼泪之门
11896	DinodasRAT Linux Malware Attack on Linux Servers to Gain Backdoor Access	https://gbhackers.com/dinodasrats-linux-malware-attack/	GBHacker	news;Cyber Attack;cyber security;Cyber Security News;	1	2024-04-01	DinodasRAT Linux Malware 攻击 Linux 服务器获取后门访问
3794	Apple Security Advisory 03-07-2024-4	https://packetstormsecurity.com/files/177592/APPLE-SA-03-07-2024-4.txt	packetstorm	vuln;;	1	2024-03-14	苹果安全咨询 03-07-2024-4
3795	Apple Security Advisory 03-07-2024-5	https://packetstormsecurity.com/files/177593/APPLE-SA-03-07-2024-5.txt	packetstorm	vuln;;	1	2024-03-14	苹果安全咨询 03-07-2024-5
3796	Apple Security Advisory 03-07-2024-6	https://packetstormsecurity.com/files/177594/APPLE-SA-03-07-2024-6.txt	packetstorm	vuln;;	1	2024-03-14	苹果安全咨询 03-07-2024-6
10303	bulwarkpestcontrolcom	http://www.ransomfeed.it/index.php?page=post_details&id_post=13999	ransomfeed	ransom;blackbasta;	1	2024-03-27	bulwarkpest controctcom 防波控制器
3797	StimulusReflex 3.5.0 Arbitrary Code Execution	https://packetstormsecurity.com/files/177595/stimulusreflex350-exec.txt	packetstorm	vuln;;	1	2024-03-14	3.5.0 任意处决
12237	FTC: Americans lost $1.1 billion to impersonation scams in 2023	https://www.bleepingcomputer.com/news/security/ftc-americans-lost-11-billion-to-impersonation-scams-in-2023/	bleepingcomputer	news;Security;Legal;	1	2024-04-01	FTC:美国人在2023年因冒名顶替骗局损失11亿美元
11812	rjcorpin	http://www.ransomfeed.it/index.php?page=post_details&id_post=14046	ransomfeed	ransom;lockbit3;	1	2024-03-31	rjcorpin (rjcorp)
3680	journeyfreightcom	http://www.ransomfeed.it/index.php?page=post_details&id_post=13729	ransomfeed	ransom;lockbit3;	1	2024-03-14	运费
10074	LimeSurvey Community 5.3.32 Cross Site Scripting	https://cxsecurity.com/issue/WLB-2024030058	cxsecurity	vuln;	1	2024-03-26	5.3.32 跨站点脚本
12238	OWASP discloses data breach caused by wiki misconfiguration	https://www.bleepingcomputer.com/news/security/owasp-discloses-data-breach-caused-by-wiki-misconfiguration/	bleepingcomputer	news;Security;	1	2024-04-01	OWASP 披露因wiki 错误配置导致数据中断
11819	《大语言模型（LLM）攻防实战手册》第一章：提示词注入（LLM01）-概述	https://www.freebuf.com/articles/database/396596.html	freebuf	news;数据安全;	1	2024-04-01	《大语言模型（LLM）攻防实战手册》第一章：提示词注入（LLM01）-概述
3788	Red Hat Security Advisory 2024-1311-03	https://packetstormsecurity.com/files/177586/RHSA-2024-1311-03.txt	packetstorm	vuln;;	1	2024-03-14	2024-1311-03红色帽子安保咨询
3892	Beware the Ides of March 2024: Analyzing CISA KEV Data to Understand Danger	https://buaq.net/go-228210.html	buaq	newscopy;	0	2024-03-15	当心2024年3月的IDdes:分析 CISA KEV 数据以了解危险
3883	Memory Safety, Re-Writing Software, and OSS Supply Chains - Omkhar Arasaratnam - PSW #820	https://buaq.net/go-228176.html	buaq	newscopy;	0	2024-03-15	记忆安全、重新写入软件和开放源码软件供应链 -- -- Omkhar Arasaratnam -- -- PSW
3896	The Dark Web and Banking: What Financial Institutions Need to Know	https://buaq.net/go-228223.html	buaq	newscopy;	0	2024-03-15	黑暗网络和银行:金融机构需要知道什么
3897	The Role of Developing Countries in Your Web3 Project’s Marketing Strategy	https://buaq.net/go-228224.html	buaq	newscopy;	0	2024-03-15	发展中国家在你们Web3项目营销战略中的作用
3886	SIM swappers now stealing phone numbers from eSIMs	https://buaq.net/go-228196.html	buaq	newscopy;	0	2024-03-15	SIM交换商现在从eSIMS窃取电话号码
3880	Combining Threat Intelligence Platforms & Sandboxes for Efficient Security Operations – A DFIR Guide	https://gbhackers.com/threat-intelligence-platforms/	GBHacker	news;Cyber Crime;cyber security;What is;	1	2024-03-14	合并威胁情报平台
3882	独立开发变现周刊（第126期） : 治愈恐慌的App月入8.3万美元	https://buaq.net/go-228146.html	buaq	newscopy;	0	2024-03-15	独立开发变现周刊（第126期） : 治愈恐慌的App月入8.3万美元
3893	Testing TensorFlowLite with Meadow .NET	https://buaq.net/go-228216.html	buaq	newscopy;	0	2024-03-15	使用 Meadow.NET 测试 Tensor FlowLite 和 Meadow 测试天线 。
11842	【翻译】xz 供应链投毒你需要知道的一切	https://xz.aliyun.com/t/14206	阿里先知实验室	news;	1	2024-03-30	【翻译】xz 供应链投毒你需要知道的一切
3881	2023 年度总结	https://buaq.net/go-228115.html	buaq	newscopy;	0	2024-03-16	2023 年度总结
11840	Escalating malware tactics drive global cybercrime epidemic	https://www.helpnetsecurity.com/2024/04/01/q4-2023-malware-rise/	helpnetsecurity	news;News;cybercrime;cybersecurity;malware;report;survey;WatchGuard;	1	2024-04-01	恶意软件策略的升级驱动全球网络犯罪的流行
3885	SIM swappers hijacking phone numbers in eSIM attacks	https://buaq.net/go-228195.html	buaq	newscopy;	0	2024-03-15	在eSIM攻击中劫持电话号码
3872	Bitcoin Fog Operator Convicted for Stealing Over $400M	https://gbhackers.com/bitcoin-fog-operator/	GBHacker	news;cryptocurrency;Cyber Attack;Cyber Security News;	1	2024-03-14	比特币雾操作员因盗窃超过400万元而被定罪
3898	How I Deployed My Own Lil' Private Internet (a.k.a. VPC)	https://buaq.net/go-228225.html	buaq	newscopy;	0	2024-03-15	我如何部署我自己的私人互联网(a.k.a. VPC)
3894	MarineMax colpito da incidente informatico: disagi operativi nel settore delle barche di lusso	https://buaq.net/go-228221.html	buaq	newscopy;	0	2024-03-15	Marine Max colpito da informico 事件: 解除大戏性大戏
4928	CTF Binary Exploitation – Cyber Apocalypse 2024: Hacker Royale – Death Note	https://buaq.net/go-228646.html	buaq	newscopy;	0	2024-03-17	CTF 二进剥削 — — 2024年网络世界末日:Hacker Royale — — 死亡笔记本
4927	“gitgub” malware campaign targets Github users with RisePro info-stealer	https://buaq.net/go-228640.html	buaq	newscopy;	0	2024-03-17	“Gitgub”恶意软件运动以Github用户为对象,使用RisePro Info-stealer
4929	Freenom 关闭域名服务 Cloudflare 托管的域名减少逾五分之一	https://buaq.net/go-228647.html	buaq	newscopy;	0	2024-03-17	Freenom 关闭域名服务 Cloudflare 托管的域名减少逾五分之一
10075	Insurance Management System PHP And MySQL 1.0 Cross Site Scripting	https://cxsecurity.com/issue/WLB-2024030059	cxsecurity	vuln;	1	2024-03-26	保险管理系统 PHP 和 MySQL 1.0 跨站点脚本
10076	ORANGE STATION-1.0 File Upload Remote Code Execution Vulnerability	https://cxsecurity.com/issue/WLB-2024030060	cxsecurity	vuln;	1	2024-03-26	OANGE Statation-1.0 文件上传远程代码执行脆弱性
4930	Microsoft again bothers Chrome users with Bing popup ads in Windows	https://buaq.net/go-228650.html	buaq	newscopy;	0	2024-03-18	微软再次骚扰在 Windows 中带有 Bing 弹出广告的铬用户
10077	MobileShop master - SQL Injection Vuln.	https://cxsecurity.com/issue/WLB-2024030061	cxsecurity	vuln;	1	2024-03-26	手机Shop大师 SQL 注射Vuln。
10078	Bludit 3.13.0 Cross Site Scripting	https://cxsecurity.com/issue/WLB-2024030062	cxsecurity	vuln;	1	2024-03-26	3.13.0 跨站点脚本
10079	SourceCodester PHP Task Management System 1.0 (admin-manage-user.php) - SQL Injection	https://cxsecurity.com/issue/WLB-2024030063	cxsecurity	vuln;	1	2024-03-26	PHP 任务管理系统1.0(管理管理-用户.php) - SQL 注射
10080	Ubuntu Security Notice USN-6701-3	https://packetstormsecurity.com/files/177759/USN-6701-3.txt	packetstorm	vuln;;	1	2024-03-26	Ubuntu Ubuntu 安全通知 USN-6701-3
3900	Antler Interactive To Showcase Their Latest Creation, Cloudborn, At GDC	https://buaq.net/go-228227.html	buaq	newscopy;	0	2024-03-15	展示其最新创作的鹿角互动,云生,GDC
3884	Undersea cable failures cause Internet disruptions for multiple African countries	https://buaq.net/go-228194.html	buaq	newscopy;	0	2024-03-15	海底电缆故障给多个非洲国家造成互联网中断
3874	Hackers Abuse Document Publishing (DDP) Websites to Launch Cyber Attacks	https://gbhackers.com/hackers-abuse-ddp-websites/	GBHacker	news;Cyber Attack;Cyber Security News;computer security;	1	2024-03-14	发起网络攻击的黑客滥用文件出版网站
3895	Cisco fixed high-severity elevation of privilege and DoS bugs	https://buaq.net/go-228222.html	buaq	newscopy;	0	2024-03-15	Cisco 固定了特权和DoS 错误的高强度高高高
12240	Shopping platform PandaBuy data leak impacts 1.3 million users	https://www.bleepingcomputer.com/news/security/shopping-platform-pandabuy-data-leak-impacts-13-million-users/	bleepingcomputer	news;Security;	1	2024-04-01	PandaBuy购物平台数据泄漏影响到130万用户
3890	Recent DarkGate campaign exploited Microsoft Windows zero-day	https://buaq.net/go-228206.html	buaq	newscopy;	0	2024-03-15	最近的 DarkGate 运动利用微软 Windows 零天
3888	CEO of Data Privacy Company Onerep.com Founded Dozens of People-Search Firms	https://buaq.net/go-228204.html	buaq	newscopy;	0	2024-03-15	数据隐私公司Onerep.com首席执行官
3875	Hackers Use Weaponized Lnk File to Deploy AutoIt Malware	https://gbhackers.com/hackers-use-weaponized/	GBHacker	news;Cyber Attack;Cyber Security News;Malware;	1	2024-03-14	Hackers 使用武器化 Lnk 文件来安装自动软件
10083	Red Hat Security Advisory 2024-1489-03	https://packetstormsecurity.com/files/177762/RHSA-2024-1489-03.txt	packetstorm	vuln;;	1	2024-03-26	2024-1489-03红色帽子安保咨询
3564	New Research: BEC Attacks Rose 246% in 2023	https://blog.knowbe4.com/bec-attacks-rose-246-in-2023	knowbe4	news;Social Engineering;Phishing;Security Awareness Training;Security Culture;	1	2024-03-14	新研究:2023年BEC攻击玫瑰246%
4935	ENISA Telecom security incidents 2022	https://buaq.net/go-228663.html	buaq	newscopy;	0	2024-03-18	ENISA 2022年电信安全事件
5575	APT28 Hacker Group Targeting Europe, Americas, Asia in Widespread Phishing Scheme	https://thehackernews.com/2024/03/apt28-hacker-group-targeting-europe.html	feedburner	news;	2	2024-03-18	APT28 以欧洲、美洲、亚洲为对象的黑客集团
17923	美国环境保护局遭黑客攻击，850万用户数据泄露	https://www.freebuf.com/articles/397144.html	freebuf	news;	1	2024-04-08	美国环境保护局遭黑客攻击，850万用户数据泄露
10082	Red Hat Security Advisory 2024-1488-03	https://packetstormsecurity.com/files/177761/RHSA-2024-1488-03.txt	packetstorm	vuln;;	1	2024-03-26	红帽子安保咨询2024-1488-03
17932	Rhadamanthys 针对石油和天然气行业发起网络钓鱼攻击	https://www.freebuf.com/news/397145.html	freebuf	news;资讯;	1	2024-04-08	Rhadamanthys 针对石油和天然气行业发起网络钓鱼攻击
3848	Senators propose a compromise over hot-button Section 702 renewal	https://therecord.media/senators-durbin-lee-propose-section-702-compromise	therecord	ransom;Government;News;Leadership;	1	2024-03-14	参议员们提议对702节的 热纽扣展期达成妥协
4939	OperationQueue + Asynchronous Code: Everything You Need to Know	https://buaq.net/go-228675.html	buaq	newscopy;	0	2024-03-18	单同步代码:你需要知道的一切
4734	Hackers Using Cracked Software on GitHub to Spread RisePro Info Stealer	https://thehackernews.com/2024/03/hackers-using-cracked-software-on.html	feedburner	news;	1	2024-03-16	使用GitHub上被破碎的软件进行黑客, 以传播崛起Pro Infe Infesteiner
4942	Building Wealth is Simple, in Theory	https://buaq.net/go-228678.html	buaq	newscopy;	0	2024-03-18	建设财富很简单,在理论中
3798	Backdoor.Win32.Emegrab.b MVID-2024-0675 Buffer Overflow	https://packetstormsecurity.com/files/177596/MVID-2024-0675.txt	packetstorm	vuln;;	1	2024-03-14	Win32.Emegrab.b MVID-2024-0675缓冲流
4937	Approvato l'AI Act europeo	https://buaq.net/go-228665.html	buaq	newscopy;	0	2024-03-18	核准《欧元法》
4933	10 Takeaways from the 2024 Gartner IAM Summit UK	https://buaq.net/go-228659.html	buaq	newscopy;	0	2024-03-18	10名从2024年英国Gartner IAM高峰会议外出
3891	USENIX Security ’23 – Powering for Privacy: Improving User Trust in Smart Speaker Microphones with Intentional Powering and Perceptible Assurance	https://buaq.net/go-228209.html	buaq	newscopy;	0	2024-03-15	USENIX 安全 23 — 隐私权力:提高用户对有有意授权和可感知保证的智能话筒的用户信任
4940	GlobalScope in Kotlin Coroutines: Is It Really Worth the Risk?	https://buaq.net/go-228676.html	buaq	newscopy;	0	2024-03-18	Kotlin Cooutines的全球景象:这真的值得冒险吗?
4938	Where do you start in removing DRM from a game	https://buaq.net/go-228674.html	buaq	newscopy;	0	2024-03-18	您从哪里开始从游戏中删除 DRM ?
3615	QuProtect Core Security secures Cisco routers against quantum threats	https://www.helpnetsecurity.com/2024/03/14/quprotect-core-security/	helpnetsecurity	news;Industry news;	1	2024-03-14	保护核心安全核心安全确保思科路由器免受量子威胁
3962	Look Good & Gain Peace of Mind with Fairwinds’ Managed Kubernetes	https://securityboulevard.com/2024/03/look-good-gain-peace-of-mind-with-fairwinds-managed-kubernetes/	securityboulevard	news;Security Bloggers Network;security;	1	2024-03-14	看好
4931	Threat actors leaked 70,000,000+ records allegedly stolen from AT&T	https://buaq.net/go-228652.html	buaq	newscopy;	0	2024-03-18	威胁行为体泄露了70 000 000的记录,据称这些记录是从AT上偷来的。
4936	eIDAS 2.0	https://buaq.net/go-228664.html	buaq	newscopy;	0	2024-03-18	eIDAS2.0
3889	StopCrypt: Most widely distributed ransomware now evades detection	https://buaq.net/go-228205.html	buaq	newscopy;	0	2024-03-15	StopCrypt:最广泛分发的赎金软件现在无法被发现
3682	voidinteractivenet-you-are-welcome-in-our-chat	http://www.ransomfeed.it/index.php?page=post_details&id_post=13731	ransomfeed	ransom;donutleaks;	1	2024-03-14	无效的互用网络 欢迎来到我们的聊天场
4932	How to Master Authentication and User Flow in Node.js With Knex and Redis	https://buaq.net/go-228653.html	buaq	newscopy;	0	2024-03-17	如何在 Knex 和 Redis 的 Nde.js 中控制验证和用户流
10305	Pavilion-Construction	http://www.ransomfeed.it/index.php?page=post_details&id_post=14001	ransomfeed	ransom;play;	1	2024-03-27	馆 馆 馆 馆 馆 馆 馆 馆 馆 馆 馆 馆 馆 馆 馆 馆 馆 馆 馆 馆 馆 馆 馆 馆 馆 馆 馆 馆 馆 馆 馆 馆 馆 馆 馆 馆 馆 馆 馆 馆 馆 馆 馆 馆 馆 馆 馆 馆 馆 馆 馆 馆 馆 馆 馆 馆
3877	Microsoft Copilot for Security: AI tool to Help Security and IT professionals	https://gbhackers.com/microsoft-copilot-for-security/	GBHacker	news;Cyber AI;cyber security;Cyber Security News;Security Tools;computer security;	1	2024-03-14	微软安全联合试点项目:AI帮助安全和信息技术专业人员的工具
3808	Checkmk Agent 2.0.0 / 2.1.0 / 2.2.0 Local Privilege Escalation	https://packetstormsecurity.com/files/177606/SA-20240307-0.txt	packetstorm	vuln;;	1	2024-03-14	2.0.0 / 2.1.0 / 2.2.0 地方特权升级
3790	Red Hat Security Advisory 2024-1314-03	https://packetstormsecurity.com/files/177588/RHSA-2024-1314-03.txt	packetstorm	vuln;;	1	2024-03-14	2024-1314-03红色帽子安保咨询
4944	The Noonification: Effective Workarounds for SQL-Style Joins in Elasticsearch (3/17/2024)	https://buaq.net/go-228680.html	buaq	newscopy;	0	2024-03-18	说明:为SQL-Style Insearch中的SQL-Style Comits提供有效变通办法(3/17/2024)
3963	Navigating the Digital Operational Resilience Act (DORA)	https://securityboulevard.com/2024/03/navigating-the-digital-operational-resilience-act-dora/	securityboulevard	news;Security Bloggers Network;security posture;	1	2024-03-14	指导《数字行动复原力法》(DORA)
10081	Red Hat Security Advisory 2024-1487-03	https://packetstormsecurity.com/files/177760/RHSA-2024-1487-03.txt	packetstorm	vuln;;	1	2024-03-26	红色帽子安保咨询 2024-1487-03
10087	Red Hat Security Advisory 2024-1490-03	https://packetstormsecurity.com/files/177766/RHSA-2024-1490-03.txt	packetstorm	vuln;;	1	2024-03-26	红帽子安保咨询 2024-1490-03
5878	美国电信公司AT&T 否认超 7000 万人数据被盗	https://buaq.net/go-228726.html	buaq	newscopy;	0	2024-03-18	美国电信公司AT&T 否认超 7000 万人数据被盗
4154	200小时挑战，最终收获$20,300赏金的故事	https://buaq.net/go-228237.html	buaq	newscopy;	0	2024-03-15	200小时挑战，最终收获$20,300赏金的故事
17940	Threat actors are raising the bar for cyber attacks	https://www.helpnetsecurity.com/2024/04/08/cyberattacks-implications-video/	helpnetsecurity	news;Video;Barracuda Networks;cybersecurity;EfficientIP;Netacea;NetWitness;PhishFirewall;video;	1	2024-04-08	威胁行为体正在提高网络攻击的屏障
14160	Cyberattacks Wreaking Physical Disruption on the Rise	https://www.darkreading.com/ics-ot-security/cyberattacks-wreaking-physical-disruption-on-the-rise	darkreading	news;	1	2024-04-02	Cyberattacks Wreaking Physical Disruption on the Rise
4159	谷歌将在5月14日举办Google I/O 2024全球开发者大会	https://buaq.net/go-228242.html	buaq	newscopy;	0	2024-03-15	谷歌将在5月14日举办Google I/O 2024全球开发者大会
14410	China-linked Hackers Deploy New 'UNAPIMON' Malware for Stealthy Operations	https://thehackernews.com/2024/04/china-linked-hackers-deploy-new.html	feedburner	news;	4	2024-04-02	与中国有联系的黑客部署新“ UNAPIMON ” 用于隐形操作的 Maware
4160	5Ghoul Revisited: Three Months Later, (Fri, Mar 15th)	https://buaq.net/go-228243.html	buaq	newscopy;	0	2024-03-15	5Ghoul Review: 三个月后, (Fri, Mar 15th)
4330	worthenindcom	http://www.ransomfeed.it/index.php?page=post_details&id_post=13735	ransomfeed	ransom;lockbit3;	1	2024-03-15	价值天文
4157	谷歌浏览器正在增强实时安全保护 将每个网址发送给谷歌检查是否为恶意网站	https://buaq.net/go-228240.html	buaq	newscopy;	0	2024-03-15	谷歌浏览器正在增强实时安全保护 将每个网址发送给谷歌检查是否为恶意网站
4165	微软在全球222个国家或地区推出Copilot Pro服务 可以免费试用1个月	https://buaq.net/go-228250.html	buaq	newscopy;	0	2024-03-15	微软在全球222个国家或地区推出Copilot Pro服务 可以免费试用1个月
4166	ISC Stormcast For Friday, March 15th, 2024 https://isc.sans.edu/podcastdetail/8896, (Fri, Mar 15th)	https://buaq.net/go-228252.html	buaq	newscopy;	0	2024-03-15	2024年3月15日星期五的ISC风暴预报 https://isc.sans.edu/podcastdetail/8896 (Fri, Mar 15th)
15085	iMessage是怎么成为“黑灰产的乐园”	https://www.freebuf.com/articles/neopoints/396882.html	freebuf	news;观点;	1	2024-04-03	iMessage是怎么成为“黑灰产的乐园”
4329	mckimcreedcom	http://www.ransomfeed.it/index.php?page=post_details&id_post=13734	ransomfeed	ransom;lockbit3;	1	2024-03-14	mcccimcreedcom( mcccimcreedcom )
15031	Fortanix Builds Private Search for AI	https://www.darkreading.com/data-privacy/bringing-private-search-for-ai	darkreading	news;	1	2024-04-02	Fortanix 建立 AI 的私密搜索
4048	FreeBuf 早报 | 欧洲议会正式通过人工智能监管法案；大洋洲日产汽车公司遭入侵	https://www.freebuf.com/news/394814.html	freebuf	news;资讯;	1	2024-03-14	FreeBuf 早报 | 欧洲议会正式通过人工智能监管法案；大洋洲日产汽车公司遭入侵
4049	波及4300万人！法国官方就业机构数据遭窃	https://www.freebuf.com/news/394879.html	freebuf	news;资讯;	1	2024-03-15	波及4300万人！法国官方就业机构数据遭窃
4156	英特尔推出Intel Core i9-14900KS旗舰处理器 默认即提供6.2GHz的频率	https://buaq.net/go-228239.html	buaq	newscopy;	0	2024-03-15	英特尔推出Intel Core i9-14900KS旗舰处理器 默认即提供6.2GHz的频率
4331	rushenergyservicescom	http://www.ransomfeed.it/index.php?page=post_details&id_post=13736	ransomfeed	ransom;lockbit3;	1	2024-03-15	热能服务中心
4059	AI and the future of corporate security	https://www.helpnetsecurity.com/2024/03/15/ai-technology-guardrails-video/	helpnetsecurity	news;Don't miss;Hot stuff;Video;access control;artificial intelligence;cybersecurity;Everbridge;fraud;insider threat;threats;video;	1	2024-03-15	大赦国际与公司担保的未来
4067	​​Microsoft named as a Leader in three IDC MarketScapes for Modern Endpoint Security 2024	https://techcommunity.microsoft.com/t5/security-compliance-and-identity/microsoft-named-as-a-leader-in-three-idc-marketscapes-for-modern/ba-p/4083116	microsoft	news;	1	2024-03-14	微软公司被命名为3个国际开发公司现代终端安全2024年市场杯的领先者。
4155	俄/加公民瓦西里耶夫因通过LockBit勒索数千万美元被判刑四年	https://buaq.net/go-228238.html	buaq	newscopy;	0	2024-03-15	俄/加公民瓦西里耶夫因通过LockBit勒索数千万美元被判刑四年
4163	聚焦两会｜《计划报告》中的“数据要素”	https://buaq.net/go-228248.html	buaq	newscopy;	0	2024-03-15	聚焦两会｜《计划报告》中的“数据要素”
4060	New infosec products of the week: March 15, 2024	https://www.helpnetsecurity.com/2024/03/15/new-infosec-products-of-the-week-march-15-2024/	helpnetsecurity	news;News;AuditBoard;Cynerio;DataDome;Regula;Tenable;	1	2024-03-15	2024年3月15日 2024年3月15日
5876	谷歌升级 Safe Browsing，为用户增强实时 URL 保护	https://buaq.net/go-228724.html	buaq	newscopy;	0	2024-03-18	谷歌升级 Safe Browsing，为用户增强实时 URL 保护
5877	麦当劳全球系统宕机，影响数千家门店	https://buaq.net/go-228725.html	buaq	newscopy;	0	2024-03-18	麦当劳全球系统宕机，影响数千家门店
10084	Ubuntu Security Notice USN-6704-3	https://packetstormsecurity.com/files/177763/USN-6704-3.txt	packetstorm	vuln;;	1	2024-03-26	Ubuntu Ubuntu 安全通知 USN-6704-3
13394	企业如何设计和实施有效的网络安全演练？	https://www.freebuf.com/news/396750.html	freebuf	news;资讯;	1	2024-04-02	企业如何设计和实施有效的网络安全演练？
10085	Orange Station 1.0 Shell Upload	https://packetstormsecurity.com/files/177764/orangestation10-shell.txt	packetstorm	vuln;;	1	2024-03-26	橙色站1.0壳牌上传
10086	LimeSurvey Community 5.3.32 Cross Site Scripting	https://packetstormsecurity.com/files/177765/limesurveycommunity5332-xss.txt	packetstorm	vuln;;	1	2024-03-26	5.3.32 跨站点脚本
394	French government agencies hit by cyberattacks of ‘unprecedented intensity’	https://therecord.media/france-government-ddos-incident	therecord	ransom;Government;News;News Briefs;Nation-state;	1	2024-03-11	法国政府机构遭到网络攻击「前所未有的激烈程度」,
4743	How to Think Like a Hacker — and Defend Your Data	https://securityboulevard.com/2024/03/how-to-think-like-a-hacker-and-defend-your-data/	securityboulevard	news;Security Bloggers Network;	1	2024-03-17	如何思考像黑客 — 并捍卫你的数据
1526	JetBrains vulnerability exploitation highlights debate over 'silent patching'	https://buaq.net/go-227703.html	buaq	newscopy;	0	2024-03-13	Jeffbrains 脆弱性开发凸显了对“沉默补丁”的争论。
17941	How malicious email campaigns continue to slip through the cracks	https://www.helpnetsecurity.com/2024/04/08/email-remains-predominant-target-video/	helpnetsecurity	news;Don't miss;Hot stuff;Video;Cofense;communication;cybersecurity;email;exploit;phishing;QR codes;video;vishing;	1	2024-04-08	恶意的电子邮件活动如何继续从裂缝中溜走
10088	Red Hat Security Advisory 2024-1491-03	https://packetstormsecurity.com/files/177767/RHSA-2024-1491-03.txt	packetstorm	vuln;;	1	2024-03-26	红帽子安保咨询 2024-1491-03
10325	Google Play 上的免费VPN应用能将用户手机变成恶意代理	https://www.freebuf.com/news/396042.html	freebuf	news;资讯;	1	2024-03-27	Google Play 上的免费VPN应用能将用户手机变成恶意代理
10089	Red Hat Security Advisory 2024-1496-03	https://packetstormsecurity.com/files/177768/RHSA-2024-1496-03.txt	packetstorm	vuln;;	1	2024-03-26	红帽子安保咨询 2024-1496-03
20546	Rocket DevOps simplifies compliance processes	https://www.helpnetsecurity.com/2024/04/09/rocket-devops-suite/	helpnetsecurity	news;Industry news;Rocket Software;	1	2024-04-09	火箭设计设计系统简化遵守程序
1193	To Spot Attacks Through AI Models, Companies Need Visibility	https://www.darkreading.com/cyber-risk/ai-models-take-off-leaving-security-behind	darkreading	news;	1	2024-03-11	通过AI 模型对袭击进行现场袭击,公司需要能见度
4796	ATL-Leasing	http://www.ransomfeed.it/index.php?page=post_details&id_post=13740	ransomfeed	ransom;hunters;	1	2024-03-15	ATL-租赁
4780	If Social Engineering Accounts for up to 90% of Attacks, Why Is It Ignored?	https://blog.knowbe4.com/social-engineering-accounts-for-90-of-attacks-why-is-it-ignored	knowbe4	news;Social Engineering;Phishing;Spear Phishing;	1	2024-03-15	如果社会工程账户 高达90%的攻击, 为什么被忽略?
10091	Ubuntu Security Notice USN-6707-3	https://packetstormsecurity.com/files/177770/USN-6707-3.txt	packetstorm	vuln;;	1	2024-03-26	Ubuntu Ubuntu 安全通知 USN-6707-3
201	​​Secure SaaS applications with Valence Security and Microsoft Security​​	https://www.microsoft.com/en-us/security/blog/2024/03/05/secure-saas-applications-with-valence-security-and-microsoft-security/	microsoft	news;	1	2024-03-05	具有Valence安全和微软安全的SaaS安全应用程序
4770	6 CISO Takeaways From the NSA's Zero-Trust Guidance	https://www.darkreading.com/cybersecurity-operations/6-ciso-takeaways-nsa-zero-trust-guidance	darkreading	news;	1	2024-03-15	6个来自消极安全保证零信任指导的CISO取走
4363	90% of exposed secrets on GitHub remain active for at least five days	https://www.helpnetsecurity.com/2024/03/15/github-sensitive-information-exposure/	helpnetsecurity	news;News;cybersecurity;data leak;GitGuardian;GitHub;report;survey;	1	2024-03-15	GitHub上90%的公开秘密 保持至少五天
1533	USENIX Security ’23 – Piet De Vaere, Adrian Perrig – Hey Kimya, Is My Smart Speaker Spying On Me? Taking Control Of Sensor Privacy Through Isolation And Amnesia	https://buaq.net/go-227712.html	buaq	newscopy;	0	2024-03-13	USENIX 安全 23 — — Piet De Vaere, Adrian Perrig — — Hey Kimya, 我的聪明演讲人是否在监视我? 通过隔离和失忆控制感官隐私
4746	Securing Your Software Development in Compliance with CISA: How OX Security Simplifies the Process	https://securityboulevard.com/2024/03/securing-your-software-development-in-compliance-with-cisa-how-ox-security-simplifies-the-process/	securityboulevard	news;Governance, Risk & Compliance;Security Bloggers Network;Compliance;	1	2024-03-15	确保您的软件开发符合独联体国家信息系统:牛津安全如何简化程序
1530	Acer confirms Philippines employee data leaked on hacking forum	https://buaq.net/go-227707.html	buaq	newscopy;	0	2024-03-13	Acer确认菲律宾员工数据在黑客论坛泄露
17942	Industrial sectors embrace zero trust for enhanced security	https://www.helpnetsecurity.com/2024/04/08/ot-environments-zero-trust-implementation/	helpnetsecurity	news;News;cybersecurity;digital transformation;report;survey;Xage Security;zero trust;	1	2024-04-08	工业部门对加强安全表示零信任
844	International Women’s Day: Expanding cybersecurity opportunities in the era of AI	https://www.microsoft.com/en-us/security/blog/2024/03/08/international-womens-day-expanding-cybersecurity-opportunities-in-the-era-of-ai/	microsoft	news;	1	2024-03-08	国际妇女节国际妇女节:在AI时代扩大网络安全机会
1180	Over 12 million auth secrets and keys leaked on GitHub in 2023	https://www.bleepingcomputer.com/news/security/over-12-million-auth-secrets-and-keys-leaked-on-github-in-2023/	bleepingcomputer	news;Security;	1	2024-03-12	2023年GitHub 泄露了超过1 200万个授权机密和密钥
20513	Thousands Of Internet-Exposed Ivanti VPN Appliances Vulnerable To RCE Attacks	https://gbhackers.com/ivanti-vpn-rce-vulnerabilities/	GBHacker	news;CVE/vulnerability;cyber security;Network Security;cybersecurity;Remote code execution;Vulnerabilities;	1	2024-04-09	成千上万的互联网上被灭绝的Ivanti VPN 易受到RCME攻击的
4764	'GhostRace' Speculative Execution Attack Impacts All CPU, OS Vendors	https://www.darkreading.com/cyber-risk/ghostrace-speculative-execution-attack-cpu-os-vendors	darkreading	news;	1	2024-03-15	所有CPU,OS销售商
4727	Crypto Phishing Kit Impersonating Login Pages: Stay Informed	https://buaq.net/go-228289.html	buaq	newscopy;	0	2024-03-15	加密钓鱼工具 冒名登录页面: 保持知情
4728	每日安全动态推送(3-15)	https://buaq.net/go-228297.html	buaq	newscopy;	0	2024-03-15	每日安全动态推送(3-15)
4613	日产汽车承认 10 万人的数据信息遭窃	https://www.freebuf.com/news/394908.html	freebuf	news;资讯;	1	2024-03-15	日产汽车承认 10 万人的数据信息遭窃
10093	Red Hat Security Advisory 2024-1499-03	https://packetstormsecurity.com/files/177772/RHSA-2024-1499-03.txt	packetstorm	vuln;;	1	2024-03-26	红帽子安保咨询 2024-1499-03
10327	AU10TIX’s Digital ID suite identifies potentially fraudulent activities	https://www.helpnetsecurity.com/2024/03/27/au10tix-digital-id-solution/	helpnetsecurity	news;Industry news;AU10TIX;	1	2024-03-27	AU10TIX的数字身份证套件查明了潜在的欺诈活动。
10332	Drozer: Open-source Android security assessment framework	https://www.helpnetsecurity.com/2024/03/27/drozer-open-source-android-security-assessment-framework/	helpnetsecurity	news;Don't miss;Hot stuff;News;Android;application security;GitHub;mobile security;open source;penetration testing;software;WithSecure;	2	2024-03-27	Drozer:开放源码和机器人安非他明安全评估框架
4444	Google Introduces Enhanced Real-Time URL Protection for Chrome Users	https://thehackernews.com/2024/03/google-introduces-enhanced-real-time.html	feedburner	news;	1	2024-03-15	Google为铬用户引入强化实时URL保护
10092	Craft CMS 4.4.14 Remote Code Execution	https://packetstormsecurity.com/files/177771/craftcms4414-exec.txt	packetstorm	vuln;;	1	2024-03-26	CMS 4.4.14 远程代码执行
4711	一次常规更新：M3 版 MacBook Air 快速上手	https://buaq.net/go-228270.html	buaq	newscopy;	0	2024-03-15	一次常规更新：M3 版 MacBook Air 快速上手
10094	Red Hat Security Advisory 2024-1500-03	https://packetstormsecurity.com/files/177773/RHSA-2024-1500-03.txt	packetstorm	vuln;;	1	2024-03-26	红色帽子安保咨询2024-1500-03
10095	Red Hat Security Advisory 2024-1501-03	https://packetstormsecurity.com/files/177774/RHSA-2024-1501-03.txt	packetstorm	vuln;;	1	2024-03-26	红色帽子安保咨询 2024-1501-03
4648	Threat intelligence explained | Unlocked 403: A cybersecurity podcast	https://www.welivesecurity.com/en/videos/threat-intelligence-explained-unlocked-403-cybersecurity-podcast/	eset	news;	1	2024-03-14	网络安全播客:网络安全播客
4701	Critical ChatGPT Plugins Flaw Let Attackers Gain Control Over Organization’s Account	https://gbhackers.com/critical-chatgpt-plugins-flaw/	GBHacker	news;Artificial Intelligence;CVE/vulnerability;Cyber AI;cyber security;ChatGPT Plugins;Cyber Security News;Vulnerabilities;	1	2024-03-15	关键聊天GPT 插件
10881	AI abuse and misinformation campaigns threaten financial institutions	https://www.helpnetsecurity.com/2024/03/29/financial-firms-cyberthreats/	helpnetsecurity	news;News;cybercrime;cybersecurity;financial industry;Generative AI;report;survey;threats;	1	2024-03-29	滥用大赦国际和错误信息运动威胁金融机构
4710	Malicious Ads Targeting Chinese Users with Fake Notepad++ and VNote Installers	https://buaq.net/go-228263.html	buaq	newscopy;	0	2024-03-15	使用假笔记和 VNote 安装器瞄准中国用户
1540	Serverless Architecture for B2B SaaS Products: Benefits and Considerations	https://buaq.net/go-227723.html	buaq	newscopy;	0	2024-03-13	B2B SaaS产品无服务器建筑:效益和考虑
10090	Red Hat Security Advisory 2024-1497-03	https://packetstormsecurity.com/files/177769/RHSA-2024-1497-03.txt	packetstorm	vuln;;	1	2024-03-26	红色帽子安保咨询 2024-1497-03
4715	独家情报 | 2023年国内APT攻击威胁年报	https://buaq.net/go-228275.html	buaq	newscopy;	0	2024-03-15	独家情报 | 2023年国内APT攻击威胁年报
4716	英国高等法院裁决 Craig Wright 不是中本聪	https://buaq.net/go-228276.html	buaq	newscopy;	0	2024-03-15	英国高等法院裁决 Craig Wright 不是中本聪
4714	喜报 | 御安信息网安智能威胁检测处置平台入选省级示范项目	https://buaq.net/go-228274.html	buaq	newscopy;	0	2024-03-15	喜报 | 御安信息网安智能威胁检测处置平台入选省级示范项目
4717	日本和东盟将在 2025 年实现扫码支付互通	https://buaq.net/go-228277.html	buaq	newscopy;	0	2024-03-15	日本和东盟将在 2025 年实现扫码支付互通
4712	聊聊网络安全培训 - 飘渺红尘✨	https://buaq.net/go-228272.html	buaq	newscopy;	0	2024-03-15	聊聊网络安全培训 - 飘渺红尘✨
4718	外交部批评美国众议院通过 TikTok 法案	https://buaq.net/go-228278.html	buaq	newscopy;	0	2024-03-15	外交部批评美国众议院通过 TikTok 法案
4719	Google Chrome 安全浏览保护将实时检查用户访问的网址	https://buaq.net/go-228279.html	buaq	newscopy;	0	2024-03-15	Google Chrome 安全浏览保护将实时检查用户访问的网址
4720	Let's Encrypt旧的根证书即将到期 Android 7.1.1及更早版本的用户将受影响	https://buaq.net/go-228281.html	buaq	newscopy;	0	2024-03-15	Let's Encrypt旧的根证书即将到期 Android 7.1.1及更早版本的用户将受影响
4721	微软宣布在2025年3月31日停用Visual Studio应用中心 后续无法再API调用	https://buaq.net/go-228282.html	buaq	newscopy;	0	2024-03-15	微软宣布在2025年3月31日停用Visual Studio应用中心 后续无法再API调用
4722	欧盟用户现在已经可以正常卸载Microsoft Edge浏览器 不需要借助额外工具	https://buaq.net/go-228283.html	buaq	newscopy;	0	2024-03-15	欧盟用户现在已经可以正常卸载Microsoft Edge浏览器 不需要借助额外工具
4723	微软通过Windows 10/11系统弹窗请求将必应搜索设置Chrome默认搜索	https://buaq.net/go-228284.html	buaq	newscopy;	0	2024-03-15	微软通过Windows 10/11系统弹窗请求将必应搜索设置Chrome默认搜索
4725	Google Introduces Enhanced Real-Time URL Protection for Chrome Users	https://buaq.net/go-228286.html	buaq	newscopy;	0	2024-03-15	Google为铬用户引入强化实时URL保护
4726	Il podcast salta anche questa settimana	https://buaq.net/go-228287.html	buaq	newscopy;	0	2024-03-15	Il 播客 盐类 anche 探险 康提马纳
4724	I container Kubernetes delle aziende sono a rischio ransomware	https://buaq.net/go-228285.html	buaq	newscopy;	0	2024-03-15	库伯涅兹·戴勒·阿齐安德 索诺意大利面条赎金器械
10385	Red Hat Security Advisory 2024-1515-03	https://packetstormsecurity.com/files/177791/RHSA-2024-1515-03.txt	packetstorm	vuln;;	1	2024-03-27	红色帽子安保咨询2024-1515-03
14549	Malicious Code in XZ Utils for Linux Systems Enables Remote Code Execution	https://thehackernews.com/2024/04/malicious-code-in-xz-utils-for-linux.html	feedburner	news;	1	2024-04-02	XZ Linux 系统中的 XZ 无效代码工具允许远程代码执行
10099	Red Hat Security Advisory 2024-1510-03	https://packetstormsecurity.com/files/177778/RHSA-2024-1510-03.txt	packetstorm	vuln;;	1	2024-03-26	红色帽子安保咨询2024-1510-03
10098	Red Hat Security Advisory 2024-1509-03	https://packetstormsecurity.com/files/177777/RHSA-2024-1509-03.txt	packetstorm	vuln;;	1	2024-03-26	红色帽子安保咨询2024-1509-03
675	Powill-Manufacturing--Engineering	http://www.ransomfeed.it/index.php?page=post_details&id_post=13555	ransomfeed	ransom;play;	1	2024-03-02	将 - 制造 - 工程 - 工程
2518	Join Our Webinar on Protecting Human and Non-Human Identities in SaaS Platforms	https://thehackernews.com/2024/03/join-our-webinar-on-protecting-human.html	feedburner	news;	1	2024-03-13	加入我们在SaaS平台上关于保护人类和非人类身份的网络研讨会
15099	黑客滥用谷歌虚假广告传播恶意软件	https://www.freebuf.com/news/396864.html	freebuf	news;资讯;	2	2024-04-03	黑客滥用谷歌虚假广告传播恶意软件
1166	DOJ Warns Using AI in Crimes Will Mean Harsher Sentences	https://securityboulevard.com/2024/03/doj-warns-using-ai-in-crimes-will-mean-harsher-sentences/	securityboulevard	news;Cyberlaw;Cybersecurity;Data Security;Featured;Governance, Risk & Compliance;Industry Spotlight;Mobile Security;Network Security;News;Security Awareness;Security Boulevard (Original);Social - Facebook;Social - LinkedIn;Social - X;Spotlight;AI;Department of Justice (DOJ);	1	2024-03-12	DOJ Warns Warns 在犯罪中使用AI
2704	MSMS-PHP (by: oretnom23 ) v1.0 File Upload - RCE browser using	https://www.nu11secur1ty.com/2024/03/msms-php-by-oretnom23-v10-file-upload.html	nu11security	vuln;	1	2024-03-13	MSMS-PHPP (按: oretnom23) v1.0 文件上传 - RCE 浏览器
4820	Autorit-di-Sistema-Portuale-del-Mar-Tirreno-Settentrionale-It	http://www.ransomfeed.it/index.php?page=post_details&id_post=13765	ransomfeed	ransom;medusa;	1	2024-03-17	自动- di- 西斯泰马- 单式- del- del- mar- Tirreno- Settetrionale- It
4816	HUDSONBUSSALESCOM	http://www.ransomfeed.it/index.php?page=post_details&id_post=13761	ransomfeed	ransom;clop;	1	2024-03-16	人道主义教育
4752	Microsoft again bothers Chrome users with Bing popup ads in Windows	https://www.bleepingcomputer.com/news/microsoft/microsoft-again-bothers-chrome-users-with-bing-popup-ads-in-windows/	bleepingcomputer	news;Microsoft;Google;	1	2024-03-17	微软再次骚扰在 Windows 中带有 Bing 弹出广告的铬用户
5852	微软3月安全更新多个产品高危漏洞通告	https://blog.nsfocus.net/microsoftmarch-2/	绿盟	news;威胁通告;安全分享;安全漏洞;漏洞防护;	3	2024-03-18	微软3月安全更新多个产品高危漏洞通告
5854	DarkGPT – A ChatGPT-4 Powered OSINT Tool To Detect Leaked Databases	https://gbhackers.com/darkgpt/	GBHacker	news;Cyber AI;What is;computer security;Cyber Security News;	1	2024-03-18	黑暗 — — 检测泄漏数据库的ChatgPT-4动力化OSINT工具
4828	安全左移是责任左移吗；漏洞重复出现怎么办 | FB甲方群话题讨论	https://www.freebuf.com/articles/neopoints/394907.html	freebuf	news;观点;	3	2024-03-15	安全左移是责任左移吗；漏洞重复出现怎么办 | FB甲方群话题讨论
5856	Hackers Stolen 70 Million AT&T Sensitive Customers Data	https://gbhackers.com/hackers-stolen-att-data/	GBHacker	news;Cyber Security News;Data Breach;	1	2024-03-18	Hackers盗盗7 000万AT&T敏感客户数据
5855	GBHackers Weekly Round-Up: Cyber Attacks, Vulnerabilities, Threats & New Cyber Stories	https://gbhackers.com/gbhackers-weekly-round-up/	GBHacker	news;Cyber Attack;Cyber Security News;Malware;Vulnerability;	1	2024-03-18	GB Hackers 每周综述:网络攻击、脆弱性、威胁和新网络故事
3080	基于欧盟要求微软不在默认浏览器选择里推荐Edge 此更新适用于全球用户	https://buaq.net/go-228019.html	buaq	newscopy;	0	2024-03-14	基于欧盟要求微软不在默认浏览器选择里推荐Edge 此更新适用于全球用户
11843	运营人员关于零信任现状的梳理	https://xz.aliyun.com/t/14207	阿里先知实验室	news;	1	2024-03-30	运营人员关于零信任现状的梳理
4897	Lazarus Group hackers appear to return to Tornado Cash for money laundering	https://therecord.media/lazarus-group-north-korea-tornado-cash-money-laundering	therecord	ransom;Cybercrime;Nation-state;News;	1	2024-03-15	拉扎鲁斯集团黑客集团的黑客 似乎又回到龙卷风现金银行去洗钱
4751	US moves to recover $2.3 million from 'pig butchers' on Binance	https://www.bleepingcomputer.com/news/cryptocurrency/us-moves-to-recover-23-million-from-pig-butchers-on-binance/	bleepingcomputer	news;CryptoCurrency;Legal;Security;	1	2024-03-15	美国从Binance上的猪肉屠夫那里 追回230万美元
2791	Hackers exploit Windows SmartScreen flaw to drop DarkGate malware	https://buaq.net/go-227972.html	buaq	newscopy;	0	2024-03-14	黑客利用 Windows SmartScreen 瑕疵来降低 DarkGate 恶意软件
10948	[Account Take Over] through reset password token leaked in response, 2500 € Reward	https://infosecwriteups.com/account-take-over-through-reset-password-token-leaked-in-response-2500-reward-b643f97a7c67?source=rss----7b722bfd1b8d---4	infosecwriteups	tech;bug-bounty-hunter;security-research;bug-bounty-tips;bug-bounty;bug-bounty-writeup;	1	2024-03-29	[账户接管]通过重设密码凭证重设 回应漏漏,2500欧元奖励
10096	Insurance Management System PHP And MySQL 1.0 Cross Site Scripting	https://packetstormsecurity.com/files/177775/imsphpmysql10-xss.txt	packetstorm	vuln;;	1	2024-03-26	保险管理系统 PHP 和 MySQL 1.0 跨站点脚本
10097	Red Hat Security Advisory 2024-1502-03	https://packetstormsecurity.com/files/177776/RHSA-2024-1502-03.txt	packetstorm	vuln;;	1	2024-03-26	红色帽子安保咨询2024-1502-03
10378	Red Hat Security Advisory 2024-1454-03	https://packetstormsecurity.com/files/177784/RHSA-2024-1454-03.txt	packetstorm	vuln;;	1	2024-03-27	红色帽子安保咨询 2024-1454-03
2512	派早报：阿里云盘将下线部分功能、Apple 将在国内扩建及新增更多实验室等	https://buaq.net/go-227732.html	buaq	newscopy;	0	2024-03-13	派早报：阿里云盘将下线部分功能、Apple 将在国内扩建及新增更多实验室等
2822	5M WordPress Websites At Risk Amid LiteSpeed Plugin Flaw	https://securityboulevard.com/2024/03/5m-wordpress-websites-at-risk-amid-litespeed-plugin-flaw/	securityboulevard	news;Security Bloggers Network;Cross-Site Scripting (XSS);Cyber Threats;Cybersecurity News;Cybersecurity Vulnerabilities;LiteSpeed Plugin;patch management;Privilege Escalation;Website Acceleration;Website Optimization;Website Security;wordpress security;Wordpress updates;	1	2024-03-14	5M WordPress网站在利特斯拉皮插件中面临风险
3489	Nozomi Networks Secures $100M Investment to Defend Critical Infrastructure	https://www.darkreading.com/ics-ot-security/nozomi-networks-secures-100-million-investment-to-defend-critical-infrastructure	darkreading	news;	1	2024-03-14	诺索米网络确保投资100万美元保护关键基础设施
2971	IT leaders think immutable data storage is an insurance policy against ransomware	https://www.helpnetsecurity.com/2024/03/14/immutable-storage-cybersecurity-strategy/	helpnetsecurity	news;News;cybersecurity;data security;report;Scality;strategy;survey;	2	2024-03-14	IT领导者认为 不可改变的数据存储 是针对赎金软件的保险政策
2760	DarkGPT - An OSINT Assistant Based On GPT-4-200K Designed To Perform Queries On Leaked Databases, Thus Providing An Artificial Intelligence Assistant That Can Be Useful In Your Traditional OSINT Processes	http://www.kitploit.com/2024/03/darkgpt-osint-assistant-based-on-gpt-4.html	kitploit	tool;DarkGPT;Intelligence;Leaked;OSINT;Python;Python3;	1	2024-03-13	DarkGPT - 基于GPT-4-2200K的OSINT助理,设计用于在泄漏数据库上进行查询,从而提供一名人工情报助理,可用于你传统的OSINT程序。
4202	SOC Best Practices You Should Implement	https://securityboulevard.com/2024/03/soc-best-practices-you-should-implement/	securityboulevard	news;Governance, Risk & Compliance;Security Bloggers Network;secops;Security Automation;security operations;SOC;	1	2024-03-14	SOC 你应实施的最佳做法
3887	Not everything has to be a massive, global cyber attack	https://buaq.net/go-228197.html	buaq	newscopy;	0	2024-03-15	并非每件事 都必须是大规模,全球性的网络攻击
3373	英国议会指责政府“鸵鸟策略”应对勒索软件，已对国家造成高风险	https://buaq.net/go-228041.html	buaq	newscopy;	0	2024-03-14	英国议会指责政府“鸵鸟策略”应对勒索软件，已对国家造成高风险
4362	Human risk factors remain outside of cybersecurity pros’ control	https://www.helpnetsecurity.com/2024/03/15/cybersecurity-human-risk-factors/	helpnetsecurity	news;News;artificial intelligence;cybercrime;cybersecurity;Mimecast;report;survey;	1	2024-03-15	人类风险因素仍不受网络安全促进者控制
4704	Hackers Claim 740GB of Data Stolen from Viber VOIP Platform	https://gbhackers.com/hackers-claim-of-data-stolen/	GBHacker	news;Cyber Security News;Data Breach;	1	2024-03-15	Hackers索赔740GB号数据被盗自Viber VOIP平台的数据
5865	Doing 50 Things with RTL-SDR in One Week	https://buaq.net/go-228706.html	buaq	newscopy;	0	2024-03-18	在一周内与RTL-SDR做50件事情
4705	Hackers Exploit Windows SmartScreen Vulnerability to Install DarkGate Malware	https://gbhackers.com/hackers-exploit-windows-smartscreen/	GBHacker	news;cyber security;Cyber Security News;Windows;Vulnerability;	1	2024-03-15	用于安装 DarkGate 磁碟的黑客开发窗口智能缩写脆弱性
4862	Webenlive - Blind Sql Injection	https://cxsecurity.com/issue/WLB-2024030034	cxsecurity	vuln;	1	2024-03-16	Webenlive - 盲人 Sql 注射
5869	2023年我国APT攻击威胁态势观察：受攻击态势呈饱和式状态	https://buaq.net/go-228711.html	buaq	newscopy;	0	2024-03-18	2023年我国APT攻击威胁态势观察：受攻击态势呈饱和式状态
4865	HALO-2.13.1 Cross-origin resource sharing: arbitrary origin trusted	https://cxsecurity.com/issue/WLB-2024030033	cxsecurity	vuln;	1	2024-03-16	HALO-2.13.1 跨来源资源分享:可信赖的任意来源
10100	Ubuntu Security Notice USN-6714-1	https://packetstormsecurity.com/files/177779/USN-6714-1.txt	packetstorm	vuln;;	1	2024-03-26	Ubuntu Ubuntu 安全通知 USN-6714-1
10101	Ubuntu Security Notice USN-6716-1	https://packetstormsecurity.com/files/177780/USN-6716-1.txt	packetstorm	vuln;;	1	2024-03-26	Ubuntu Ubuntu 安全通知 USN-6716-1
3785	Red Hat Security Advisory 2024-1308-03	https://packetstormsecurity.com/files/177583/RHSA-2024-1308-03.txt	packetstorm	vuln;;	1	2024-03-14	红帽子安保咨询2024-13008-03
10389	Red Hat Security Advisory 2024-1530-03	https://packetstormsecurity.com/files/177795/RHSA-2024-1530-03.txt	packetstorm	vuln;;	1	2024-03-27	红色帽子安保咨询2024-1530-03
10395	WordPress Bricks Builder Theme 1.9.6 Remote Code Execution	https://packetstormsecurity.com/files/177801/wp_bricks_builder_rce.rb.txt	packetstorm	vuln;;	1	2024-03-27	Wordpress Bricks 构建器主题 1.9.6 远程代码执行
10103	Ubuntu Security Notice USN-6588-2	https://packetstormsecurity.com/files/177782/USN-6588-2.txt	packetstorm	vuln;;	1	2024-03-26	Ubuntu Ubuntu 安全通知 USN-6588-2
10104	Ubuntu Security Notice USN-6717-1	https://packetstormsecurity.com/files/177783/USN-6717-1.txt	packetstorm	vuln;;	1	2024-03-26	Ubuntu Ubuntu 安全通知 USN-6717-1
4895	Ubuntu Security Notice USN-6694-1	https://packetstormsecurity.com/files/177622/USN-6694-1.txt	packetstorm	vuln;;	1	2024-03-15	Ubuntu Ubuntu 安全通知 USN6694-1
4447	Malicious Ads Targeting Chinese Users with Fake Notepad++ and VNote Installers	https://thehackernews.com/2024/03/malicious-ads-targeting-chinese-users.html	feedburner	news;	4	2024-03-15	使用假笔记和 VNote 安装器瞄准中国用户
10102	Bludit 3.13.0 Cross Site Scripting	https://packetstormsecurity.com/files/177781/bludit3130-xss.txt	packetstorm	vuln;;	1	2024-03-26	3.13.0 跨站点脚本
5867	3·15曝光 | 主板机黑灰产业链揭秘，网络水军利用IP变更逃避监管	https://buaq.net/go-228709.html	buaq	newscopy;	0	2024-03-18	3·15曝光 | 主板机黑灰产业链揭秘，网络水军利用IP变更逃避监管
5864	Android 15将推出基于Google Play的应用归档功能 删除保留数据重装直接用	https://buaq.net/go-228698.html	buaq	newscopy;	0	2024-03-18	Android 15将推出基于Google Play的应用归档功能 删除保留数据重装直接用
5868	ChatGPT vs Gemini：谁在网络安全运营中更好用？	https://buaq.net/go-228710.html	buaq	newscopy;	0	2024-03-18	ChatGPT vs Gemini：谁在网络安全运营中更好用？
4893	Financials By Coda Authorization Bypass	https://packetstormsecurity.com/files/177620/financialsbycoda-bypass.txt	packetstorm	vuln;;	1	2024-03-15	以 Coda 授权的密钥
10122	Hackers Claiming that EagleSpy Android RAT 3.0 Steals 2FA Google Authenticator Code	https://gbhackers.com/hackers-claiming-eaglespy-android/	GBHacker	news;Android;Cyber Security News;Google;computer security;	2	2024-03-26	Hackers声称EagleSpy Android RAT 3.0 窃取2FA谷歌认证码
10124	New Tycoon 2FA Phishing Kit Attacking Microsoft 365 & Gmail Users	https://gbhackers.com/tycoon-2fa-phishing-kit/	GBHacker	news;Cyber Security News;Email Security;Phishing;2FA;Cybersecurity Threats;Phishing Security;	1	2024-03-26	微软365365和Gmail用户
10125	Microsoft Releases Out-of-band Update to Fix Windows Server Memory Leak Flaw	https://gbhackers.com/windows-server-memory-leak/	GBHacker	news;Cyber Security News;Microsoft;cyber security;Vulnerability;	1	2024-03-26	微软发布带外更新到修补 Windows 服务器内存泄漏法
4810	bergmeistereu	http://www.ransomfeed.it/index.php?page=post_details&id_post=13755	ransomfeed	ransom;lockbit3;	1	2024-03-16	贝格梅斯特
10127	ASEAN Entities in the Spotlight: Chinese APT Group Targeting	https://buaq.net/go-230668.html	buaq	newscopy;	0	2024-03-27	处于焦点的东盟实体:中国防止酷刑小组
4753	Microsoft announces Office LTSC 2024 preview starting next month	https://www.bleepingcomputer.com/news/microsoft/microsoft-announces-office-ltsc-2024-preview-starting-next-month/	bleepingcomputer	news;Microsoft;	1	2024-03-15	微软宣布办公室 LTSC 2024 预览从下个月开始
5870	网传 AT&T 泄露 7100 万用户数据，该公司多次否认	https://buaq.net/go-228712.html	buaq	newscopy;	0	2024-03-18	网传 AT&T 泄露 7100 万用户数据，该公司多次否认
4859	Hack The Box: Manager Machine Walkthrough – Medium Difficulty	https://threatninja.net/2024/03/hack-the-box-manager-machine-walkthrough-medium-difficulty/	threatninja	sectest;Medium Machine;Certify;Challenges;crackmapexec;evil-winrm;HackTheBox;ManageCA vulnerability;MSSQL;mssqlclient;NetExec;Penetration Testing;smb;Windows;	1	2024-03-16	Hack 盒子:经理机器走过 - 中度困难
10107	Ransomware gang attacks the Big Issue, a street newspaper supporting the homeless	https://therecord.media/ransomware-gang-attacks-big-issue-street-paper	therecord	ransom;News;Cybercrime;	2	2024-03-26	支持无家可归者的街头报纸《大问题》,
10399	India's government, energy sector breached in cyber-espionage campaign	https://therecord.media/india-infostealer-government-energy-sector-espionage	therecord	ransom;Nation-state;Malware;News;Government;	1	2024-03-27	印度政府的能源部门在网络防御运动中 被破坏
10110	AutoWLAN - Run A Portable Access Point On A Raspberry Pi Making Use Of Docker Containers	http://www.kitploit.com/2024/03/autowlan-run-portable-access-point-on.html	kitploit	tool;AutoWLAN;Management;Wep;WPA2;	1	2024-03-26	AutoWLAN - 运行一个使用箱式容器的草莓皮的便携式接入点
13534	简析数据安全保护策略中的10个核心要素	https://buaq.net/go-231607.html	buaq	newscopy;	0	2024-04-02	简析数据安全保护策略中的10个核心要素
13535	审计师眼中的API安全与风险控制	https://buaq.net/go-231608.html	buaq	newscopy;	0	2024-04-02	审计师眼中的API安全与风险控制
13536	EM Eye: Eavesdropping on Security Camera via Unintentional RF Emissions	https://buaq.net/go-231636.html	buaq	newscopy;	0	2024-04-02	EEM Eye:通过无意RF排放量监听安保摄像头
13537	PhantomSDR: WebSDR Software for the RX888 MKII	https://buaq.net/go-231637.html	buaq	newscopy;	0	2024-04-02	幻影SDR:RX888 MKIIWEWSDR软件
10118	CISA Warns Of Active Exploitation Of Flaws In Fortinet, Ivanti, & Nice Linear	https://gbhackers.com/cisa-warns-of-active-exploitation/	GBHacker	news;CVE/vulnerability;Cyber Attack;Cyber Security News;Exploit;Cybersecurity Vulnerabilities;Exploit Prevention;	1	2024-03-26	Ivanti、Nice Linear等Fortinet、Ivanti和Nice Linear中主动利用法律的战争
10106	Florida enacts tough social media law barring children under 14 from holding accounts	https://therecord.media/florida-enacts-social-media-law-bars-minors	therecord	ransom;News;Government;Technology;Privacy;	1	2024-03-26	佛罗里达州颁布了严厉的社会媒体法,禁止14岁以下儿童持有账户
65	Blog: Why Hackers Love Phones – Keep your Eye on the Device	https://securityboulevard.com/2024/03/blog-why-hackers-love-phones-keep-your-eye-on-the-device/	securityboulevard	news;Mobile Security;Security Bloggers Network;API security;API Security - Analysis, News and Insights;Mobile App Authentication;	1	2024-03-12	博客:为什么黑客爱电话 — — 关注设备
10109	UK counter-eavesdropping agency gets slap on the wrist for eavesdropping	https://therecord.media/uk-nace-unlawful-surveillance-journalistic-source	therecord	ransom;Government;News;Privacy;	1	2024-03-26	英国反窃听机构 被拍打手腕 偷听
10108	Thousands of companies using Ray framework exposed to cyberattacks, researchers say	https://therecord.media/thousands-exposed-to-ray-framework-vulnerability	therecord	ransom;Cybercrime;Technology;	1	2024-03-26	研究者说,数千家公司使用雷光框架受到网络攻击,
5684	Harnessing the power of privacy-enhancing tech for safer AI adoption	https://www.helpnetsecurity.com/2024/03/18/privacy-enhancing-technologies-pets-video/	helpnetsecurity	news;Don't miss;Hot stuff;Video;artificial intelligence;cybersecurity;data;Enveil;framework;machine learning;privacy;regulation;video;	1	2024-03-18	利用增强隐私技术的力量促进采用更安全的人工智能
10117	CISA & FBI Warns that Hackers Use SQL Injection Vulnerabilities to hack Servers	https://gbhackers.com/cisa-fbi-warns-sql-injection/	GBHacker	news;CVE/vulnerability;cyber security;Cyber Security News;Hacks;Vulnerability;	1	2024-03-26	CISA 和 FBI 警告, 黑客使用 SQL 喷射脆弱性黑入服务器
10119	CrowdStrike Partnered with HCLTech to Drive Enterprise Cybersecurity Transformation	https://gbhackers.com/crowdstrike-partnered-hcltech/	GBHacker	news;cyber security;Cyber Security News;computer security;	1	2024-03-26	推动企业网络安全转型
9927	Hackers Transform the Raspberry Pi into an Online Anonymity Tool	https://gbhackers.com/hackers-transform-the-raspberry-pi-into-an-online-anonymity-tool/	GBHacker	news;Cyber Attack;Cyber Crime;cyber security;computer security;Cyber Security News;	1	2024-03-25	黑客将草莓皮转换成在线匿名工具
10120	Giant Tiger Data Breach: Customers Data Exposed Via Vendor	https://gbhackers.com/giant-tiger-data-breach/	GBHacker	news;cyber security;Cyber Security News;Data Breach;	1	2024-03-26	巨老虎数据突破:客户数据暴露于Via供应商
10121	What is Global Threat Intelligence? – SOC/DFIR Team Guide	https://gbhackers.com/global-threat-intelligence/	GBHacker	news;THREATS;Uncategorized;	1	2024-03-26	- 全球威胁情报是什么? - SOC/DFIR小组指南
68	GUEST ESSAY: A DIY guide to recognizing – and derailing –  Generative AI voice scams	https://securityboulevard.com/2024/03/guest-essay-a-diy-guide-to-recognizing-and-derailing-generative-ai-voice-scams/	securityboulevard	news;SBN News;Security Bloggers Network;Best Practices;essays;Privacy;Top Stories;	1	2024-03-11	识别 — — 和脱轨 — — 创生的AI语音骗术的DIY指南
9764	Hackers Hijack GitHub Accounts in Supply Chain Attack Affecting Top-gg and Others	https://thehackernews.com/2024/03/hackers-hijack-github-accounts-in.html	feedburner	news;	1	2024-03-25	Hackers Hackers Hackers Hickers 劫吉特Hub账户 " 供应链对顶顶顶顶顶顶顶打击 " 中的供应链打击 " 账户和其他账户
9782	The Show Must Go On	https://securityboulevard.com/2024/03/the-show-must-go-on/	securityboulevard	news;Security Bloggers Network;Features;Liquidmatrix;	1	2024-03-25	演出必须继续下去
10410	Chinese Hackers Attacking Southeast Asian Nations With Malware Packages	https://gbhackers.com/chinese-apt-hackers-attacking/	GBHacker	news;Cyber Attack;Cyber Security News;	4	2024-03-27	中国黑客用恶意软件包袭击东南亚国家
9767	Key Lesson from Microsoft’s Password Spray Hack: Secure Every Account	https://thehackernews.com/2024/03/key-lesson-from-microsofts-password.html	feedburner	news;	1	2024-03-25	微软密码喷雾 Hack 的密钥课程: 安全每个账户
3849	The water industry wants to write its own cybersecurity rules. Will Biden and Congress go for it?	https://therecord.media/water-industry-wants-to-write-its-own-cyber-rules	therecord	ransom;Cybercrime;Government;Industry;News;	1	2024-03-14	水产业希望自己制定网络安全规则。 拜登和国会会同意吗?
9766	Iran-Linked MuddyWater Deploys Atera for Surveillance in Phishing Attacks	https://thehackernews.com/2024/03/iran-linked-muddywater-deploys-atera.html	feedburner	news;	3	2024-03-25	用于监视钓鱼袭击的伊朗与伊朗联系的泥水水部署
9777	Constella and Social Links Join Forces to Deliver Transformative OSINT Solutions	https://securityboulevard.com/2024/03/constella-and-social-links-join-forces-to-deliver-transformative-osint-solutions/	securityboulevard	news;Press Releases;Security Bloggers Network;	1	2024-03-25	Constella与社会联系联合力量,以交付变革性OSINT解决方案
9778	Cybersecurity in Financial Disclosures: 11 Topics Your Section 1C of 10-K Filings Should Address	https://securityboulevard.com/2024/03/cybersecurity-in-financial-disclosures-11-topics-your-section-1c-of-10-k-filings-should-address/	securityboulevard	news;Security Bloggers Network;Blog Posts;Regulation Updates;	1	2024-03-25	财务披露的网络安全:11个主题:你关于10K申报应处理的第1C节
9775	AI Regulation at a Crossroads	https://securityboulevard.com/2024/03/ai-regulation-at-a-crossroads/	securityboulevard	news;Security Bloggers Network;Cybersecurity Institute;	1	2024-03-25	在十字路口的AIA条例
14427	Why risk management is key for Oracle ERP Cloud Success 	https://securityboulevard.com/2024/04/why-risk-management-is-key-for-oracle-erp-cloud-success/	securityboulevard	news;Security Bloggers Network;articles;Oracle ERP Cloud;Policy-based Access Control;	1	2024-04-02	为何风险管理是甲骨文机构资源规划云云成功的关键
12244	Microsoft Beefs Up Defenses in Azure AI	https://www.darkreading.com/application-security/microsoft-adds-tools-for-protecting-against-prompt-injection-other-threats-in-azure-ai	darkreading	news;	1	2024-04-01	Azure AI 中的微软牛肉
9779	How to Get the Most From Your Secrets Scanning	https://securityboulevard.com/2024/03/how-to-get-the-most-from-your-secrets-scanning/	securityboulevard	news;Security Bloggers Network;AppSec;Best Practices;Legit;threats;	1	2024-03-25	如何从你的秘密扫描中 获取最伟大的信息
3845	FCC adopts voluntary 'Cyber Trust Mark' labeling rule for IoT devices	https://therecord.media/cyber-trust-mark-internet-of-things-devices-fcc-approval	therecord	ransom;Industry;Technology;Government;News;	1	2024-03-14	FCC 对 IoT 设备采用自愿的“ Cyber Trust Mark ” 标签规则
10126	CanSecWest 2024 - Glitching in 3D: Low Cost EMFI Attacks	https://buaq.net/go-230667.html	buaq	newscopy;	0	2024-03-27	2024年西Canse West 2024 - 3D中滑入:低成本的EMFI袭击
9780	Log Formatting Best Practices for Improved Security	https://securityboulevard.com/2024/03/log-formatting-best-practices-for-improved-security/	securityboulevard	news;Governance, Risk & Compliance;Security Bloggers Network;Blog;security log management;security operations;	1	2024-03-25	改进安保最佳做法的记录格式化
9770	New 'GoFetch' Vulnerability in Apple M-Series Chips Leaks Secret Encryption Keys	https://thehackernews.com/2024/03/new-gofetch-vulnerability-in-apple-m.html	feedburner	news;	1	2024-03-25	苹果 M- 系列芯片泄漏中的新“ GoFetch” 脆弱性
12247	Name That Edge Toon: Defying Gravity	https://www.darkreading.com/cloud-security/name-that-edge-toon-defying-gravity	darkreading	news;	1	2024-04-01	名称: 顶撞重力
9774	填补盾牌的裂缝：堆分配器中的MTE	https://paper.seebug.org/3134/	seebug	news;经验心得;	1	2024-03-25	填补盾牌的裂缝：堆分配器中的MTE
12780	Why AI forensics matters now	https://www.helpnetsecurity.com/2024/04/02/ai-forensics-video/	helpnetsecurity	news;Don't miss;Hot stuff;Video;artificial intelligence;automation;Credo;cybersecurity;data;Generative AI;investment;Qualcomm;regulation;video;	1	2024-04-02	为什么大赦国际的法证现在很重要
26194	华为时尚盛典 	https://s.weibo.com/weibo?q=%23华为时尚盛典 %23	sina.weibo	hotsearch;weibo	1	2024-02-22	华为时尚盛典
26196	华为校招	https://s.weibo.com/weibo?q=%23华为校招%23	sina.weibo	hotsearch;weibo	1	2023-11-29	华为校招
26197	华为汽车 	https://s.weibo.com/weibo?q=%23华为汽车 %23	sina.weibo	hotsearch;weibo	1	2023-12-29	华为汽车
26199	华为相关人士辟谣P70预售时间和售价 	https://s.weibo.com/weibo?q=%23华为相关人士辟谣P70预售时间和售价 %23	sina.weibo	hotsearch;weibo	1	2024-03-22	华为相关人士辟谣P70预售时间和售价
5682	43 million workers potentially affected in France Travail data breach	https://www.helpnetsecurity.com/2024/03/18/france-travail-data-breach/	helpnetsecurity	news;Don't miss;Hot stuff;News;data breach;data theft;EU;France;government;	1	2024-03-18	4 300万工人有可能在法国受到影响
5610	South African Government Pension Data Leak Fears Spark Probe	https://www.darkreading.com/cyberattacks-data-breaches/south-african-government-pension-data-leak-fears-spark-probe	darkreading	news;	1	2024-03-18	南非政府养恤金数据泄漏恐惧Spark Probe
5683	The dark side of GenAI	https://www.helpnetsecurity.com/2024/03/18/genai-dark-side-video/	helpnetsecurity	news;Video;cybersecurity;Fortra;Generative AI;SECURITI.ai;Sonatype;	1	2024-03-18	GenAI的阴暗面
9788	CISA urges software devs to weed out SQL injection vulnerabilities	https://www.bleepingcomputer.com/news/security/cisa-urges-software-devs-to-weed-out-sql-injection-vulnerabilities/	bleepingcomputer	news;Security;Software;	1	2024-03-25	CISA敦促软件商剔除 SQL 注射易感染性
5681	Public anxiety mounts over critical infrastructure resilience to cyber attacks	https://www.helpnetsecurity.com/2024/03/18/critical-infrastructure-cyberattacks-risk/	helpnetsecurity	news;News;critical infrastructure;cybersecurity;government;MITRE;report;risk;survey;The Harris Poll;	1	2024-03-18	公众对于关键基础设施抵御网络攻击的能力日益焦虑
5658	RSHP	http://www.ransomfeed.it/index.php?page=post_details&id_post=13771	ransomfeed	ransom;8base;	1	2024-03-18	RSHP RSHP RSHP RSHP RSHP RSHP RSHP RSHP RSHP RSHP RSHP RSHP RSHP RSHP RSHP RSHP RSHP RSHP RSHP RSHP RSHP
5657	crineticscom	http://www.ransomfeed.it/index.php?page=post_details&id_post=13770	ransomfeed	ransom;lockbit3;	1	2024-03-18	列列曲
5672	聚焦315：操控网络水军的主板机；AI”换脸“诈骗	https://www.freebuf.com/news/395065.html	freebuf	news;资讯;	1	2024-03-18	聚焦315：操控网络水军的主板机；AI”换脸“诈骗
9790	New MFA-bypassing phishing kit targets Microsoft 365, Gmail accounts	https://www.bleepingcomputer.com/news/security/new-mfa-bypassing-phishing-kit-targets-microsoft-365-gmail-accounts/	bleepingcomputer	news;Security;	1	2024-03-25	MAFA新通过邮管局的钓鱼资料袋瞄准微软365Gmail账户。
9786	US fines man $9.9 million for thousands of disturbing robocalls	https://www.bleepingcomputer.com/news/legal/us-fines-man-99-million-for-thousands-of-disturbing-robocalls/	bleepingcomputer	news;Legal;	1	2024-03-25	美国罚款 人990万美元 对于成千上万 令人不安的抢劫
5671	谷歌升级 Safe Browsing，为用户增强实时 URL 保护	https://www.freebuf.com/news/395061.html	freebuf	news;资讯;	1	2024-03-18	谷歌升级 Safe Browsing，为用户增强实时 URL 保护
5611	3 Ways Businesses Can Overcome the Cybersecurity Skills Shortage	https://www.darkreading.com/cybersecurity-operations/3-ways-businesses-can-overcome-cybersecurity-skills-shortage	darkreading	news;	1	2024-03-18	3 企业如何克服网络安全技能短缺问题
9789	Hackers poison source code from largest Discord bot platform	https://www.bleepingcomputer.com/news/security/hackers-poison-source-code-from-largest-discord-bot-platform/	bleepingcomputer	news;Security;	1	2024-03-25	来自最大Discoord 机器人平台的黑客毒源代码
10425	USENIX Security ’23 – Automata-Guided Control-Flow-Sensitive Fuzz Driver Generation	https://buaq.net/go-230927.html	buaq	newscopy;	0	2024-03-28	USENIX 安全 23 — — 自动马塔制导控制 — — 敏敏度低的引信驱动器生成
10429	Attacchi nel Sud-Est asiatico: gruppi cinesi APT sotto accusa	https://buaq.net/go-230933.html	buaq	newscopy;	0	2024-03-28	Attacchi Nel Sud-Est asiatico: 强奸罪
5674	网传 AT&T 泄露 7100 万用户数据，该公司多次否认	https://www.freebuf.com/news/395109.html	freebuf	news;资讯;	1	2024-03-18	网传 AT&T 泄露 7100 万用户数据，该公司多次否认
9792	Over 100 US and EU orgs targeted in StrelaStealer malware attacks	https://www.bleepingcomputer.com/news/security/over-100-us-and-eu-orgs-targeted-in-strelastealer-malware-attacks/	bleepingcomputer	news;Security;	1	2024-03-24	Streela Stealer恶意软件袭击中针对的100多个美国和欧盟大兽
20547	Sectigo appoints Jason Scott as CISO	https://www.helpnetsecurity.com/2024/04/09/sectigo-jason-scott-ciso/	helpnetsecurity	news;Industry news;Sectigo;	1	2024-04-09	部门任命杰森·斯科特为中央情报厅
20570	French football club PSG says ticketing system targeted by cyberattack	https://therecord.media/paris-saint-germain-cyberattack-ticketing-system	therecord	ransom;Cybercrime;News;News Briefs;	1	2024-04-09	法国足球俱乐部PSG说,
20571	Computer accessory giant Targus says cyberattack interrupting business operations	https://therecord.media/targus-cyberattack-operations-disrupted	therecord	ransom;Industry;Cybercrime;News;News Briefs;	1	2024-04-09	电脑从属巨头Targus说 网络攻击干扰了商业业务
5673	麦当劳全球系统宕机，影响数千家门店	https://www.freebuf.com/news/395076.html	freebuf	news;资讯;	1	2024-03-18	麦当劳全球系统宕机，影响数千家门店
9783	Top 4 Industries at Risk of Credential Stuffing  and Account Takeover (ATO) attacks	https://securityboulevard.com/2024/03/top-4-industries-at-risk-of-credential-stuffing-and-account-takeover-ato-attacks/	securityboulevard	news;Security Bloggers Network;API security;	1	2024-03-25	面临持证和账户接管(ATO)攻击风险的4大行业
5663	SRC挖掘实战 | JS中能利用的那些信息	https://www.freebuf.com/articles/web/394873.html	freebuf	news;Web安全;	1	2024-03-15	SRC挖掘实战 | JS中能利用的那些信息
9785	Google's new AI search results promotes sites pushing malware, scams	https://www.bleepingcomputer.com/news/google/googles-new-ai-search-results-promotes-sites-pushing-malware-scams/	bleepingcomputer	news;Google;Software;	1	2024-03-25	Google的新人工智能搜索结果促进网站推出恶意软件、诈骗
5659	Romark-Laboratories-	http://www.ransomfeed.it/index.php?page=post_details&id_post=13772	ransomfeed	ransom;medusa;	1	2024-03-18	罗姆克-劳改所
9793	Panera Bread experiencing nationwide IT outage since Saturday	https://www.bleepingcomputer.com/news/security/panera-bread-experiencing-nationwide-it-outage-since-saturday/	bleepingcomputer	news;Security;	1	2024-03-25	自星期六以来,全国范围经历了信息技术中断的面包面包
3899	NAV Revolutionizes DeFi Investing with Regulatory-Compliant Structured Investment Products	https://buaq.net/go-228226.html	buaq	newscopy;	0	2024-03-15	NAV 以监管和综合结构化投资产品使“非金融投资”革命化
169	FreeBuf 早报 | 新的xStealer恶意软件首次亮相；英国政府针对勒索软件防范失职	https://www.freebuf.com/news/393993.html	freebuf	news;资讯;	2	2024-03-11	FreeBuf 早报 | 新的xStealer恶意软件首次亮相；英国政府针对勒索软件防范失职
119	4 Security Tips From PCI DSS 4.0 Anyone Can Use	https://www.darkreading.com/cybersecurity-operations/pci-dss-4-0-is-good-security-guidance-for-everyone	darkreading	news;	1	2024-03-11	4个安全提示,来自PCI DSS 4.0 任何人都可以使用
13539	黑客利用 WordPress 插件缺陷感染了 3300 个网站	https://buaq.net/go-231645.html	buaq	newscopy;	0	2024-04-02	黑客利用 WordPress 插件缺陷感染了 3300 个网站
9796	It's not just you: ChatGPT is down for many worldwide	https://www.bleepingcomputer.com/news/technology/its-not-just-you-chatgpt-is-down-for-many-worldwide/	bleepingcomputer	news;Technology;Software;	1	2024-03-25	不只是你一个人 全世界很多人都在聊天
352	Petrol Pump Management Software v1.0 Remote Code Execution via File Upload	https://cxsecurity.com/issue/WLB-2024030004	cxsecurity	vuln;	1	2024-03-03	汽油泵管理软件 v1.0 通过文件上传远程代码执行
9798	GitHub Developers Hit in Complex Supply Chain Cyberattack	https://www.darkreading.com/application-security/github-developers-hit-in-complex-supply-chain-cyberattack	darkreading	news;	1	2024-03-25	GitHub开发商在复杂供应链网络攻击中受到打击
174	Cynerio extends Healthcare Cybersecurity Platform to improve patient data protections	https://www.helpnetsecurity.com/2024/03/11/cynerio-healthcare-cybersecurity-platform/	helpnetsecurity	news;Industry news;Cynerio;	1	2024-03-11	Cynerio扩大保健网络安全平台,改善患者数据保护
9794	US sanctions APT31 hackers behind critical infrastructure attacks	https://www.bleepingcomputer.com/news/security/us-sanctions-apt31-hackers-behind-critical-infrastructure-attacks/	bleepingcomputer	news;Security;	2	2024-03-25	美国制裁 APT31 重大基础设施袭击背后的黑客
4934	USENIX Security ’23 – Tanusree Sharma, Zhixuan Zhou, Andrew Miller, Yang Wang – A Mixed-Methods Study Of Security Practices Of Smart Contract Developers	https://buaq.net/go-228660.html	buaq	newscopy;	0	2024-03-17	USENIX 安全 23 — — 塔努斯里·夏尔马、周志泉、安德鲁·米勒、杨王 — — 智能合同开发商安全做法混合方法研究
312	Blue Team toolkit: 6 open-source tools to assess and enhance corporate defenses	https://www.welivesecurity.com/en/business-security/blue-team-toolkit-6-open-source-tools-corporate-defenses/	eset	news;	1	2024-02-29	蓝小组工具包:6个用于评估和加强公司防御的开放源码工具
9801	Chinese State-Sponsored Hackers Charged, Sanctions Levied by US	https://www.darkreading.com/cyber-risk/chinese-state-hackers-slapped-with-us-charges-sanctions	darkreading	news;	4	2024-03-25	中国国务院负责的黑客(Hackers)被美国指控受制裁
9805	CISA Seeks to Curtail 'Unforgivable' SQL Injection Defects	https://www.darkreading.com/cyberattacks-data-breaches/cisa-seeks-to-stem-unforgivable-sql-injection-defects	darkreading	news;	1	2024-03-25	CISA 寻求缩小“不可原谅的” SQL 注射缺陷
9808	UN Adopts Resolution for 'Secure, Trustworthy' AI	https://www.darkreading.com/cybersecurity-operations/un-adopts-symbolic-resolution-secure-trustworthy-ai	darkreading	news;	1	2024-03-25	联合国通过关于“安全、可信赖”的AI号决议
118	Japan on Line Breach: Clean Up Post-Merger Tech Sprawl	https://www.darkreading.com/cybersecurity-operations/japan-line-breach-clean-up-post-merger-tech-sprawl	darkreading	news;	1	2024-03-06	日本在一线突破线上的突破:清除后机器人技术扩散
10129	$700 cybercrime software turns Raspberry Pi into an evasive fraud tool	https://buaq.net/go-230670.html	buaq	newscopy;	0	2024-03-27	700美元 网络犯罪软件将Raspberry Pi 变成一个逃避欺诈的工具
10130	SourceCodester PHP Task Management System 1.0 (admin-manage-user.php) - SQL Injection	https://buaq.net/go-230674.html	buaq	newscopy;	0	2024-03-27	PHP 任务管理系统1.0(管理管理-用户.php) - SQL 注射
10131	Bludit 3.13.0 Cross Site Scripting	https://buaq.net/go-230675.html	buaq	newscopy;	0	2024-03-27	3.13.0 跨站点脚本
12379	xz-utils 后门漏洞 CVE-2024-3094 分析	https://paper.seebug.org/3139/	seebug	news;漏洞分析;	5	2024-04-02	xz-utils 后门漏洞 CVE-2024-3094 分析
10132	MobileShop master - SQL Injection Vuln.	https://buaq.net/go-230676.html	buaq	newscopy;	0	2024-03-27	手机Shop大师 SQL 注射Vuln。
10133	ORANGE STATION-1.0 File Upload Remote Code Execution Vulnerability	https://buaq.net/go-230677.html	buaq	newscopy;	0	2024-03-27	OANGE Statation-1.0 文件上传远程代码执行脆弱性
10134	Insurance Management System PHP And MySQL 1.0 Cross Site Scripting	https://buaq.net/go-230678.html	buaq	newscopy;	0	2024-03-27	保险管理系统 PHP 和 MySQL 1.0 跨站点脚本
10431	Fugitive US Militant Ammon Bundy Geolocated to Utah	https://buaq.net/go-230935.html	buaq	newscopy;	0	2024-03-28	美国逃逃兵Ammon Bundy 地处犹他州
10135	LimeSurvey Community 5.3.32 Cross Site Scripting	https://buaq.net/go-230679.html	buaq	newscopy;	0	2024-03-27	5.3.32 跨站点脚本
10436	Taking the Azure Open AI Challenge: Image Generation - Day 2	https://buaq.net/go-230940.html	buaq	newscopy;	0	2024-03-28	接受Azure公开的AI挑战:图像生成-第2天
10136	TheMoon bot infected 40,000 devices in January and February	https://buaq.net/go-230680.html	buaq	newscopy;	0	2024-03-27	1月和2月,Moon机器人感染了40 000个装置
13538	尽快提交！2024网络安全产业图谱调研进入收尾阶段	https://buaq.net/go-231644.html	buaq	newscopy;	0	2024-04-02	尽快提交！2024网络安全产业图谱调研进入收尾阶段
9800	A Database-Oriented Operating System Wants to Shake Up Cloud Security	https://www.darkreading.com/cloud-security/can-a-database-oriented-operating-system-make-the-cloud-more-secure	darkreading	news;	1	2024-03-25	数据库导向操作系统想要摇云安全
8229	DS Cloud – 群晖融合怪：第三方群晖 NAS 客户端，视频播放、音乐播放、文件管理[iPhone、iPad]	https://buaq.net/go-228737.html	buaq	newscopy;	0	2024-03-18	DS Cloud – 群晖融合怪：第三方群晖 NAS 客户端，视频播放、音乐播放、文件管理[iPhone、iPad]
8244	Microsoft Teams Notifications Integration	https://securityboulevard.com/2024/03/microsoft-teams-notifications-integration/	securityboulevard	news;Security Bloggers Network;Product updates;Software Release;	1	2024-03-18	微软团队通知整合
8245	Randall Munroe’s XKCD ‘Earth’	https://securityboulevard.com/2024/03/randall-munroes-xkcd-earth/	securityboulevard	news;Humor;Security Bloggers Network;Randall Munroe;Sarcasm;satire;XKCD;	1	2024-03-18	Randall Munroe的 XKCD “地球”
8233	Fortra Patches Critical RCE Vulnerability in FileCatalyst Transfer Tool	https://thehackernews.com/2024/03/fortra-patches-critical-rce.html	feedburner	news;	1	2024-03-18	FileCatalyst 传输工具中的 CRCE 关键脆弱性
6315	Fujitsu Hacked – Attackers Infected The  Company Computers with Malware	https://gbhackers.com/fujitsu-hacked/	GBHacker	news;Data Breach;Hacks;Malware;Cyber Attack;Cyber Security News;	1	2024-03-18	Fujitsu Hacked — — 攻击者感染了麦华公司计算机公司
8246	SOPS [Security Zines]	https://securityboulevard.com/2024/03/sops-security-zines/	securityboulevard	news;Security Bloggers Network;Security Zines;	1	2024-03-18	SOPS [保安区]
8248	The Secret to Optimizing Enterprise Data Detection & Response	https://securityboulevard.com/2024/03/the-secret-to-optimizing-enterprise-data-detection-response/	securityboulevard	news;Security Bloggers Network;Webinars & Videos;	1	2024-03-18	优化企业数据检测和反应的秘密
8237	Hackers Using Sneaky HTML Smuggling to Deliver Malware via Fake Google Sites	https://thehackernews.com/2024/03/hackers-using-sneaky-html-smuggling-to.html	feedburner	news;	1	2024-03-18	利用Sneaky HTML走私通过假谷歌网站运送Malware的黑客
8239	New DEEP#GOSU Malware Campaign Targets Windows Users with Advanced Tactics	https://thehackernews.com/2024/03/new-deepgosu-malware-campaign-targets.html	feedburner	news;	1	2024-03-18	新建的EEP# GOSU 恶意运动目标窗口用户
8345	How to Spot, and Prevent, the Tax Scams That Target Elders	https://www.mcafee.com/blogs/privacy-identity-protection/how-to-spot-and-prevent-the-tax-scams-that-target-elders/	mcafee	news;Tips & Tricks;Privacy & Identity Protection;tax scams;tax refund;	1	2024-03-18	如何发现和预防针对老年人的税收飞弹
8247	SubdoMailing and the Rise of Subdomain Phishing	https://securityboulevard.com/2024/03/subdomailing-and-the-rise-of-subdomain-phishing/	securityboulevard	news;Security Bloggers Network;Cybersecurity;	1	2024-03-18	子买卖和子买卖钓鱼的兴起
8342	Nissan breach exposed data of 100,000 individuals	https://www.helpnetsecurity.com/2024/03/18/nissan-data-breach/	helpnetsecurity	news;Don't miss;Hot stuff;News;Australia;data breach;data theft;manufacturing sector;ransomware;	1	2024-03-18	违反日产破尼桑事件暴露的100 000人数据
3471	How to Identify a Cyber Adversary: What to Look For	https://www.darkreading.com/cyberattacks-data-breaches/how-to-identify-cyber-adversary-what-to-look-for	darkreading	news;	1	2024-03-14	如何识别网络逆向:寻找什么
2768	ChatGPT-Next-Web SSRF Bug Let Hackers Gain Full Access to HTTP Endpoints	https://gbhackers.com/chatgpt-next-web-ssrf-vulnerability/	GBHacker	news;Cyber Attack;cyber security;Cyber Security News;computer security;	1	2024-03-13	ChatGPT- 下一个WebSSRF 错误让黑客获取 HTTP 端点的完整访问权限
8047	WordPress Admins Urged to Remove miniOrange Plugins Due to Critical Flaw	https://thehackernews.com/2024/03/wordpress-admins-urged-to-remove.html	feedburner	news;	1	2024-03-18	WordPresresress 管理员敦促根据关键法例删除小型 Orange 插件
4823	Ramdev-Chemical-Industries	http://www.ransomfeed.it/index.php?page=post_details&id_post=13768	ransomfeed	ransom;mallox;	1	2024-03-17	Ramdev-化学工业
8228	A week in security (March 11 &#8211; March 17)	https://buaq.net/go-228736.html	buaq	newscopy;	0	2024-03-18	安全一周(3月11日,8211;3月17日)
319	Hack The Box: Appsanity Machine Walkthrough – Hard Difficulty	https://threatninja.net/2024/03/hack-the-box-appsanity-machine-walkthrough-hard-difficulty/	threatninja	sectest;Hard Machine;aspx shell;BurpSuite;Challenges;chisel;gobuster;HackTheBox;Linux;Penetration Testing;port forwarding;python3;ssh;	1	2024-03-09	Hack 盒子:体巧机器走过 — — 困难
8226	周岁前的日子也可以很精彩：我的小月龄带娃经历	https://buaq.net/go-228734.html	buaq	newscopy;	0	2024-03-18	周岁前的日子也可以很精彩：我的小月龄带娃经历
4164	南非四条海底光缆出现故障影响非洲东海岸互联网连接 同时故障的原因未知	https://buaq.net/go-228249.html	buaq	newscopy;	0	2024-03-15	南非四条海底光缆出现故障影响非洲东海岸互联网连接 同时故障的原因未知
9811	The Average Malicious Website Exists for Less Than 10 Minutes	https://blog.knowbe4.com/average-malicious-website-exists-10-minutes	knowbe4	news;Phishing;Security Awareness Training;Security Culture;	1	2024-03-25	平均恶意网站存在时间不到10分钟
9804	Mitigating Third-Party Risk Requires a Collaborative, Thorough Approach	https://www.darkreading.com/cyber-risk/mitigating-third-party-risk-requires-collaborative-approach	darkreading	news;	1	2024-03-25	缓解第三方风险需要合作、彻底的办法
8227	派开箱 | 科技祛魅，返璞归真：明基新款屏幕挂灯实用也更好用了	https://buaq.net/go-228735.html	buaq	newscopy;	0	2024-03-18	派开箱 | 科技祛魅，返璞归真：明基新款屏幕挂灯实用也更好用了
9812	Cloud-Conscious Cyber Attacks Spike 110% as Threat Groups Sharpen their Attack Skills	https://blog.knowbe4.com/cloud-conscious-cyberattacks-spike-110-as-threat-groups-sharpen-skills	knowbe4	news;Security Awareness Training;Ransomware;Security Culture;	1	2024-03-25	Spike 110%作为威胁团体 锐化其攻击技能
8242	ConMon: FedRAMP Continuous Monitoring and How It Works	https://securityboulevard.com/2024/03/conmon-fedramp-continuous-monitoring-and-how-it-works/	securityboulevard	news;Security Bloggers Network;Supplier Risk;	1	2024-03-18	Conmon:FedRAMP 持续监测和如何运作
8274	North Korea-Linked Group Levels Multistage Cyberattack on South Korea	https://www.darkreading.com/vulnerabilities-threats/north-korea-linked-group-level-multistage-cyberattack-on-south-korea	darkreading	news;	3	2024-03-19	对南朝鲜的多阶段网络攻击
8275	Tracking Everything on the Dark Web Is Mission Critical	https://www.darkreading.com/vulnerabilities-threats/tracking-everything-on-dark-web-is-mission-critical	darkreading	news;	1	2024-03-18	追踪黑暗网络上的一切是关键任务
8266	Fujitsu: Malware on Company Computers Exposed Customer Data	https://www.darkreading.com/cyberattacks-data-breaches/fujitsu-malware-on-company-computers-exposed-customer-data	darkreading	news;	1	2024-03-18	Fujitsu: 公司计算机披露客户数据的恶意软件
8276	Automate your Crypto Journey With Binance Auto Invest	https://blog.drhack.net/how-binance-auto-invest-works-to-make-profit/	drhack	news;Cryptocurrency;auto invest;binance;bnb;	1	2024-03-18	将您的加密旅行自动自动自动投放
8313	activeconceptsllccom	http://www.ransomfeed.it/index.php?page=post_details&id_post=13774	ransomfeed	ransom;blackbasta;	1	2024-03-18	激活的氯氟化氯
8314	eclinicalsolcom	http://www.ransomfeed.it/index.php?page=post_details&id_post=13776	ransomfeed	ransom;cactus;	1	2024-03-18	日服太阳
8315	grupatopexcom	http://www.ransomfeed.it/index.php?page=post_details&id_post=13777	ransomfeed	ransom;cactus;	1	2024-03-18	grupatopexcom 语组 语组 语组 语组
8317	Sun-Holdings	http://www.ransomfeed.it/index.php?page=post_details&id_post=13779	ransomfeed	ransom;hunters;	1	2024-03-18	太阳遮太阳
8319	后量子密码｜谷歌发布后量子密码学计划，距离PQC更进一步	https://www.freebuf.com/articles/neopoints/394881.html	freebuf	news;观点;	1	2024-03-15	后量子密码｜谷歌发布后量子密码学计划，距离PQC更进一步
8316	paginesi	http://www.ransomfeed.it/index.php?page=post_details&id_post=13778	ransomfeed	ransom;stormous;	1	2024-03-18	松松
8322	从蓝初小白到蓝中猴子（一）	https://www.freebuf.com/articles/web/370800.html	freebuf	news;Web安全;	1	2024-03-18	从蓝初小白到蓝中猴子（一）
8328	数据泄露态势（2024年2月）	https://www.freebuf.com/news/394963.html	freebuf	news;资讯;	1	2024-03-15	数据泄露态势（2024年2月）
8341	Loft Labs simplifies multi-cluster Kubernetes management for Rancher users	https://www.helpnetsecurity.com/2024/03/18/loft-labs-vcluster-for-rancher/	helpnetsecurity	news;Industry news;Loft Labs;	1	2024-03-18	为Rancher 用户简化多组库伯涅兹管理
8251	What is OSCAL and Why Does It Matter for NIST and FedRAMP?	https://securityboulevard.com/2024/03/what-is-oscal-and-why-does-it-matter-for-nist-and-fedramp/	securityboulevard	news;Security Bloggers Network;Supplier Risk;	1	2024-03-18	OSCAL是什么? 为什么它与NIST和FedRAMP有关?
8253	Microsoft announces deprecation of 1024-bit RSA keys in Windows	https://www.bleepingcomputer.com/news/microsoft/microsoft-announces-deprecation-of-1024-bit-rsa-keys-in-windows/	bleepingcomputer	news;Microsoft;Security;	1	2024-03-18	微软宣布 Windows 中 1024 位 RSA 键的折旧
8254	Apex Legends players worried about RCE flaw after ALGS hacks	https://www.bleepingcomputer.com/news/security/apex-legends-players-worried-about-rce-flaw-after-algs-hacks/	bleepingcomputer	news;Security;Gaming;	1	2024-03-18	Apex传奇球员在ALGS入侵后担心RCE的缺陷
8256	Chinese Earth Krahang hackers breach 70 orgs in 23 countries	https://www.bleepingcomputer.com/news/security/chinese-earth-krahang-hackers-breach-70-orgs-in-23-countries/	bleepingcomputer	news;Security;	4	2024-03-18	中国的黑客在23个国家突破70个兽群,
8257	Fujitsu found malware on IT systems, confirms data breach	https://www.bleepingcomputer.com/news/security/fujitsu-found-malware-on-it-systems-confirms-data-breach/	bleepingcomputer	news;Security;	1	2024-03-18	藤津在IT系统中发现恶意软件 证实数据被破坏
9829	Ejrcito-del-Per	http://www.ransomfeed.it/index.php?page=post_details&id_post=13918	ransomfeed	ransom;incransom;	1	2024-03-25	Ejrcito- del- per
9830	Law-Offices-of-John-V-Orrick-PL	http://www.ransomfeed.it/index.php?page=post_details&id_post=13919	ransomfeed	ransom;incransom;	1	2024-03-25	John-V-Orrick-PL法律办公室
9813	FBI: Losses Due to Cybercrime Jump to $12.5 Billion as Phishing Continues to Dominate	https://blog.knowbe4.com/fbi-losses-due-to-cybercrime-jump-12.5-billion-as-phishing-continues	knowbe4	news;Phishing;Security Awareness Training;Security Culture;	1	2024-03-25	FBI: 网络犯罪导致的损失 跳到125亿
9814	There Is Only So Much Lipstick You Can Put on a Cybercriminal Troll	https://blog.knowbe4.com/lipstick-you-can-put-cybercriminal-troll	knowbe4	news;Social Engineering;Phishing;	1	2024-03-25	只有这么多的唇膏 你可以把一个网络犯罪巨怪
8262	Investment advisers pay $400K to settle ‘AI washing’ charges	https://www.bleepingcomputer.com/news/technology/investment-advisers-pay-400k-to-settle-ai-washing-charges/	bleepingcomputer	news;Technology;	1	2024-03-18	投资顾问支付400KK美元,以结清 " AI清洗 " 费用
20572	Medusa cybercrime gang takes credit for another attack on US municipality	https://therecord.media/tarrant-county-texas-ransomware-attack-medusa	therecord	ransom;Cybercrime;News;News Briefs;Government;	1	2024-04-09	Medusa网络犯罪团伙因再次袭击美国市政府而获得信用
13540	融合智慧，赋能城市更新——副中心智慧城市建设研讨会成功举办	https://buaq.net/go-231646.html	buaq	newscopy;	0	2024-04-02	融合智慧，赋能城市更新——副中心智慧城市建设研讨会成功举办
8264	ML Model Repositories: The Next Big Supply Chain Attack Target	https://www.darkreading.com/cloud-security/ml-model-repositories-next-big-supply-chain-attack-target	darkreading	news;	1	2024-03-18	ML 模式储存库:下一个大供应链攻击目标
8270	Brazilian Authorities Arrest Members of Banking Trojan Cybercrime Group	https://www.darkreading.com/cybersecurity-operations/brazilian-authorities-arrest-members-of-banking-trojan-cybercrime-group	darkreading	news;	1	2024-03-18	巴西当局逮捕银行集团特洛伊电脑犯罪集团成员
8273	Chinese APT 'Earth Krahang' Compromises 48 Gov't Orgs on 5 Continents	https://www.darkreading.com/threat-intelligence/chinese-apt-earth-krahang-compromised-48-gov-orgs-5-continents	darkreading	news;	5	2024-03-18	中文 APT “ 地球Krahang” 折叠 48 5个大陆上的天兽
8419	How The Evolving Threat Landscape Drives Innovation In Cybersecurity - Tom Parker, Dave Dewalt - BSW #342	https://buaq.net/go-228873.html	buaq	newscopy;	0	2024-03-19	网络安全领域不断变化的威胁景观如何推动创新-Tom Parker、Dave Dewalt、BSW #342
8421	Ci ha lasciato Tom Stafford, astronauta lunare (1930-2024)	https://buaq.net/go-228875.html	buaq	newscopy;	0	2024-03-19	Ci ha lasciato Tom Stafford,宇航员Lunare(1930-2024年)
8422	Investment advisers pay $400K to settle ‘AI washing’ charges	https://buaq.net/go-228890.html	buaq	newscopy;	0	2024-03-19	投资顾问支付400KK美元,以结清 " AI清洗 " 费用
8423	Discussing Tools for Fitting Mutational Signatures: A Comprehensive Comparison	https://buaq.net/go-228891.html	buaq	newscopy;	0	2024-03-19	讨论用于配配配异性签名的工具:综合比较
8424	Comparing Tools for Fitting Mutational Signatures: The Results of Our Work	https://buaq.net/go-228892.html	buaq	newscopy;	0	2024-03-19	配配 Mudiation 签名的比较工具:我们工作的成果
8426	What Exactly Am I Making a Resume For?	https://buaq.net/go-228894.html	buaq	newscopy;	0	2024-03-19	我到底为什麽要再做一次?
8428	If The Interviewer Says, 'Do You Have Any Questions for Me?” Ask Questions That Matter	https://buaq.net/go-228896.html	buaq	newscopy;	0	2024-03-19	如果问者说:你们告诉我吧!你们有问题吗?问吧!
8379	vm2 3.9.19 Sandbox Escape	https://packetstormsecurity.com/files/177623/vm2-escape.txt	packetstorm	vuln;;	1	2024-03-18	3.9.19 沙箱逃逸
8380	Nokia BMC Log Scanner 13 Command Injection	https://packetstormsecurity.com/files/177624/nokialogscanner13-exec.txt	packetstorm	vuln;;	1	2024-03-18	Nokia BMC 日志扫描器 13 命令喷射
8381	Gasmark Pro 1.0 Shell Upload	https://packetstormsecurity.com/files/177625/gasmarkpro10-shell.txt	packetstorm	vuln;;	1	2024-03-18	Gasmark Pro 1.0 壳牌上传
8382	UPS Network Management Card 4 Path Traversal	https://packetstormsecurity.com/files/177626/upsnmc4-traversal.txt	packetstorm	vuln;;	1	2024-03-18	UPS UPS 网络管理卡 4 路径 Traversal
8384	Red Hat Security Advisory 2024-1346-03	https://packetstormsecurity.com/files/177628/RHSA-2024-1346-03.txt	packetstorm	vuln;;	1	2024-03-18	红帽子安保咨询2024-1346-03
8427	A Comprehensive Comparison of Tools for Fitting Mutational Signatures	https://buaq.net/go-228895.html	buaq	newscopy;	0	2024-03-19	供异性签名使用的工具综合比较
8385	Red Hat Security Advisory 2024-1348-03	https://packetstormsecurity.com/files/177629/RHSA-2024-1348-03.txt	packetstorm	vuln;;	1	2024-03-18	2024-1348-03红色帽子安保咨询
8386	Ubuntu Security Notice USN-6696-1	https://packetstormsecurity.com/files/177630/USN-6696-1.txt	packetstorm	vuln;;	1	2024-03-18	Ubuntu Ubuntu 安全通知 USN6696-1
8638	EPA looking to create water sector cyber task force to reduce risks from Iran, China	https://buaq.net/go-229092.html	buaq	newscopy;	0	2024-03-20	EPA 寻求建立水部门网络工作队,以减少伊朗、中国的风险
8388	Lynis Auditing Tool 3.1.1	https://packetstormsecurity.com/files/177633/lynis-3.1.1.tar.gz	packetstorm	vuln;;	1	2024-03-18	Lynis审计工具 3.1.1
8392	Nations Direct Mortgage alerts 83,000 to personal data leaks from December cyberattack	https://therecord.media/nations-direct-mortgage-data-breach	therecord	ransom;Industry;Cybercrime;News;News Briefs;	1	2024-03-18	12月网络攻击泄露个人数据后 直接抵押贷款警报83000
8398	4 Ways Cybercrime Could Impact Your Loan Business	https://infosecwriteups.com/4-ways-cybercrime-could-impact-your-loan-business-25076a810a77?source=rss----7b722bfd1b8d---4	infosecwriteups	tech;business;cybersecurity;loạn;security;cybercrime;	1	2024-03-18	4. 网络犯罪如何影响你的贷款业务
8397	Shodan Dorks	http://www.kitploit.com/2024/03/shodan-dorks.html	kitploit	tool;Shodan;Shodan Dorks;Webcam;Windows;WordPress;	1	2024-03-18	肖丹多尔克斯
8387	dav1d Integer Overflow / Out-Of-Bounds Write	https://packetstormsecurity.com/files/177632/GS20240318142425.tgz	packetstorm	vuln;;	1	2024-03-18	dav1d 整数溢出 / 溢出 写
8406	Discontinued WordPress Plugin Flaw Exposes Websites to Cyber Attacks	https://gbhackers.com/discontinued-wordpress-plugin-flaw/	GBHacker	news;Cyber Attack;Cyber Security News;Wordpress;	1	2024-03-18	停止 WordPress Plugin Flaw 网络攻击网站
8410	Hackers Using Weaponized SVG Files in Cyber Attacks	https://gbhackers.com/hackers-using-weaponized-svg-files-in-cyber-attacks/	GBHacker	news;Cyber Crime;cyber security;computer security;Cyber Security News;Malware;	1	2024-03-18	在网络攻击中使用武器化SVG文件的黑客
8411	ShadowSyndicate Hackers Exploiting Aiohttp Vulnerability To Access Sensitive Data	https://gbhackers.com/shadowsyndicate-aiohttp-vulnerability/	GBHacker	news;CVE/vulnerability;Cyber Crime;Ransomware;Aiohttp Vulnerability;CVE-2024-23334;Cyber Security News;Vulnerability;	1	2024-03-18	利用Aiohttp 脆弱性获取敏感数据
9831	Pantana-CPA	http://www.ransomfeed.it/index.php?page=post_details&id_post=13920	ransomfeed	ransom;incransom;	1	2024-03-25	Pantana-CPA
9832	khorg	http://www.ransomfeed.it/index.php?page=post_details&id_post=13921	ransomfeed	ransom;threeam;	1	2024-03-25	赫尔赫
9833	Affiliated-Dermatologists-and-Dermatologic-Surgeons	http://www.ransomfeed.it/index.php?page=post_details&id_post=13922	ransomfeed	ransom;bianlian;	1	2024-03-25	附属多光学和多光学外科医生
8413	Fujitsu suffered a malware attack and probably a data breach	https://buaq.net/go-228849.html	buaq	newscopy;	0	2024-03-19	藤津遭受恶意软件攻击 数据可能被破坏
8414	Chinese Earth Krahang hackers breach 70 orgs in 23 countries	https://buaq.net/go-228868.html	buaq	newscopy;	0	2024-03-19	中国的黑客在23个国家突破70个兽群,
8415	Cyberattack knocks out Pensacola city government phone lines	https://buaq.net/go-228869.html	buaq	newscopy;	0	2024-03-19	网络攻击击倒了潘萨科拉市政府的电话线
26376	小米集团盘前大涨15% 	https://s.weibo.com/weibo?q=%23小米集团盘前大涨15% %23	sina.weibo	hotsearch;weibo	1	2024-04-02	小米集团盘前大涨15%
26377	小米集团股价转跌 	https://s.weibo.com/weibo?q=%23小米集团股价转跌 %23	sina.weibo	hotsearch;weibo	1	2023-12-28	小米集团股价转跌
8416	Microsoft announces deprecation of 1024-bit RSA keys in Windows	https://buaq.net/go-228870.html	buaq	newscopy;	0	2024-03-19	微软宣布 Windows 中 1024 位 RSA 键的折旧
26378	小米高管回应年会跳舞视频 	https://s.weibo.com/weibo?q=%23小米高管回应年会跳舞视频 %23	sina.weibo	hotsearch;weibo	1	2024-01-03	小米高管回应年会跳舞视频
9839	Greenline-Service	http://www.ransomfeed.it/index.php?page=post_details&id_post=13928	ransomfeed	ransom;dragonforce;	1	2024-03-25	绿线服务
8383	Red Hat Security Advisory 2024-1345-03	https://packetstormsecurity.com/files/177627/RHSA-2024-1345-03.txt	packetstorm	vuln;;	1	2024-03-18	2024-1345-03红色帽子安保咨询
8430	Microsoft Teams Notifications Integration	https://buaq.net/go-228899.html	buaq	newscopy;	0	2024-03-19	微软团队通知整合
18009	Decoding the Web: Exploring the Depths of Exploitation | CTF Newbies	https://infosecwriteups.com/decoding-the-web-exploring-the-depths-of-exploitation-ctf-newbies-233293a2a739?source=rss----7b722bfd1b8d---4	infosecwriteups	tech;ctf-writeup;hackthebox-writeup;web-exploitation;cybersecurity;hackthebox;	1	2024-04-08	解码网络:探索开发深度 CCF Newbies
7632	Hackers Launching AI-Powered Cyber Attacks to Steal Billions	https://gbhackers.com/ai-powered-cyber-attacks/	GBHacker	news;Cyber Attack;Cyber Security News;	1	2024-03-18	黑客发射AI授权的网络攻击 以窃取数十亿
8425	Job Listed As In-Office? You Might Be Able To Go Remote	https://buaq.net/go-228893.html	buaq	newscopy;	0	2024-03-19	被列名为在职任务吗 ? 您可能有能力远程迁移 。
8453	Shadow SaaS Dangers in Cybersecurity Compliance Standards	https://securityboulevard.com/2024/03/shadow-saas-dangers-in-cybersecurity-compliance-standards/	securityboulevard	news;Security Bloggers Network;	1	2024-03-19	网络安全合规标准中的影子萨阿萨沙危险
8452	Malware	https://securityboulevard.com/2024/03/malware-2/	securityboulevard	news;Malware;Security Bloggers Network;aiXDR;Cyber Security Company;cybersecurity solution;	1	2024-03-19	错误软件
9835	Calida	http://www.ransomfeed.it/index.php?page=post_details&id_post=13924	ransomfeed	ransom;akira;	1	2024-03-25	卡利达
8390	FTC investigating Reddit plan to sell user content for AI model training	https://therecord.media/ftc-investigating-reddit-selling-user-data-ai	therecord	ransom;Government;Leadership;News;Privacy;	1	2024-03-18	FTC调查Reddit计划销售AI示范培训的用户内容
8420	PoC exploit for critical RCE flaw in Fortra FileCatalyst transfer tool released	https://buaq.net/go-228874.html	buaq	newscopy;	0	2024-03-19	PoC 利用Fortra FileCatalyst 传输工具,在Fortra FileCatalyst 传输工具中弥补 CRCE 严重缺陷
9838	Big-Issue-Group	http://www.ransomfeed.it/index.php?page=post_details&id_post=13927	ransomfeed	ransom;qilin;	1	2024-03-25	大岛组
8337	Deloitte unveils CyberSphere platform for simplified cyber program management	https://www.helpnetsecurity.com/2024/03/18/deloitte-cybersphere-platform/	helpnetsecurity	news;Industry news;Deloitte;	1	2024-03-18	Deloitte揭开简化网络方案管理的网络空间平台
8431	Last Week in Security (LWiS) - 2024-03-18	https://buaq.net/go-228905.html	buaq	newscopy;	0	2024-03-19	安全(LWIS)最后一周 - 2024-03-18
8616	Russians will no longer be able to access Microsoft cloud services, business intelligence tools	https://therecord.media/russians-losing-access-microsoft-cloud-amazon	therecord	ransom;News;Technology;	3	2024-03-19	俄罗斯人将无法再获得微软云服务、商业情报工具
9834	Burnham-Wood-Charter-Schools	http://www.ransomfeed.it/index.php?page=post_details&id_post=13923	ransomfeed	ransom;qilin;	1	2024-03-25	Burnham-Wood-《宪章》学校
8451	How MFA-Based Phishing Campaigns are Targeting Schools	https://securityboulevard.com/2024/03/how-mfa-based-phishing-campaigns-are-targeting-schools/	securityboulevard	news;Security Bloggers Network;Blog;Schools, Colleges, & Universities;	1	2024-03-19	MAFA-MFA的钓鱼运动如何以学校为目标
8449	Daniel Stori’s ‘I’m Fine’	https://securityboulevard.com/2024/03/daniel-storis-im-fine/	securityboulevard	news;Humor;Security Bloggers Network;Daniel Stori;Sarcasm;satire;turnoff.us;	1	2024-03-19	丹尼尔·斯托里(Daniel Storori)的“我罚款”
8433	 国内首家！如此渗透网络360也能拦截！ 	https://360.net/about/news/article64fa82bd2decde001f1a1e6e#menu	360	news;	1	2024-03-19	国内首家！如此渗透网络360也能拦截！
8393	Nigerian court orders Binance to release user data, as company execs continue to be held without charge	https://therecord.media/nigerian-court-orders-binance-to-release-user-data-executives-detained	therecord	ransom;Cybercrime;Government;News;People;Technology;	1	2024-03-18	尼日利亚法院命令 " Binance " 发布用户数据,因为公司执行人员继续被免费拘留
8536	Jasper-Dubois-County-Public-Library	http://www.ransomfeed.it/index.php?page=post_details&id_post=13833	ransomfeed	ransom;dragonforce;	1	2024-03-19	贾斯帕-多布瓦-国家-公共图书馆
8450	Discovering API secrets & endpoints using APKLeaks	https://securityboulevard.com/2024/03/discovering-api-secrets-endpoints-using-apkleaks/	securityboulevard	news;Security Bloggers Network;API Hacking Techniques;API Hacking Tools;	1	2024-03-19	使用 APKleaks 发现 APPI 机密和端点
8417	Nations Direct Mortgage alerts 83,000 to personal data leaks from December cyberattack	https://buaq.net/go-228871.html	buaq	newscopy;	0	2024-03-19	12月网络攻击泄露个人数据后 直接抵押贷款警报83000
8491	CyberheistNews Vol 14 #12 [HEADS UP] I Am Announcing AIDA: Artificial Intelligence Defense Agents!	https://blog.knowbe4.com/cyberheistnews-vol-14-12-heads-up-i-am-announcing-aida-artificial-intelligence-defense-agents	knowbe4	news;Cybercrime;KnowBe4;	1	2024-03-19	网 Heist News Vol 14 #12 [HEADS UP] 我宣布AIDA:人工情报防卫特工!
8429	The Elon Musk Don Lemon Interview: Full Video and Text Transcript	https://buaq.net/go-228897.html	buaq	newscopy;	0	2024-03-19	Elon Mussk Don Lemon访谈:全视频和文字记录
8389	Cyberattack knocks out Pensacola city government phone lines	https://therecord.media/cyberattack-pensacola-florida-knocks-out-phones	therecord	ransom;News;Government;Cybercrime;	1	2024-03-18	网络攻击击倒了潘萨科拉市政府的电话线
8432	无标题	https://360.net/about/news/article64d1b36e89b820001f90acd6#menu	360	news;	1	2024-03-19	无标题
9868	Phishing for W-2s: Keeping Your Financial Data Safe During Tax Season	https://www.mcafee.com/blogs/privacy-identity-protection/tax-season-scams/	mcafee	news;Internet Security;Privacy & Identity Protection;cybercrime;Phishing;	1	2024-03-25	W-2的幻象:在税收季节保持财务数据安全
9870	先知安全沙龙(成都站) - 浅析AD DS渗透中的防御规避	https://xz.aliyun.com/t/14184	阿里先知实验室	news;	1	2024-03-25	先知安全沙龙(成都站) - 浅析AD DS渗透中的防御规避
9854	Synopsys 同意出售应用安全部门，价值 5.25 亿美元	https://www.freebuf.com/news/395765.html	freebuf	news;资讯;	1	2024-03-25	Synopsys 同意出售应用安全部门，价值 5.25 亿美元
10019	网安标委发布《网络安全标准实践指南——网络安全产品互联互通 资产信息格式》	https://www.freebuf.com/articles/396002.html	freebuf	news;	1	2024-03-26	网安标委发布《网络安全标准实践指南——网络安全产品互联互通 资产信息格式》
8437	E-Root Marketplace Admin Sentenced to 42 Months for Selling 350K Stolen Credentials	https://thehackernews.com/2024/03/e-root-marketplace-admin-sentenced-to.html	feedburner	news;	1	2024-03-19	因出售350K被盗证书而被判处42个月监禁
1298	Scam or Not? How to Tell Whether Your Text Message Is Real 	https://www.mcafee.com/blogs/tips-tricks/scam-or-not-how-to-tell-whether-your-text-message-is-real/	mcafee	news;Tips & Tricks;	1	2024-03-12	Scam 或不是 scam ? 如何判断您的短信是否真实 ?
8448	Cybersecurity’s Class Conundrum: Winner-Take-All Market Dynamics	https://securityboulevard.com/2024/03/cybersecuritys-class-conundrum-winner-take-all-market-dynamics/	securityboulevard	news;Security Bloggers Network;trends;	1	2024-03-19	网络安全网络安全层面的难题:胜者全胜市场动态
8436	Crafting and Communicating Your Cybersecurity Strategy for Board Buy-In	https://thehackernews.com/2024/03/crafting-and-communicating-your.html	feedburner	news;	1	2024-03-19	制作和传播您的网络安全战略,供董事会买入
8534	Accipiter-Capital-Management-LLC-	http://www.ransomfeed.it/index.php?page=post_details&id_post=13831	ransomfeed	ransom;medusa;	1	2024-03-19	护航员 - 船长 - 管理 - LLC -
8434	APIs Drive the Majority of Internet Traffic and Cybercriminals are Taking Advantage	https://thehackernews.com/2024/03/apis-drive-majority-of-internet-traffic.html	feedburner	news;	1	2024-03-19	AIPs驱动互联网交通和网络罪犯的多数人正在利用互联网和网络罪犯的优势。
8440	Hackers Exploiting Popular Document Publishing Sites for Phishing Attacks	https://thehackernews.com/2024/03/hackers-exploiting-popular-document.html	feedburner	news;	1	2024-03-19	利用民众文件出版网站进行钓钓鱼袭击
9864	20 essential open-source cybersecurity tools that save you time	https://www.helpnetsecurity.com/2024/03/25/essential-open-source-cybersecurity-tools/	helpnetsecurity	news;Don't miss;Hot stuff;News;cybersecurity;GitHub;open source;penetration testing;software;	1	2024-03-25	20个基本开放源码网络安全工具,节省时间
9862	Cybercriminals use ChatGPT’s prompts as weapons	https://www.helpnetsecurity.com/2024/03/25/chatgpt-cybersecurity-implications-video/	helpnetsecurity	news;Video;BlackBerry;ChatGPT;cybersecurity;Perception Point;Reciprocity;Skyhigh Security;video;	1	2024-03-25	网络犯罪份子利用查特的热潮作为武器
9841	Dunbier-Boat-Trailers	http://www.ransomfeed.it/index.php?page=post_details&id_post=13930	ransomfeed	ransom;dragonforce;	1	2024-03-25	登比尔-艇-拖船
9843	国家网信办公布《促进和规范数据跨境流动规定》	https://www.freebuf.com/articles/395806.html	freebuf	news;	1	2024-03-25	国家网信办公布《促进和规范数据跨境流动规定》
9853	StrelaStealer 恶意软件“浮出水面”，数百个美国和欧盟组织遭殃	https://www.freebuf.com/news/395752.html	freebuf	news;资讯;	2	2024-03-25	StrelaStealer 恶意软件“浮出水面”，数百个美国和欧盟组织遭殃
8445	Suspected Russian Data-Wiping 'AcidPour' Malware Targeting Linux x86 Devices	https://thehackernews.com/2024/03/suspected-russian-data-wiping-acidpour.html	feedburner	news;	3	2024-03-19	俄罗斯疑似数据扫描“ ACidPour ” 恶意瞄准 Linux x86 设备
9855	95% 的公司面临 API 安全问题	https://www.freebuf.com/news/395770.html	freebuf	news;资讯;	1	2024-03-25	95% 的公司面临 API 安全问题
9856	同盾科技被指侵犯用户信息	https://www.freebuf.com/news/395771.html	freebuf	news;资讯;	1	2024-03-25	同盾科技被指侵犯用户信息
9857	GitLab 收购初创安全公司 Oxeye	https://www.freebuf.com/news/395784.html	freebuf	news;资讯;	1	2024-03-25	GitLab 收购初创安全公司 Oxeye
9860	APT29 hit German political parties with bogus invites and malware	https://www.helpnetsecurity.com/2024/03/25/apt29-german-political-parties/	helpnetsecurity	news;Don't miss;Hot stuff;News;Germany;malware;Mandiant;phishing;Russian Federation;Zscaler;	2	2024-03-25	APT29用假邀请和恶意软件袭击德国政党
9861	Scammers steal millions from FTX, BlockFi claimants	https://www.helpnetsecurity.com/2024/03/25/blockfi-ftx-phishing/	helpnetsecurity	news;Don't miss;Hot stuff;News;cryptocurrency;cryptocurrency exchange;phishing;scams;	1	2024-03-25	Scammers公司从FFX公司、BlockFi公司索赔人那里盗取了数百万美元。
3451	Nissan confirms ransomware attack exposed data of 100,000 people	https://www.bleepingcomputer.com/news/security/nissan-confirms-ransomware-attack-exposed-data-of-100-000-people/	bleepingcomputer	news;Security;	2	2024-03-14	尼桑确认赎金软件袭击 暴露数据10万人
9865	Interos Resilience Watchtower enables companies to monitor vulnerabilities	https://www.helpnetsecurity.com/2024/03/25/interos-resilience-watchtower/	helpnetsecurity	news;Industry news;Interos;	1	2024-03-25	Interos复原力观测台使公司能够监测脆弱性
8444	New Phishing Attack Uses Clever Microsoft Office Trick to Deploy NetSupport RAT	https://thehackernews.com/2024/03/new-phishing-attack-uses-clever.html	feedburner	news;	1	2024-03-19	使用新的钓鱼攻击工具 聪明的微软办公室为部署网络支持RAT
9866	Scams are becoming more convincing and costly	https://www.helpnetsecurity.com/2024/03/25/scams-volume-increase/	helpnetsecurity	news;News;cybercrime;fraud;report;scams;survey;Visa;	1	2024-03-25	飞弹越来越令人信服,越来越昂贵
18010	How I hacked Biometric machine just by using a calculator	https://infosecwriteups.com/how-i-hacked-biometric-machine-just-by-using-a-calculator-794e4254cedb?source=rss----7b722bfd1b8d---4	infosecwriteups	tech;hacking;biometrics;cybersecurity;funny;	1	2024-04-08	我如何利用计算器 黑进生物测量机器
8464	FTC warns scammers are impersonating its employees to steal money	https://www.bleepingcomputer.com/news/security/ftc-warns-scammers-are-impersonating-its-employees-to-steal-money/	bleepingcomputer	news;Security;	1	2024-03-19	公平贸易委员会警告诈骗者冒冒冒名顶替其雇员偷钱
8467	Ukraine arrests hackers trying to sell 100 million stolen accounts	https://www.bleepingcomputer.com/news/security/ukraine-arrests-hackers-trying-to-sell-100-million-stolen-accounts/	bleepingcomputer	news;Security;Legal;	1	2024-03-19	乌克兰逮捕了黑客 试图卖掉1亿个失窃账户的黑客
8468	US Defense Dept received 50,000 vulnerability reports since 2016	https://www.bleepingcomputer.com/news/security/us-defense-dept-received-50-000-vulnerability-reports-since-2016/	bleepingcomputer	news;Security;	1	2024-03-19	自2016年以来,美国国防部收到50 000份脆弱性报告
18011	How to Automatically Deploy a Malware Analysis Environment	https://infosecwriteups.com/how-to-automatically-deploy-a-malware-analysis-environment-47258fb7aeb1?source=rss----7b722bfd1b8d---4	infosecwriteups	tech;malware;guides-and-tutorials;terraform;cybersecurity;malware-analysis;	1	2024-04-08	如何自动部署错误分析环境
8471	'Conversation Overflow' Cyberattacks Bypass AI Security to Target Execs	https://www.darkreading.com/cloud-security/conversation-overflow-cyberattacks-bypass-ai-security	darkreading	news;	1	2024-03-19	“Conlocation Convolution overfrom ” 网络攻击 绕过 AI 安全到目标执行
8473	Name That Toon: Bridge the Gap	https://www.darkreading.com/cloud-security/name-that-toon-bridge-the-gap	darkreading	news;	1	2024-03-19	命名“卡通:弥合差距”
8474	Airbus Calls Off Planned Acquisition of Atos Cybersecurity Group	https://www.darkreading.com/cyber-risk/airbus-calls-off-planned-acquisition-of-atos-cybersecurity-group	darkreading	news;	1	2024-03-19	阿托斯网络安全小组
3567	Despite Feeling Prepared for Image-Based Attacks, Most Organizations Have Been Compromised by Them	https://blog.knowbe4.com/despite-prepared-for-image-based-attacks-most-organizations-have-been-compromised	knowbe4	news;Social Engineering;Phishing;Security Culture;	1	2024-03-14	多数组织都遭到他们的迫害。
8481	The New CISO: Rethinking the Role	https://www.darkreading.com/cybersecurity-operations/new-ciso-rethinking-the-role	darkreading	news;	1	2024-03-19	新的CISO:重新思考其作用
8482	New Regulations Make D&amp;O Insurance a Must for CISOs	https://www.darkreading.com/cybersecurity-operations/new-regulations-make-d-o-insurance-a-must-for-cisos	darkreading	news;	1	2024-03-19	新条例使 D&O 保险为 CISO 必需
8485	'PhantomBlu' Cyberattackers Backdoor Microsoft Office Users via OLE	https://www.darkreading.com/threat-intelligence/phantomblu-cyberattackers-backdoor-microsoft-office-users-ole	darkreading	news;	1	2024-03-19	“PhantomBlu”网络攻击者通过 OLE 后门微软办公室用户
8486	Fortra Releases Update on Critical Severity RCE Flaw	https://www.darkreading.com/vulnerabilities-threats/fortra-releases-update-on-critical-severity-rce-flaw	darkreading	news;	1	2024-03-19	关于关键严重性CREE Flaw的Fortra 释放最新情况
8490	AI and the Boardroom: Bridging Innovation and Security	https://blog.knowbe4.com/ai-and-the-boardroom-bridging-innovation-and-security	knowbe4	news;Security Culture;	1	2024-03-19	大赦国际和董事会:连接创新和安全
8495	State-Sponsored Russian Phishing Campaigns Target a Variety of Industries	https://blog.knowbe4.com/russian-phishing-campaigns-target-variety-of-industries	knowbe4	news;Social Engineering;Phishing;Security Awareness Training;Security Culture;	3	2024-03-19	针对不同行业的俄罗斯钓鱼运动
8526	AGL	http://www.ransomfeed.it/index.php?page=post_details&id_post=13780	ransomfeed	ransom;hunters;	1	2024-03-18	阿 和 成 成 成 成 成
8494	Phishing Tops 2023’s Most Common Cyber Attack Initial Access Method	https://blog.knowbe4.com/phishing-tops-2023-most-common-cyber-attack	knowbe4	news;Phishing;Ransomware;Security Culture;	1	2024-03-19	2023年最常用的网络攻击初步访问方法
8527	HSI	http://www.ransomfeed.it/index.php?page=post_details&id_post=13781	ransomfeed	ransom;hunters;	1	2024-03-18	高 血 性 性 性 性 性 性 性 性 性 性 性 性 性 性 性 性 性 性 性 性 性 性 性 性 性 性 性 性 性
8528	Dr-Leeman-ENT	http://www.ransomfeed.it/index.php?page=post_details&id_post=13782	ransomfeed	ransom;bianlian;	1	2024-03-19	列曼-恩特博士
8529	Sting-AD	http://www.ransomfeed.it/index.php?page=post_details&id_post=13785	ransomfeed	ransom;hunters;	1	2024-03-19	Sting- AD 定时
8531	Therapeutic-Health-Services	http://www.ransomfeed.it/index.php?page=post_details&id_post=13787	ransomfeed	ransom;hunters;	1	2024-03-19	治疗 -- -- 保健 -- -- 服务
8532	Panzeri-Cattaneo	http://www.ransomfeed.it/index.php?page=post_details&id_post=13788	ransomfeed	ransom;hunters;	1	2024-03-19	潘泽里-卡塔内奥
9871	先知安全沙龙(成都站) - Magic Webshell-Java文件上传流量对抗	https://xz.aliyun.com/t/14185	阿里先知实验室	news;	1	2024-03-25	先知安全沙龙(成都站) - Magic Webshell-Java文件上传流量对抗
8533	Delta-Pipeline	http://www.ransomfeed.it/index.php?page=post_details&id_post=13789	ransomfeed	ransom;bianlian;	1	2024-03-19	Delta- Pipline
9872	先知安全沙龙(成都站) - Beyond Control-Linux内核漏洞利用浅谈	https://xz.aliyun.com/t/14186	阿里先知实验室	news;	3	2024-03-25	先知安全沙龙(成都站) - Beyond Control-Linux内核漏洞利用浅谈
8461	Avoid high cyber insurance costs by improving Active Directory security	https://www.bleepingcomputer.com/news/security/avoid-high-cyber-insurance-costs-by-improving-active-directory-security/	bleepingcomputer	news;Security;	1	2024-03-19	通过改进活动目录安全,避免高额网络保险费用
13541	ChatGPT 不再需要注册，即开即用直接使用 GPT-3.5	https://buaq.net/go-231654.html	buaq	newscopy;	0	2024-04-02	ChatGPT 不再需要注册，即开即用直接使用 GPT-3.5
8463	CISA shares critical infrastructure defense tips against Chinese hackers	https://www.bleepingcomputer.com/news/security/cisa-shares-critical-infrastructure-defense-tips-against-chinese-hackers/	bleepingcomputer	news;Security;	4	2024-03-19	CISA分享了针对中国黑客的重要基础设施防御小费
13542	Last Week in Security (LWiS) - 2024-04-01	https://buaq.net/go-231661.html	buaq	newscopy;	0	2024-04-02	安保最后一周(LWIS) - 2024-04-01
8466	New AcidPour data wiper targets Linux x86 network devices	https://www.bleepingcomputer.com/news/security/new-acidpour-data-wiper-targets-linux-x86-network-devices/	bleepingcomputer	news;Security;Linux;	1	2024-03-19	新酸Pour 数据擦拭器瞄准 Linux x86 网络设备
8591	Atlassian Confluence 8.5.3 Remote Code Execution	https://packetstormsecurity.com/files/177643/atlassianconfluence853-exec.txt	packetstorm	vuln;;	1	2024-03-19	8.5.3 远程代码执行
8592	Ubuntu Security Notice USN-6700-1	https://packetstormsecurity.com/files/177644/USN-6700-1.txt	packetstorm	vuln;;	1	2024-03-19	Ubuntu Ubuntu 安全通知 USN-6700-1
8593	Red Hat Security Advisory 2024-0722-03	https://packetstormsecurity.com/files/177645/RHSA-2024-0722-03.txt	packetstorm	vuln;;	1	2024-03-19	红帽子安保咨询2024-00722-03
8594	Red Hat Security Advisory 2024-1255-03	https://packetstormsecurity.com/files/177646/RHSA-2024-1255-03.txt	packetstorm	vuln;;	1	2024-03-19	红帽子安保咨询 2024-1255-03
8595	Red Hat Security Advisory 2024-1316-03	https://packetstormsecurity.com/files/177647/RHSA-2024-1316-03.txt	packetstorm	vuln;;	1	2024-03-19	2024-1316-03红色帽子安保咨询
8537	Retirement-Line	http://www.ransomfeed.it/index.php?page=post_details&id_post=13834	ransomfeed	ransom;snatch;	1	2024-03-19	退休线
8539	PB-Capital-Group	http://www.ransomfeed.it/index.php?page=post_details&id_post=13836	ransomfeed	ransom;bianlian;	1	2024-03-19	PB-首都小组
8540	Butler-Lavanceau--Sober	http://www.ransomfeed.it/index.php?page=post_details&id_post=13837	ransomfeed	ransom;snatch;	1	2024-03-18	巴特勒-拉万塞-索伯
13543	IAST 5.X系列 | 悬镜灵脉IAST 5.2敏捷版发布，化繁为简，轻装上阵	https://buaq.net/go-231681.html	buaq	newscopy;	0	2024-04-02	IAST 5.X系列 | 悬镜灵脉IAST 5.2敏捷版发布，化繁为简，轻装上阵
8541		http://www.ransomfeed.it/index.php?page=post_details&id_post=13838	ransomfeed	ransom;cloak;	1	2024-03-18	调
13544	海盗湾上最长寿的种子有 20 年历史	https://buaq.net/go-231684.html	buaq	newscopy;	0	2024-04-02	海盗湾上最长寿的种子有 20 年历史
13545	贺建奎恢复正常工作	https://buaq.net/go-231685.html	buaq	newscopy;	0	2024-04-02	贺建奎恢复正常工作
13546	诉讼表明Facebook通过流量劫持技术分析和监视竞争对手用户数据	https://buaq.net/go-231692.html	buaq	newscopy;	0	2024-04-02	诉讼表明Facebook通过流量劫持技术分析和监视竞争对手用户数据
13547	集邦咨询认为固态硬盘将继续上涨10%~15% 企业级SSD情况更糟糕	https://buaq.net/go-231693.html	buaq	newscopy;	0	2024-04-02	集邦咨询认为固态硬盘将继续上涨10%~15% 企业级SSD情况更糟糕
8553	纳斯达克交易系统宕机2小时，RASH FIX订单无效	https://www.freebuf.com/news/395193.html	freebuf	news;资讯;	1	2024-03-19	纳斯达克交易系统宕机2小时，RASH FIX订单无效
8555	日本科技巨头富士通遭遇网络攻击，客户数据被窃	https://www.freebuf.com/news/395198.html	freebuf	news;资讯;	1	2024-03-19	日本科技巨头富士通遭遇网络攻击，客户数据被窃
8546	0day之某路由器前台RCE审计	https://www.freebuf.com/articles/web/395021.html	freebuf	news;Web安全;	1	2024-03-16	0day之某路由器前台RCE审计
8558	思科宣布完成对 Splunk 的收购	https://www.freebuf.com/news/395301.html	freebuf	news;资讯;	1	2024-03-19	思科宣布完成对 Splunk 的收购
8557	英国政府发布云托管监控和数据采集（ SCADA）安全指南	https://www.freebuf.com/news/395251.html	freebuf	news;资讯;	1	2024-03-19	英国政府发布云托管监控和数据采集（ SCADA）安全指南
8562	eSentire Threat Intelligence reduces false positive alerts	https://www.helpnetsecurity.com/2024/03/19/esentire-threat-intelligence/	helpnetsecurity	news;Industry news;eSentire;	1	2024-03-19	e. 情报减少虚假的正面警报
8564	NIST’s NVD has encountered a problem	https://www.helpnetsecurity.com/2024/03/19/nvd-vulnerability-management/	helpnetsecurity	news;Don't miss;Hot stuff;News;Chainguard;enterprise;NIST;Qualys;Rapid7;vulnerability;vulnerability management;	1	2024-03-19	NIST NND 遇到一个问题
8568	Tufin Orchestration Suite R24-1 enhances cloud security and compliance	https://www.helpnetsecurity.com/2024/03/19/tufin-tos-r24-1/	helpnetsecurity	news;Industry news;Tufin;	1	2024-03-19	Tufin管弦设计套装R24-1增强云的安全和合规性
8567	Traefik Labs updates address rising Kubernetes adoption and API management	https://www.helpnetsecurity.com/2024/03/19/traefik-labs-api-gateway-updates/	helpnetsecurity	news;Industry news;Traefik Labs;	1	2024-03-19	Treefik Labs最新消息回应库伯涅茨(Kubernetes)的收养和API管理。
8565	Ordr launches OrdrAI CAASM+ to provide asset visibility with AI/ML classification	https://www.helpnetsecurity.com/2024/03/19/ordrai-caasm/	helpnetsecurity	news;Industry news;Ordr;	1	2024-03-19	Ordr 发射Ordr 发射Ordr AI OrdrAI CAASSM+ 提供AI/ML分类资产可见度
8571	Microsoft Copilot for Security: General Availability details	https://techcommunity.microsoft.com/t5/microsoft-security-copilot-blog/microsoft-copilot-for-security-general-availability-details/ba-p/4079970	microsoft	news;	1	2024-03-18	微软安全联合试办公司:一般供应详情
8573	Quick-Cms_v6.7-en-updated-2023-08-01-SQLi	https://www.nu11secur1ty.com/2024/03/quick-cmsv67-en-updated-2023-08-01-sqli.html	nu11security	vuln;	1	2024-03-19	Quick-Cms_v6.7 - 更新到2023-08-01-SQLi
9873	先知安全沙龙(成都站) - RASP 视角下的攻防转换	https://xz.aliyun.com/t/14187	阿里先知实验室	news;	1	2024-03-25	先知安全沙龙(成都站) - RASP 视角下的攻防转换
12242	Yacht retailer MarineMax discloses data breach after cyberattack	https://www.bleepingcomputer.com/news/security/yacht-retailer-marinemax-discloses-data-breach-after-cyberattack/	bleepingcomputer	news;Security;	1	2024-04-01	MarineMax在网络攻击后披露数据被破坏
8854	Suricata IDPE 7.0.4	https://packetstormsecurity.com/files/177709/suricata-7.0.4.tar.gz	packetstorm	vuln;;	1	2024-03-20	苏里卡塔 Suriicata IDPE 7.0.4
8855	Ubuntu Security Notice USN-6686-4	https://packetstormsecurity.com/files/177710/USN-6686-4.txt	packetstorm	vuln;;	1	2024-03-20	Ubuntu Ubuntu 安全通知 USN6686-4
8856	Debian Security Advisory 5641-1	https://packetstormsecurity.com/files/177711/dsa-5641-1.txt	packetstorm	vuln;;	1	2024-03-20	Debian安全咨询 5641-1
8590	Ubuntu Security Notice USN-6699-1	https://packetstormsecurity.com/files/177642/USN-6699-1.txt	packetstorm	vuln;;	1	2024-03-19	Ubuntu Ubuntu 安全通知 USN-6699-1
20575	CL0P's Ransomware Rampage - Security Measures for 2024	https://thehackernews.com/2024/04/cl0ps-ransomware-rampage-security.html	feedburner	news;	2	2024-04-09	CL0P的Ransomware Rampage - 2024年安全措施
10958	Linux内核权限提升漏洞（CVE-2024-1086）通告	https://blog.nsfocus.net/linuxcve-2024-1086/	绿盟	news;威胁通告;安全漏洞;漏洞防护;	5	2024-03-29	Linux内核权限提升漏洞（CVE-2024-1086）通告
10950	CTF: Where Experts Play And Flags Fall | CTF Newbies	https://infosecwriteups.com/ctf-where-experts-play-and-flags-fall-ctf-newbies-3ab9513ab7d3?source=rss----7b722bfd1b8d---4	infosecwriteups	tech;ctf-walkthrough;hackthebox;infosec;cybersecurity;ctf;	1	2024-03-29	CTF: 专家玩耍和旗旗落的地方 CTF Newbies
10957	Under the Hood: How Fuzzing Really Works	https://infosecwriteups.com/under-the-hood-how-fuzzing-really-works-f16ee58be279?source=rss----7b722bfd1b8d---4	infosecwriteups	tech;	1	2024-03-29	在兜帽下:模糊如何真正发挥作用
8811	Microsoft Sentinel delivered 234% ROI, according to new Forrester study	https://www.microsoft.com/en-us/security/blog/2024/03/19/microsoft-sentinel-delivered-234-roi-according-to-new-forrester-study/	microsoft	news;	1	2024-03-19	根据Forrester的新研究,微软哨兵交付了234%的ROI
10962	Google Revealed Kernel Address Sanitizer To Harden Android Firmware And Beyond	https://gbhackers.com/google-kasan-android-firmware-hardening/	GBHacker	news;Android;CVE/vulnerability;cyber security;Android security;Firmware Hardening;Memory Safety;	2	2024-03-29	Google 公开的 Kernel 致Harden Android 企业软件及以后的 清洁剂
15399	73% 的组织担忧未来网络安全威胁会影响业务	https://www.freebuf.com/news/396871.html	freebuf	news;资讯;	1	2024-04-03	73% 的组织担忧未来网络安全威胁会影响业务
9899	Red Hat Security Advisory 2024-0689-03	https://packetstormsecurity.com/files/177741/RHSA-2024-0689-03.txt	packetstorm	vuln;;	1	2024-03-25	红色帽子安保咨询2024-0689-03
15411	How Google plans to make stolen session cookies worthless for attackers	https://www.helpnetsecurity.com/2024/04/03/using-stolen-session-cookies/	helpnetsecurity	news;Don't miss;Hot stuff;News;authentication;Chrome;cookies;malware;MFA;privacy;public-key cryptography;	1	2024-04-03	Google计划如何让失窃的会话饼干对攻击者毫无价值,
8631	Mintlify Data Breach Exposes Customer GitHub Tokens	https://gbhackers.com/mintlify-data-breach-exposes/	GBHacker	news;cyber security;Cyber Security News;Data Breach;Data breaches;	1	2024-03-19	最小化数据泄漏曝光客户 GitHub Tokens
10949	Crafting Chaos: A deep dive into developing Shellcode Loaders!	https://infosecwriteups.com/crafting-chaos-a-deep-dive-into-developing-shellcode-loaders-a965a80903f2?source=rss----7b722bfd1b8d---4	infosecwriteups	tech;malware;infosec;red-team;malware-development;	1	2024-03-29	深层潜入开发壳牌装载器!
13548	喜讯！部分幸运用户获得Microsoft 365 E3免费续订 而且还是续订1年	https://buaq.net/go-231694.html	buaq	newscopy;	0	2024-04-02	喜讯！部分幸运用户获得Microsoft 365 E3免费续订 而且还是续订1年
13551	71% Website Vulnerable: API Security Becomes Prime Target for Hackers	https://buaq.net/go-231758.html	buaq	newscopy;	0	2024-04-02	71%网站弱势:API安全成为黑客的首要目标
10956	THM — Expose	https://infosecwriteups.com/thm-expose-4ceca4bcbd53?source=rss----7b722bfd1b8d---4	infosecwriteups	tech;learning;medium;writing;tryhackme;technology;	1	2024-03-29	THM - 说明
13549	Google to Delete Billions of Browsing Records in 'Incognito Mode' Privacy Lawsuit Settlement	https://buaq.net/go-231712.html	buaq	newscopy;	0	2024-04-02	谷歌删除数十亿张浏览记录 在“ Incognito mode” 隐私法律解决中
16358	-San-Pasqual-Band-of-Mission-Indians	http://www.ransomfeed.it/index.php?page=post_details&id_post=14090	ransomfeed	ransom;medusa;	1	2024-04-03	- San-Pasqual-Band-Miss-印度人
16359	East-Baton-Rouge-Sheriffs-Office	http://www.ransomfeed.it/index.php?page=post_details&id_post=14091	ransomfeed	ransom;medusa;	1	2024-04-03	东巴顿-鲁格-警长办公室
13550	Massive Phishing Campaign Strikes Latin America: Venom RAT Targeting Multiple Sectors	https://buaq.net/go-231713.html	buaq	newscopy;	0	2024-04-02	拉丁美洲:毒液RAT针对多个部门
16360	Phillip-Townsend-Associates	http://www.ransomfeed.it/index.php?page=post_details&id_post=14094	ransomfeed	ransom;blacksuit;	1	2024-04-03	Philip- Townsend- Associates 协会
13552	On Hiatus	https://buaq.net/go-231759.html	buaq	newscopy;	0	2024-04-02	在 Hiatus 上
13553	每日安全动态推送(4-2)	https://buaq.net/go-231805.html	buaq	newscopy;	0	2024-04-02	每日安全动态推送(4-2)
24403	Yesterday, in DC, I was given the Holland on the Hill Freddy Heineken Award	https://blog.knowbe4.com/yesterday-in-dc-i-was-given-the-holland-on-the-hill-freddy-heineken-award	knowbe4	news;KnowBe4;	1	2024-04-11	昨天在华盛顿,我被授予荷兰 佛莱迪海尼根山奖
8824	Microsoft Outlook Remote Code Execution Vulnerability	https://cxsecurity.com/issue/WLB-2024030042	cxsecurity	vuln;	1	2024-03-20	微软 Outlook 远程代码执行脆弱性
8797	Growing AceCryptor attacks in Europe	https://www.helpnetsecurity.com/2024/03/20/acecryptor-attacks-increase/	helpnetsecurity	news;News;cybercrime;cybersecurity;email;ESET;EU;Europe;malware;remote access trojan;	1	2024-03-20	欧洲的Acreactoptor 袭击
8694	Here's why Twitter sends you to a different site than what you clicked	https://www.bleepingcomputer.com/news/security/heres-why-twitter-sends-you-to-a-different-site-than-what-you-clicked/	bleepingcomputer	news;Security;	1	2024-03-20	这就是为什么Twitter将你发送到不同网站的原因,
10953	HTB Cyber Apocalypse CTF 2024 — Web	https://infosecwriteups.com/htb-cyber-apocalypse-ctf-2024-web-50b31126de50?source=rss----7b722bfd1b8d---4	infosecwriteups	tech;htb;ctf-writeup;web;walkthrough;ctf;	1	2024-03-29	HTB 网络世界末日 CTF 2024-Web
10951	HTB Analytics Walkthrough	https://infosecwriteups.com/htb-analytics-walkthrough-fd256a170fae?source=rss----7b722bfd1b8d---4	infosecwriteups	tech;hackthebox;pentesting;htb-writeup;infosec;cybersecurity;	1	2024-03-29	HTB 分析法
26379	小米高管辟谣SU7锁单量 	https://s.weibo.com/weibo?q=%23小米高管辟谣SU7锁单量 %23	sina.weibo	hotsearch;weibo	1	2024-04-01	小米高管辟谣SU7锁单量
26380	小米龙铠架构 	https://s.weibo.com/weibo?q=%23小米龙铠架构 %23	sina.weibo	hotsearch;weibo	1	2024-02-21	小米龙铠架构
10961	Compromised SaaS Supply Chain Apps: 97% of Organizations at Risk of Cyber Attacks	https://gbhackers.com/compromised-saas-supply-chain-apps/	GBHacker	news;Cyber Security News;computer security;	1	2024-03-29	SaaS供应链应用程序:97%面临网络袭击风险的组织
26381	小黑盒崩了 	https://s.weibo.com/weibo?q=%23小黑盒崩了 %23	sina.weibo	hotsearch;weibo	1	2024-03-15	小黑盒崩了
2593	[Security Masterminds] The Art of Defending Against Social Engineering in the Age of AI: Insights from Rachel Tobac	https://blog.knowbe4.com/security-masterminds-the-art-of-defending-against-social-engineering-in-the-age-of-ai-insights-from-rachel-tobac	knowbe4	news;Security Masterminds Podcast;	1	2024-03-13	[安全硕士] 《在AI时代捍卫社会工程的艺术:Rachel Tobac的洞察》
2513	Alert: Cybercriminals Deploying VCURMS and STRRAT Trojans via AWS and GitHub	https://thehackernews.com/2024/03/alert-cybercriminals-deploying-vcurms.html	feedburner	news;	1	2024-03-13	警报:通过AWS和GitHub部署VCURMS和STRRATT Trojans的网络犯罪分子
4943	Finding Your Ideal Workplace: Beyond Salary, What Truly Matters in a Job?	https://buaq.net/go-228679.html	buaq	newscopy;	0	2024-03-18	寻找你理想的工作场所:超过工资,工作的真正意义是什么?
9900	Red Hat Security Advisory 2024-0691-03	https://packetstormsecurity.com/files/177742/RHSA-2024-0691-03.txt	packetstorm	vuln;;	1	2024-03-25	红色帽子安保咨询 2024-0691-003
4748	USENIX Security ’23 – Pushed By Accident: A Mixed-Methods Study On Strategies Of Handling Secret Information In Source Code Repositories	https://securityboulevard.com/2024/03/usenix-security-23-pushed-by-accident-a-mixed-methods-study-on-strategies-of-handling-secret-information-in-source-code-repositories/	securityboulevard	news;Security Bloggers Network;Open Access Research;Security Conferences;Security Research;USENIX;USENIX Security ’23;	1	2024-03-16	USENIX 安全 ' 23 - 意外推动:关于源代码存放处处理机密信息战略的混合方法研究
8402	New Acoustic Keyboard Side Channel Attack Let Attackers Steal Sensitive Data	https://gbhackers.com/acoustic-keyboard-attack-data-theft/	GBHacker	news;Cyber Security News;Information Security Risks;THREATS;cyber security;Data Security;Vulnerability;	1	2024-03-18	新建音频键盘侧边频道 攻击频道 让攻击者窃取敏感数据
9901	Red Hat Security Advisory 2024-0692-03	https://packetstormsecurity.com/files/177743/RHSA-2024-0692-03.txt	packetstorm	vuln;;	1	2024-03-25	红色帽子安保咨询 2024-0692-003
9902	Red Hat Security Advisory 2024-1372-03	https://packetstormsecurity.com/files/177744/RHSA-2024-1372-03.txt	packetstorm	vuln;;	1	2024-03-25	2024-1372-03红色帽子安保咨询
18012	How to start Bug Bounty Hunting $$$$ in 2024?? | A short RoadMap	https://infosecwriteups.com/how-to-start-bug-bounty-hunting-in-2024-a-short-roadmap-9f9eeddd24ca?source=rss----7b722bfd1b8d---4	infosecwriteups	tech;money;hacking;bug-bounty;ethical-hacking;infosec;	1	2024-04-08	如何在2024年启动“虫子博恩蒂猎杀”计划?
4744	Navigating Certificate Lifecycle Management (CLM) and Mobile Device  Management (MDM) With an Effective PKI Solution	https://securityboulevard.com/2024/03/navigating-certificate-lifecycle-management-clm-and-mobile-device-management-mdm-with-an-effective-pki-solution/	securityboulevard	news;Security Bloggers Network;Certificate Services;public-key infrastructure;	1	2024-03-15	利用有效的公用钥匙基础结构解决方案,导航证书生命周期管理(CLM)和移动设备管理(MDM)
5048	FreeBuf早报 | 非洲海底光缆发生故障；中央网信办部署开展24年“清朗”专项行动	https://www.freebuf.com/news/394979.html	freebuf	news;资讯;	1	2024-03-15	FreeBuf早报 | 非洲海底光缆发生故障；中央网信办部署开展24年“清朗”专项行动
77	Fake Leather wallet app on Apple App Store is a crypto drainer	https://www.bleepingcomputer.com/news/security/fake-leather-wallet-app-on-apple-app-store-is-a-crypto-drainer/	bleepingcomputer	news;Security;Apple;CryptoCurrency;	1	2024-03-11	Apple App Store 上的假皮革钱包应用程序是一个加密排水器
5685	Quicmap: Fast, open-source QUIC protocol scanner	https://www.helpnetsecurity.com/2024/03/18/quicmap-open-source-quic-protocol-scanner/	helpnetsecurity	news;Don't miss;News;GitHub;networking;open source;penetration testing;scanning;software;	1	2024-03-18	Quicmap:快速、开放源码的QUIC协议扫描仪
198	Tax Time is Prime Time for Scammers: How to Stay Safe When Paying Your Taxes to the IRS	https://www.mcafee.com/blogs/privacy-identity-protection/tax-time-is-prime-time-for-scammers-how-to-stay-safe-when-paying-your-taxes-to-the-irs/	mcafee	news;Privacy & Identity Protection;IRS dirty dozen;tax;	1	2024-03-11	税收时间是Scammers的黄金时间:在向国税局交税时如何保持安全
271	携带恶意rootkit的github项目通过SeroXen RAT木马攻击github项目使用人员	https://xz.aliyun.com/t/14055	阿里先知实验室	news;	1	2024-03-07	携带恶意rootkit的github项目通过SeroXen RAT木马攻击github项目使用人员
132	Typosquatting Wave Shows No Signs of Abating	https://www.darkreading.com/threat-intelligence/typosquatting-wave-shows-no-signs-of-abating	darkreading	news;	1	2024-03-11	质比波显示无退缩信号
741	New-York-Home-Healthcare	http://www.ransomfeed.it/index.php?page=post_details&id_post=13626	ransomfeed	ransom;bianlian;	1	2024-03-07	纽约家庭保健
63	Alert: FBI Warns Of BlackCat Ransomware Healthcare Attack	https://securityboulevard.com/2024/03/alert-fbi-warns-of-blackcat-ransomware-healthcare-attack/	securityboulevard	news;Security Bloggers Network;BlackCat ransomware;ConnectWise Vulnerabilities;Cyber Threats;Cybersecurity Advisory;Cybersecurity Measures;Cybersecurity News;FBI warning;healthcare cybersecurity;ransomware mitigation;Ransomware Resurgence;Remote Access Security;	2	2024-03-12	警示: 联邦调查局的黑猫战警
9999	Africa Tackles Online Disinformation Campaigns During Major Election Year	https://www.darkreading.com/cyberattacks-data-breaches/africa-tackles-online-disinformation-campaigns-during-major-election-year	darkreading	news;	1	2024-03-26	非洲在主要选举年期间处理网上假冒信息运动
8648	Pokemon resets some users passwords after hacking attempts	https://buaq.net/go-229110.html	buaq	newscopy;	0	2024-03-20	黑入尝试完成后, Pokemon 重置一些用户密码
5586	Microsoft Entra ID: The Complete Guide to Conditional Access Policies	https://securityboulevard.com/2024/03/microsoft-entra-id-the-complete-guide-to-conditional-access-policies-2/	securityboulevard	news;Cloud Security;Identity & Access;Security Bloggers Network;Azure Active Directory;EntraID;identity management;Identity-First Security;research;security;Technical;	1	2024-03-17	Microsoft Entra ID: 有条件准入政策完整指南
10982	Viva Games and Vanar Chain Paving the Way for the Transformation of Web3 Gaming	https://buaq.net/go-231429.html	buaq	newscopy;	0	2024-03-30	为网络3游戏的转型铺平道路
10970	Ross Anderson, professor and famed author of ‘Security Engineering,’ passes away	https://buaq.net/go-231398.html	buaq	newscopy;	0	2024-03-30	Ross Anderson, 教授兼著名的 " 安全工程 " 作者,
10972	Why cyber hygiene requires curious talent - Clea Ostendorf - ESW #355	https://buaq.net/go-231401.html	buaq	newscopy;	0	2024-03-30	网络卫生为何需要好奇才艺-Clea Ostendorf-ESW#355
10981	15 Benefits of Online Proofing Software for Creative Teams	https://buaq.net/go-231428.html	buaq	newscopy;	0	2024-03-30	15 创作团队在线验证软件的好处
10983	Vanar L1 Blockchain Introduces Its Testnet Vanguard: Here's Why This Is an Exciting Development	https://buaq.net/go-231430.html	buaq	newscopy;	0	2024-03-30	Vanar L1 块链推出其测试网先锋:这就是为什么这是令人振奋的发展。
10988	Getting rid of a 20+ year old known vulnerability: It’s like a PSA for Runtime Security	https://buaq.net/go-231436.html	buaq	newscopy;	0	2024-03-30	摆脱20岁以上已知的脆弱性:就像运行时安全PSA
10966	WarzoneRAT Returns Post FBI Seizure: Utilizing LNK & HTA File	https://gbhackers.com/warzonerat-returns-post/	GBHacker	news;cyber security;Cyber Security News;	1	2024-03-29	FBI查获后收缴:利用LNK和HTA档案
10974	‘Darcula’ PhaaS Campaign Sinks Fangs into Victims	https://buaq.net/go-231410.html	buaq	newscopy;	0	2024-03-30	`Darcula ' PhaaS " 救教运动将爱爱的芳芳转向受害者
10985	Championing Public Dialogue: CCDH's Defense of Free Speech Rights	https://buaq.net/go-231432.html	buaq	newscopy;	0	2024-03-30	CCCH捍卫言论自由的权利
10984	Navigating Anti-SLAPP Laws: CCDH's Defense Strategy in Musk-Led X Lawsuit	https://buaq.net/go-231431.html	buaq	newscopy;	0	2024-03-30	指导反塞拉利昂人民人民党法律:人咨委在Musk-Led X Lawuit一案中的国防战略
8669	New 'Loop DoS' Attack Impacts Hundreds of Thousands of Systems	https://thehackernews.com/2024/03/new-loop-dos-attack-impacts-hundreds-of.html	feedburner	news;	1	2024-03-20	新“ Loop doS” 攻击冲击 数百个系统
10976	Activision: Enable 2FA to secure accounts recently stolen by malware	https://buaq.net/go-231413.html	buaq	newscopy;	0	2024-03-30	缩略语: 使2FA能够安全最近被恶意软件窃取的账户
10977	xz 软件包被植入后门	https://buaq.net/go-231419.html	buaq	newscopy;	0	2024-03-30	xz 软件包被植入后门
10978	All about the xz-utils backdoor	https://buaq.net/go-231425.html	buaq	newscopy;	0	2024-03-30	所有关于后门的 xz- utlils
9914	US sanctions alleged Chinese state hackers for attacks on critical infrastructure	https://therecord.media/us-sanctions-chinese-hackers-infrastructure-attacks	therecord	ransom;China;News;Nation-state;Government;	4	2024-03-25	美国制裁指控中国国家黑客攻击重要基础设施
4856	Sinking Section 702 Wiretap Program Offered One Last Lifeboat	https://www.wired.com/story/section-702-safe-act-compromise/	wired	news;Security;Security / National Security;Security / Privacy;Politics / Policy;	1	2024-03-15	提供最后一艘救生艇的无线电节目
10967	Beware Of Weaponized Air Force invitation PDF Targeting Indian Defense And Energy Sectors	https://gbhackers.com/weaponized-air-force-invitation-pdf-indian-defense-energy/	GBHacker	news;Cyber Attack;Data Breach;Malware;Cyberespionage;Indian Defense;	1	2024-03-29	人民保卫部队以印度国防和能源部门为目标
10312	黑客利用 Ray 框架漏洞，入侵服务器，劫持资源	https://www.freebuf.com/articles/396057.html	freebuf	news;	3	2024-03-27	黑客利用 Ray 框架漏洞，入侵服务器，劫持资源
18014	Securing LLM-Based Systems with SecGPT: A Dive into Its Purpose-Driven Architecture	https://infosecwriteups.com/securing-llm-based-systems-with-secgpt-a-dive-into-its-purpose-driven-architecture-4407a7f49007?source=rss----7b722bfd1b8d---4	infosecwriteups	tech;cybersecurity;secgpt;llm;ai;technology;	1	2024-04-08	与SecGPT一起确保基于LLM的系统的安全:潜入其目的驱动的建筑
18013	picoCTF 2024 — Write-up — Forensics	https://infosecwriteups.com/picoctf-2024-write-up-forensics-c471e79e6af9?source=rss----7b722bfd1b8d---4	infosecwriteups	tech;walkthrough;ctf;ctf-writeup;forensics;picoctf;	1	2024-04-08	PicoCCTF 2024 - 编写 - 法医
10975	Malicious backdoor code embedded in popular Linux tool, CISA and Red Hat warn	https://buaq.net/go-231412.html	buaq	newscopy;	0	2024-03-30	Linux 工具、 CISA 和Red Hat 警告
10979	Prisma Finance crypto theft caps strange week of platform breaches	https://buaq.net/go-231426.html	buaq	newscopy;	0	2024-03-30	普里斯马金融秘密偷盗上限 奇异的一周 破坏平台的一周
10971	Electric Sheep, Exchange, Darcula, NuGet, Rockwell, FTX, Aaran Leyland, and More - SWN #373	https://buaq.net/go-231400.html	buaq	newscopy;	0	2024-03-30	电动羊、交换机、Darcula、Nuget、Rockwell、FTX、Aaran Leyland和More - SWN 373
10973	xz/liblzma Backdoored	https://buaq.net/go-231403.html	buaq	newscopy;	0	2024-03-30	xz/liblzma 后门
26567	赵明称荣耀Magic6有三个最好 	https://s.weibo.com/weibo?q=%23赵明称荣耀Magic6有三个最好 %23	sina.weibo	hotsearch;weibo	1	2024-01-03	赵明称荣耀Magic6有三个最好
10987	Two-Step Analysis of the Anti-SLAPP Statute in California, Invoked in X’s Lawsuit Against Ccdh	https://buaq.net/go-231434.html	buaq	newscopy;	0	2024-03-30	对加利福尼亚州反塞拉利昂人民党法规的两步分析,在X的《反对Ccdh法律诉讼案》中援引
26568	赵明称荣耀Magic就是为AI而生 	https://s.weibo.com/weibo?q=%23赵明称荣耀Magic就是为AI而生 %23	sina.weibo	hotsearch;weibo	1	2024-03-18	赵明称荣耀Magic就是为AI而生
26569	赵明称荣耀手机运动摄影遥遥领先 	https://s.weibo.com/weibo?q=%23赵明称荣耀手机运动摄影遥遥领先 %23	sina.weibo	hotsearch;weibo	1	2024-03-18	赵明称荣耀手机运动摄影遥遥领先
10980	Frequently Asked Questions About CVE-2024-3094, A Backdoor in XZ Utils	https://buaq.net/go-231427.html	buaq	newscopy;	0	2024-03-30	关于CVE 2024-3094, XZ 用户端的后门的常见问题
26570	邓文迪看小米SU7 	https://s.weibo.com/weibo?q=%23邓文迪看小米SU7 %23	sina.weibo	hotsearch;weibo	1	2024-04-01	邓文迪看小米SU7
26571	部分滴滴司机开始提现 	https://s.weibo.com/weibo?q=%23部分滴滴司机开始提现 %23	sina.weibo	hotsearch;weibo	1	2023-11-28	部分滴滴司机开始提现
10155	Hackers Hit Indian Defense, Energy Sectors with Malware Posing as Air Force Invite	https://thehackernews.com/2024/03/hackers-target-indian-defense-and.html	feedburner	news;	1	2024-03-27	黑客击打印度国防 能源部门 马拉威波斯作为空军邀请
19	Exit Scam: BlackCat Ransomware Group Vanishes After $22 Million Payout	https://thehackernews.com/2024/03/exit-scam-blackcat-ransomware-group.html	feedburner	news;	2	2024-03-06	退出 Scam: BlackCat Ransomware Group 在2 200万美元支付后消失的黑Cat Ransomware集团
10140	Finland confirms APT31 hackers behind 2021 parliament breach	https://buaq.net/go-230691.html	buaq	newscopy;	0	2024-03-27	芬兰确认,APT31黑客在2021年议会违约后
9436	USENIX Security ’23 – Jinwen Wang, Yujie Wang, Ao Li, Yang Xiao, Ruide Zhang, Wenjing Lou, Y. Thomas Hou, Ning Zhang – ARI: Attestation of Real-time Mission Execution Integrity	https://securityboulevard.com/2024/03/usenix-security-23-jinwen-wang-yujie-wang-ao-li-yang-xiao-ruide-zhang-wenjing-lou-y-thomas-hou-ning-zhang-ari-attestation-of-real-time-mission-execution-integrity/	securityboulevard	news;Security Bloggers Network;Open Access Research;Security Conferences;Security Research;USENIX;USENIX Security ’23;	1	2024-03-24	USENIX 安全 23 — — 金文王、王玉洁、秋李、杨晓、张瑞德、张文京、吴文京卢、Y.托马斯霍、张宁 — — 阿里:实时任务执行完整性的证明
9784	USENIX Security ’23 – Lukas Lamster, Martin Unterguggenberger, David Schrammel, and Stefan Mangard – HashTag: Hash-based Integrity Protection for Tagged Architectures	https://securityboulevard.com/2024/03/usenix-security-23-lukas-lamster-martin-unterguggenberger-david-schrammel-and-stefan-mangard-hashtag-hash-based-integrity-protection-for-tagged-architectures/	securityboulevard	news;Security Bloggers Network;Open Access Research;Security Conferences;Security Research;USENIX;USENIX Security ’23;	1	2024-03-25	USENIX 安全 23 — — Lukas Lamster, Martin Untergugggenberger, David Schrammel和Stefan Mangard — — HashTag: 挂钩建筑的以散字为基础的完整保护
9985	Free VPN apps on Google Play turned Android phones into proxies	https://www.bleepingcomputer.com/news/security/free-vpn-apps-on-google-play-turned-android-phones-into-proxies/	bleepingcomputer	news;Security;Google;Mobile;	2	2024-03-26	Google Play的免费 VPN 应用程序将安打手机转换为代理
10989	From Underground to Overground	https://buaq.net/go-231441.html	buaq	newscopy;	0	2024-03-30	从地下到地面
18015	Shield your System — XZ Utils Backdoor (Linux Distribution)	https://infosecwriteups.com/shield-your-system-xz-utils-backdoor-linux-distribution-54583b071ccc?source=rss----7b722bfd1b8d---4	infosecwriteups	tech;linux;cybersecurity;vulnerability;hacking;bug-bounty;	1	2024-04-08	盾牌您的系统 - XZ 工具后门( Linux 分发)
9973	Datto Networking and VSA 10: Your Shortcut to Smarter Networks	https://securityboulevard.com/2024/03/datto-networking-and-vsa-10-your-shortcut-to-smarter-networks/	securityboulevard	news;Security Bloggers Network;Datto Networking and VSA integration;Integrated Solutions;integration;System Integration;VSA Datto Networking Integration;Workflow integration;	1	2024-03-26	Dattto 网络化和 VSA 10: 您对智能网络的快捷键
18016	The Power of Open Source Intelligence | OSINT | CTF Newbies	https://infosecwriteups.com/the-power-of-open-source-intelligence-osint-ctf-newbies-b39db0421dd4?source=rss----7b722bfd1b8d---4	infosecwriteups	tech;htb;osint;ctf-walkthrough;ctf;cybersecurity;	1	2024-04-08	开放源码情报力量 OSINT CTF 新菌
48	VMware Issues Security Patches for ESXi, Workstation, and Fusion Flaws	https://thehackernews.com/2024/03/vmware-issues-security-patches-for-esxi.html	feedburner	news;	1	2024-03-06	用于ESXi、工作站和融合法的VM软件问题安全补丁
9535	Illinois county government, local college affected by ransomware attacks	https://therecord.media/illinois-county-gov-college-hit-with-ransomware	therecord	ransom;News;Government;Cybercrime;	2	2024-03-22	伊利诺伊州州政府、受赎金软件袭击影响的地方学院
148	From refresh token theft to global admin	https://threats.wiz.io/all-incidents/from-refresh-token-theft-to-global-admin	wizio	incident;	1	2024-02-28	从物证盗窃到全球行政
2973	Only 13% of medical devices support endpoint protection agents	https://www.helpnetsecurity.com/2024/03/14/medical-devices-cybersecurity-concerns/	helpnetsecurity	news;News;Claroty;cybersecurity;healthcare;report;survey;threats;	1	2024-03-14	只有13%的医疗设备支持端点保护人员
308	Inside Registered Agents Inc., the Shadowy Firm Pushing the Limits of Business Privacy	https://www.wired.com/story/registered-agents-inc-fake-personas/	wired	news;Security;Security / Privacy;Business;	1	2024-03-05	推动商业隐私界限的影子公司 " 内部注册代理人公司 "
9975	One More Time on SIEM Telemetry / Log Sources …	https://securityboulevard.com/2024/03/one-more-time-on-siem-telemetry-log-sources/	securityboulevard	news;Analytics & Intelligence;Security Bloggers Network;SIEM;threat detection;	1	2024-03-26	在SIM遥测/日志来源中再次使用SIM遥测/日志来源.。
400	Persistence – Explorer	https://pentestlab.blog/2024/03/05/persistence-explorer/	pentestlab	tech;Persistence;DLL Hijacking;explorer.exe;Red Team;	1	2024-03-05	持久性 - 探索者
648	Erwat	http://www.ransomfeed.it/index.php?page=post_details&id_post=13524	ransomfeed	ransom;dragonforce;	1	2024-02-29	Erwat( 土瓦特)
416	Circumventing Common SSRF Defenses: A Deep Dive into Strategies and Techniques	https://infosecwriteups.com/circumventing-common-ssrf-defenses-a-deep-dive-into-strategies-and-techniques-c9607f1bb61e?source=rss----7b722bfd1b8d---4	infosecwriteups	tech;security;cybersecurity;bug-bounty;hacking;careers;	1	2024-03-04	环绕着共同的SSRF防御:对战略和技术的深入潜水
440	WordPress Plugin Flaw Exposes 200,000+ Websites to XSS Attacks	https://gbhackers.com/wordpress-plugin-flaw/	GBHacker	news;Cyber Attack;Cyber Security News;	1	2024-03-12	WordPress 插件 Flaw 展出20万个网站,用于 XSS 攻击
13718	Pentagon Releases Cybersecurity Strategy To Strengthen Defense Industrial Base 	https://gbhackers.com/pentagon-cybersecurity-defense-industrial-base/	GBHacker	news;cyber security;Incident Response;Vulnerability Analysis;Cybersecurity Strategy;Defense Industrial Base;	1	2024-04-02	五角大楼发布加强国防工业基地的网络安全战略
5571	timwhitez starred awesome-cs-tutorial	https://buaq.net/go-228684.html	buaq	newscopy;	0	2024-03-18	immwhitez 明星 真棒 -cS - 研究
8804	RaaS groups increasing efforts to recruit affiliates	https://www.helpnetsecurity.com/2024/03/20/raas-recruit-affiliates/	helpnetsecurity	news;Don't miss;Hot stuff;News;cybercrime;cybercriminals;dark web;GuidePoint Security;ransomware;research;	1	2024-03-20	RaaS 组织起来,加大招募子公司的力度
21236	GSMA releases Mobile Threat Intelligence Framework	https://www.helpnetsecurity.com/2024/04/10/gsma-mobile-threat-intelligence-framework/	helpnetsecurity	news;News;framework;GSMA;MITRE;	1	2024-04-10	GSMA释放流动威胁情报框架
18046	Change-HealthCare---OPTUM-Group---United-HealthCare-Group	http://www.ransomfeed.it/index.php?page=post_details&id_post=14148	ransomfeed	ransom;ransomhub;	1	2024-04-08	改革-保健-保健-OPTUM-小组-联合国保健-保健-小组
16097	Skyrocket Your Bug Bounty Success Using These Crawlers	https://infosecwriteups.com/skyrocket-your-bug-bounty-success-using-these-crawlers-03ce28efb498?source=rss----7b722bfd1b8d---4	infosecwriteups	tech;bug-bounty-tips;cybersecurity;bug-bounty;crawling;information-security;	1	2024-04-05	利用这些捕鼠者 让你的虫子成功得分天花飞
16101	IT Leaders Can’t Stop AI and Deepfake Scams as They Top the List of Most Frequent Attacks	https://blog.knowbe4.com/it-leaders-cant-stop-ai-and-deepfakes-scams	knowbe4	news;Social Engineering;Phishing;Security Awareness Training;Security Culture;	1	2024-04-04	IT领导者无法阻止AI和Depfake Scams,
18921	HHS: Health Care IT Helpdesks Under Attack in Voice Scams	https://securityboulevard.com/2024/04/hhs-heath-care-it-helpdesks-under-attack-in-voice-scams/	securityboulevard	news;Cloud Security;Cybersecurity;Data Privacy;Data Security;Featured;Identity & Access;Industry Spotlight;Network Security;News;Security Boulevard (Original);Social - Facebook;Social - LinkedIn;Social - X;Social Engineering;Spotlight;Threat Intelligence;cyberattacks in healthcare;Generative AI risks;healthcare;helpdesk;MFA;social engineering;SpearPhishing;Voice Cloning;	1	2024-04-08	HHS: 健康保健信息技术服务台
20590	SE Labs Annual Security Awards 2024	https://securityboulevard.com/2024/04/se-labs-annual-security-awards-2024/	securityboulevard	news;DevOps;SBN News;Security Bloggers Network;2024;awards;Cyber Security;How We Test;Other;security testing;standards;test results;Threat Intelligence;	1	2024-04-09	2024年SE实验室年度安全赔偿金
15558	《深化智慧城市发展 推进城市全域数字化转型的指导意见（征求意见稿）》正式发布	https://www.freebuf.com/news/396924.html	freebuf	news;资讯;	1	2024-04-03	《深化智慧城市发展 推进城市全域数字化转型的指导意见（征求意见稿）》正式发布
125	Southern Company Builds SBOM for Electric Power Substation	https://www.darkreading.com/ics-ot-security/southern-company-builds-a-power-substation-sbom	darkreading	news;	1	2024-03-06	南方公司为电力分电站建造SBOM
197	How to Protect Yourself From Identity Theft After a Data Breach	https://www.mcafee.com/blogs/privacy-identity-protection/how-to-protect-yourself-from-identity-theft-after-a-data-breach/	mcafee	news;Privacy & Identity Protection;identity theft;credit card fraud;data protection;Data Breach;cybersecurity;ShinyHunter;	1	2024-03-07	如何保护自己在数据泄露后免遭身份盗窃
696	Eastern-Rio-Blanco-Metropolitan	http://www.ransomfeed.it/index.php?page=post_details&id_post=13578	ransomfeed	ransom;medusa;	1	2024-03-03	东里约-布兰科-大都市
656	Crystal-Window--Door-Systems	http://www.ransomfeed.it/index.php?page=post_details&id_post=13535	ransomfeed	ransom;dragonforce;	1	2024-03-01	水晶窗口-门-门-系统
18017	VulnHub - Kioptrix: Level 4 (1.3) (#4)	https://infosecwriteups.com/vulnhub-kioptrix-level-4-1-3-4-ad25b000b058?source=rss----7b722bfd1b8d---4	infosecwriteups	tech;security;ctf;vulnhub;linux;	1	2024-04-08	VulnHub - Kioptrix: 4级(1.3) (# 4)
16072	TruCentive Enhances Privacy With HIPAA Compliant Personal Information De-identification	https://www.darkreading.com/cyber-risk/trucentive-enhances-privacy-with-hipaa-compliant-personal-information-de-identification	darkreading	news;	1	2024-04-03	利用HIPAA兼容的个人信息增强隐私
18079	WiCyS: A champion for a more diverse cybersecurity workforce	https://www.helpnetsecurity.com/2024/04/08/wicys-women-in-cybersecurity-workforce/	helpnetsecurity	news;Don't miss;Features;Hot stuff;News;cybersecurity talent;education;skill development;WiCyS;	1	2024-04-08	WICYS:网络安全工作人员队伍多样化的倡导者
18803	New NPSA 2024 Guidelines for Mitigating Insider Risk	https://securityboulevard.com/2024/04/new-npsa-2024-guidelines-for-mitigating-insider-risk/	securityboulevard	news;Security Bloggers Network;Threats & Breaches;advice;Best Practices;Cybersecurity;insider threat;next gen security;security;Security Research;zero trust;	1	2024-04-06	新的核动力源A 2024年新的减轻内鬼风险准则
18045	PalauGov	http://www.ransomfeed.it/index.php?page=post_details&id_post=14147	ransomfeed	ransom;dragonforce;	1	2024-04-07	帕劳Gov
9049	pathologie-bochumde	http://www.ransomfeed.it/index.php?page=post_details&id_post=13886	ransomfeed	ransom;lockbit3;	1	2024-03-21	等离子体
4781	Sophos: Over 75% of Cyber Incidents Target Small Businesses	https://blog.knowbe4.com/sophos-over-75-of-cyber-incidents-target-small-businesses	knowbe4	news;Phishing;Security Culture;	1	2024-03-15	索福斯:75%以上的网络事件针对小企业
1163	BlackCloak Identifies Rising Cyber Threats Against Crypto-Invested Venture Capital and Private Equity Firm	https://securityboulevard.com/2024/03/blackcloak-identifies-rising-cyber-threats-against-crypto-invested-venture-capital-and-private-equity-firm/	securityboulevard	news;Cyberlaw;Security Bloggers Network;Vulnerabilities;Business Insights;Cyber Threats;cybercrime;	1	2024-03-12	确定对加密投资风险资本和私人股权公司的网络威胁不断上升
1461	Red Hat Security Advisory 2024-1250-03	https://packetstormsecurity.com/files/177536/RHSA-2024-1250-03.txt	packetstorm	vuln;;	1	2024-03-12	红帽子安保咨询 2024-1250-03
10678	Dormakaba Locks Used in Millions of Hotel Rooms Could Be Cracked in Seconds	https://thehackernews.com/2024/03/dormakaba-locks-used-in-millions-of.html	feedburner	news;	1	2024-03-29	数以百万计的旅馆房间使用的Dormakaba锁 可能以秒计被破碎
8821	vm2 3.9.19 Sandbox Escape	https://cxsecurity.com/issue/WLB-2024030048	cxsecurity	vuln;	1	2024-03-20	3.9.19 沙箱逃逸
1455	Human Resource Management System 1.0 SQL Injection	https://packetstormsecurity.com/files/177530/hrms10emp-sql.txt	packetstorm	vuln;;	1	2024-03-12	人力资源管理系统1.0 SQL 注射
8820	SolarView Compact 6.00 Command Injection	https://cxsecurity.com/issue/WLB-2024030045	cxsecurity	vuln;	1	2024-03-20	6.00 指令注射
1260	硬核 | TLS指纹在Bot对抗中的应用实践	https://www.freebuf.com/articles/web/393136.html	freebuf	news;Web安全;	1	2024-03-08	硬核 | TLS指纹在Bot对抗中的应用实践
1465	Red Hat Security Advisory 2024-1269-03	https://packetstormsecurity.com/files/177540/RHSA-2024-1269-03.txt	packetstorm	vuln;;	1	2024-03-12	Red Hat Security Advisory 2024-1269-03
9969	2024 IT Risk and Compliance Benchmark Report Findings: Why Unifying Risk and Compliance Work Is No Longer Optional	https://securityboulevard.com/2024/03/2024-it-risk-and-compliance-benchmark-report-findings-why-unifying-risk-and-compliance-work-is-no-longer-optional/	securityboulevard	news;CISO Suite;Governance, Risk & Compliance;Security Bloggers Network;Blog Posts;Compliance Operations;risk management;	1	2024-03-26	2024 信息技术风险和合规基准报告调查结果:为什么统一风险和合规工作不具有更长期的可选性
4782	Vulnerability in aiohttp Targeted by ShadowSyndicate	https://threats.wiz.io/all-incidents/vulnerability-in-aiohttp-targeted-by-shadowsyndicate	wizio	incident;	1	2024-03-17	暗影辛迪加针对的Aiohttp中的脆弱性
1456	Red Hat Security Advisory 2024-1240-03	https://packetstormsecurity.com/files/177531/RHSA-2024-1240-03.txt	packetstorm	vuln;;	1	2024-03-12	红帽子安保咨询 2024-1240-03
8817	Glassdoor Wants to Know Your Real Name	https://www.wired.com/story/glassdoor-wants-to-know-your-real-name/	wired	news;Business;Business / Social Media;Security;Security / Privacy;	1	2024-03-20	玻璃门想知道你的真名
1537	Gtfocli - GTFO Command Line Interface For Easy Binaries Search Commands That Can Be Used To Bypass Local Security Restrictions In Misconfigured Systems	https://buaq.net/go-227720.html	buaq	newscopy;	0	2024-03-13	Gtfocli - GTfocli - GTFO 用于可用来绕过错误配置系统中的本地安全限制的简易二进制搜索命令的 GTFO 命令线界面
4779	Organizations Are Vulnerable to Image-based and QR Code Phishing	https://blog.knowbe4.com/organizations-vulnerable-to-image-based-qr-code-phishing	knowbe4	news;Social Engineering;Phishing;Security Culture;	1	2024-03-14	易受到图像和QR法钓钓鱼影响的组织
10965	IT and security Leaders Feel Ill-Equipped to Handle Emerging Threats: New Survey	https://gbhackers.com/it-and-security-leaders/	GBHacker	news;cyber security;Cyber Security News;	1	2024-03-29	信息技术和安全领导者感到无力应付新出现的威胁:新的调查
1203	How to Identify a Cyber Adversary: Standards of Proof	https://www.darkreading.com/cyberattacks-data-breaches/how-to-identify-cyber-adversary-standards-of-proof	darkreading	news;	1	2024-03-12	如何识别网络反竞争:证据标准
1230	'Magnet Goblin' Exploits Ivanti 1-Day Bug in Mere Hours	https://www.darkreading.com/threat-intelligence/magnet-goblin-exploits-ivanti-1-day-bug-mere-hours	darkreading	news;	1	2024-03-12	"Magnet Goblin" 爆炸 Ivanti 1天的虫子在短短的时间里
4905	How North Korean Hackers Are Robbing Millions from Banks	https://infosecwriteups.com/how-north-korean-hackers-are-robbing-millions-from-banks-1487ffac83c9?source=rss----7b722bfd1b8d---4	infosecwriteups	tech;kim-jong-un;north-korea;donald-trump;hacking;nuclear-weapons;	3	2024-03-15	北韩黑客是如何从银行抢走数百万的
10880	Finding software flaws early in the development process provides ROI	https://www.helpnetsecurity.com/2024/03/29/development-process-software-flaws/	helpnetsecurity	news;Don't miss;Hot stuff;News;cybersecurity;Probely;security assessment;security testing;software;software development;	1	2024-03-29	开发过程初期发现软件缺陷,提供了ROI
21272	MDR for Better Office 365 Security	https://securityboulevard.com/2024/04/mdr-for-better-office-365-security/	securityboulevard	news;Security Bloggers Network;Blog;	1	2024-04-09	MDR 改善办公室的MDR 安全 365
10275	lifelinedatacenterscom	http://www.ransomfeed.it/index.php?page=post_details&id_post=13971	ransomfeed	ransom;lockbit3;	1	2024-03-27	生命线数据中心通信
10442	Behind the Scenes: The Art of Safeguarding Non-Human Identities	https://thehackernews.com/2024/03/behind-scenes-art-of-safeguarding-non.html	feedburner	news;	1	2024-03-28	场景背后:保护非人类身份的艺术
9982	$700 cybercrime software turns Raspberry Pi into an evasive fraud tool	https://www.bleepingcomputer.com/news/security/700-cybercrime-software-turns-raspberry-pi-into-an-evasive-fraud-tool/	bleepingcomputer	news;Security;Hardware;	1	2024-03-26	700美元 网络犯罪软件将Raspberry Pi 变成一个逃避欺诈的工具
16167	Automating and maintaining SBOMs	https://securityboulevard.com/2024/04/automating-and-maintaining-sboms/	securityboulevard	news;Security Bloggers Network;Automation;SBOM;SBOM Manager;software bill of materials;	1	2024-04-05	自动操作和维护 SBOM 自动操作和维护
9050	Henry-County-Illinois	http://www.ransomfeed.it/index.php?page=post_details&id_post=13887	ransomfeed	ransom;medusa;	1	2024-03-21	亨利·夸迪-伊利诺斯
10447	Darcula Phishing Network Leveraging RCS and iMessage to Evade Detection	https://thehackernews.com/2024/03/darcula-phishing-network-leveraging-rcs.html	feedburner	news;	1	2024-03-28	将RCS和iMessage用于Evade探测
10453	Linux Version of DinodasRAT Spotted in Cyber Attacks Across Several Countries	https://thehackernews.com/2024/03/linux-version-of-dinodasrat-spotted-in.html	feedburner	news;	1	2024-03-28	《DinodasRAT》Linux版本,
10167	Introducing Real-Time Identity-Centric Risk Profile – Designed to Help You Outpace Your Attackers	https://securityboulevard.com/2024/03/introducing-real-time-identity-centric-risk-profile-designed-to-help-you-outpace-your-attackers/	securityboulevard	news;Identity & Access;Security Bloggers Network;Identity Centric;identity management;Identity Security Posture Management;ISPM;ITDR;Market;Product;	1	2024-03-27	引入实时身份中心风险简介 — — 旨在帮助你超越攻击者
18008	Breaking the Light Speed Barrier: The Revolutionary FLIP Protocol Unveiled	https://infosecwriteups.com/breaking-the-light-speed-barrier-the-revolutionary-flip-protocol-unveiled-7c4538c7651e?source=rss----7b722bfd1b8d---4	infosecwriteups	tech;networking;tcp;flip;technology;protocol;	1	2024-04-08	打破轻速障碍:革命性的FLIP议定书
8352	Hack The Box: Procnet Sherlock Walkthrough – Hard Difficulty	https://threatninja.net/2024/03/hack-the-box-procnet-sherlock-walkthrough-hard-difficulty/	threatninja	sectest;Sherlock Hard;	1	2024-03-19	Hack The box: Procnet 夏洛克·卡罗尔·卡通 — — 困难重重
401	CanaryTokenScanner - Script Designed To Proactively Identify Canary Tokens Within Microsoft Office Documents And Acrobat Reader PDF (docx, xlsx, pptx, pdf)	http://www.kitploit.com/2024/02/canarytokenscanner-script-designed-to.html	kitploit	tool;Canary Token Detection;Canarytokens;CanaryTokenScanner;Honeypots;HoneyToken;	1	2024-02-28	加那利TokenScanner - 设计用于预先识别微软办公室文档和Acrobat阅读器PDF内加那利调的脚本(docx, xlsx, pptx, pdf)
10038	17,000+ Microsoft Exchange servers in Germany are vulnerable to attack, BSI warns	https://www.helpnetsecurity.com/2024/03/26/vulnerable-microsoft-exchange-servers/	helpnetsecurity	news;Don't miss;Hot stuff;News;BSI;enterprise;Germany;Microsoft Exchange;Shadowserver;vulnerability;	1	2024-03-26	德国的17,000+微软交换服务器易受攻击,BSI警告
10276	West-Monroe	http://www.ransomfeed.it/index.php?page=post_details&id_post=13972	ransomfeed	ransom;play;	1	2024-03-27	西门
9781	The Next Evolution of IAM: How Generative AI is Transforming Identity and Access	https://securityboulevard.com/2024/03/the-next-evolution-of-iam-how-generative-ai-is-transforming-identity-and-access/	securityboulevard	news;Identity & Access;Security Bloggers Network;AI (Artificial Intelligence);Authentication;Automation;CIAM;Cybersecurity;iam;	1	2024-03-25	IAM的下一个演进:如何创造的AI正在改变身份和获取途径
9437	USENIX Security ’23 – Yijie Bai, Yanjiao Chen, Hanlei Zhang, Wenyuan Xu, Haiqin Weng, Dou Goodman – VILLAIN: Backdoor Attacks Against Vertical Split Learning	https://securityboulevard.com/2024/03/usenix-security-23-yijie-bai-yanjiao-chen-hanlei-zhang-wenyuan-xu-haiqin-weng-dou-goodman-villain-backdoor-attacks-against-vertical-split-learning/	securityboulevard	news;Security Bloggers Network;Open Access Research;Security Conferences;USENIX;USENIX Security ’23;	1	2024-03-23	USENIX 安全 23 — — Yijie Bai 、 陈燕尾、 张汉莱、 Wenyuuan Xu、 Haiqin Weng、 Dou Goodman — — Villain: 对纵向分化学习的后门攻击
10448	Finland Blames Chinese Hacking Group APT31 for Parliament Cyber Attack	https://thehackernews.com/2024/03/finland-blames-chinese-hacking-group.html	feedburner	news;	5	2024-03-28	Finland Blames 中文黑客集团 APT31 用于议会网络攻击
1387	US Lawmaker Cited NYC Protests in a Defense of Warrantless Spying	https://www.wired.com/story/hpsci-us-protests-section-702-presentation/	wired	news;Security;Security / National Security;Security / Privacy;Politics / Policy;	1	2024-03-12	美国立法者以纽约市民抗议为由,
4855	Automakers Are Telling Your Insurance Company How You Really Drive	https://www.wired.com/story/automakers-sharing-driver-data-security-roundup/	wired	news;Security;Security / Cyberattacks and Hacks;Security / National Security;Security / Privacy;Security / Security News;	1	2024-03-16	汽车制造商正在告诉您的保险公司 您如何真正驾驶
16071	How Soccer's 2022 World Cup in Qatar Was Nearly Hacked	https://www.darkreading.com/cyber-risk/how-the-2022-qatar-world-cup-soccer-was-nearly-hacked	darkreading	news;	1	2024-04-03	卡塔尔2022年世界杯足球赛近乎被黑
26339	小米汽车手机支架 	https://s.weibo.com/weibo?q=%23小米汽车手机支架 %23	sina.weibo	hotsearch;weibo	1	2024-03-29	小米汽车手机支架
26345	小米汽车称没有丐中丐版 	https://s.weibo.com/weibo?q=%23小米汽车称没有丐中丐版 %23	sina.weibo	hotsearch;weibo	1	2024-01-08	小米汽车称没有丐中丐版
26352	小米汽车销售称凌晨2点下班7点又上班 	https://s.weibo.com/weibo?q=%23小米汽车销售称凌晨2点下班7点又上班 %23	sina.weibo	hotsearch;weibo	1	2024-03-30	小米汽车销售称凌晨2点下班7点又上班
21372	AI risks under the auditor’s lens more than ever	https://www.helpnetsecurity.com/2024/04/10/ai-risks-audit-plan-video/	helpnetsecurity	news;Don't miss;Hot stuff;Video;artificial intelligence;auditing;compliance;cybersecurity;data security;Gartner;Generative AI;privacy;risk;video;	1	2024-04-10	审计师眼下的AI风险比以往任何时候更加严重
10458	New ZenHammer Attack Bypasses RowHammer Defenses on AMD CPUs	https://thehackernews.com/2024/03/new-zenhammer-attack-bypasses-rowhammer.html	feedburner	news;	1	2024-03-28	新的ZenHammer 攻击绕过通道
10460	Telegram Offers Premium Subscription in Exchange for Using Your Number to Send OTPs	https://thehackernews.com/2024/03/telegram-offers-premium-subscription-in.html	feedburner	news;	1	2024-03-28	
8679	Five Key Findings from the 2023 FBI Internet Crime Report	https://securityboulevard.com/2024/03/five-key-findings-from-the-2023-fbi-internet-crime-report/	securityboulevard	news;Security Bloggers Network;Cyber Security;Threats and Trends;	1	2024-03-20	《2023年联邦调查局因特网犯罪报告》的五项主要调查结果
10466	探秘 Zyxel 设备：固件提取分析	https://paper.seebug.org/3137/	seebug	news;经验心得;IoT安全;404专栏;	1	2024-03-27	探秘 Zyxel 设备：固件提取分析
9054	excellifecoachingcom	http://www.ransomfeed.it/index.php?page=post_details&id_post=13896	ransomfeed	ransom;killsec;	1	2024-03-21	超生分氯辛烷
8717	AI Won't Solve Cybersecurity's Retention Problem	https://www.darkreading.com/cybersecurity-operations/ai-wont-solve-cybersecuritys-retention-problem	darkreading	news;	1	2024-03-20	AI不会解决网络安全 的留存问题
8719	Deloitte Launches CyberSphere Platform to Simplify Cyber Operations for Clients	https://www.darkreading.com/cybersecurity-operations/deloitte-launches-cybersphere-platform-to-simplify-cyber-operations-for-clients	darkreading	news;	1	2024-03-20	Deloitte 发射网络空间平台,为客户简化网络操作
8921	Over 800 npm Packages Found with Discrepancies, 18 Exploitable to 'Manifest Confusion'	https://thehackernews.com/2024/03/over-800-npm-packages-found-with.html	feedburner	news;	1	2024-03-21	发现800多个 npm 套件, 与差异有关, 18 个可爆炸到“ 操纵混集 ”
8802	DataDome Account Protect provides security for login and registration endpoints	https://www.helpnetsecurity.com/2024/03/20/datadome-account-protect/	helpnetsecurity	news;Industry news;DataDome;	1	2024-03-20	DataDome账户保护为登录和登记终端点提供安保
8730	Russian Intelligence Targets Victims Worldwide in Rapid-Fire Cyberattacks	https://www.darkreading.com/threat-intelligence/russian-intelligence-targets-victims-worldwide-in-rapid-fire-cyberattacks	darkreading	news;	3	2024-03-20	俄罗斯情报组织在快速火力网络攻击中以全世界受害者为目标
8935	DataDome Releases Ruby Server-Side Integration	https://securityboulevard.com/2024/03/datadome-releases-ruby-server-side-integration/	securityboulevard	news;Security Bloggers Network;Bot & Fraud Protection;bot detection;Engineering;integrations;Product updates;	1	2024-03-21	DataDome 发布 Ruby 服务器- Side 整合
8795	FreeBuf 早报 | 27年中国网安市场将超200亿美元；英国国防部长专机信号中断半小时	https://www.freebuf.com/news/395395.html	freebuf	news;资讯;	1	2024-03-20	FreeBuf 早报 | 27年中国网安市场将超200亿美元；英国国防部长专机信号中断半小时
9929	Microsoft To Ban 50+ Products For Users In Russia	https://gbhackers.com/microsoft-bans-products-russia/	GBHacker	news;Cloud;Cyber Security News;Microsoft;Cloud Service Disruption;Data Migration Strategies;Sanctions Impact;	3	2024-03-25	微软 微软 禁止 50+ 俄罗斯用户产品
8563	Kasada introduces CDN edge API integrations to block abuse and online fraud	https://www.helpnetsecurity.com/2024/03/19/kasada-api-integrations/	helpnetsecurity	news;Industry news;Kasada;	1	2024-03-19	Kasada介绍CDN边缘API整合,以阻止滥用和网上欺诈
8818	A prescription for privacy protection: Exercise caution when using a mobile health app	https://www.welivesecurity.com/en/privacy/prescription-privacy-protection-exercise-caution-mobile-health-app/	eset	news;	1	2024-03-19	隐私保护规定:在使用移动健康应用程序时谨慎行事
8589	Backdrop CMS 1.23.0 Cross Site Scripting	https://packetstormsecurity.com/files/177641/backdropcms1230-xss.txt	packetstorm	vuln;;	1	2024-03-19	返回 CMS 1.23.0 跨站点脚本
9930	Russian Hackers Attacking Political Parties In Recent Cyber Attacks	https://gbhackers.com/russian-hackers-attack-political-parties/	GBHacker	news;Cyber Attack;cyber security;Incident Response;Political Espionage;Russian Hackers;	3	2024-03-25	俄国黑客组织在最近网络攻击中攻击政党
8853	Lektor Static CMS 3.3.10 Arbitrary File Upload / Remote Code Execution	https://packetstormsecurity.com/files/177708/lektorcms3310-uploadexec.txt	packetstorm	vuln;;	1	2024-03-20	Lektor静态 CMS 3.3.10 任意文件上传/远程代码执行
8806	Zoom Compliance Manager helps organizations fulfill regulatory requirements	https://www.helpnetsecurity.com/2024/03/20/zoom-compliance-manager/	helpnetsecurity	news;Industry news;Zoom;	1	2024-03-20	缩放合规主管帮助各组织满足监管要求
8927	U.S. Sanctions Russians Behind 'Doppelganger' Cyber Influence Campaign	https://thehackernews.com/2024/03/us-sanctions-russians-behind.html	feedburner	news;	3	2024-03-21	美国制裁“二重身”网络影响运动背后的俄罗斯人
8837	Red Hat Security Advisory 2024-1422-03	https://packetstormsecurity.com/files/177692/RHSA-2024-1422-03.txt	packetstorm	vuln;;	1	2024-03-20	红帽子安保咨询 2024-1422-03
21363	禁用了也没用？苹果隐私保护受到质疑	https://www.freebuf.com/news/397382.html	freebuf	news;资讯;	1	2024-04-10	禁用了也没用？苹果隐私保护受到质疑
8846	Red Hat Security Advisory 2024-1433-03	https://packetstormsecurity.com/files/177701/RHSA-2024-1433-03.txt	packetstorm	vuln;;	1	2024-03-20	红色帽子安保咨询 2024-1433-03
10465	Exploiting the libwebp Vulnerability, Part 2 Diving into Chrome Blink	https://paper.seebug.org/3136/	seebug	news;经验心得;	1	2024-03-28	利用libwebp脆弱性,第二部分
8930	通过 Google 网站走私规避 Azorult 活动分析	https://paper.seebug.org/3133/	seebug	news;威胁情报;	1	2024-03-21	通过 Google 网站走私规避 Azorult 活动分析
21364	新的勒索软件团伙 &quot;Muliaka &quot;瞄准俄罗斯企业	https://www.freebuf.com/news/397388.html	freebuf	news;资讯;	1	2024-04-10	新的勒索软件团伙 "Muliaka "瞄准俄罗斯企业
8890	Finally! You Can Colorize ChatGPT Output With AImarkdown Script: Here's How	https://buaq.net/go-229485.html	buaq	newscopy;	0	2024-03-21	最后, 您可以使用 AImardown 脚本来对 ChatGPPT 输出进行色彩化 ! 以下是
8864	MultiDump - Post-Exploitation Tool For Dumping And Extracting LSASS Memory Discreetly	http://www.kitploit.com/2024/03/multidump-post-exploitation-tool-for.html	kitploit	tool;MultiDump;Post-Exploitation;Post-Exploitation Tool;ProcDump;Pypykatz;Registry;Windows;Windows 10;	1	2024-03-20	多倾放 - 倾弃和提取 LSASS 记忆分解的开发后工具
8943	KDE advises extreme caution after theme wipes Linux user's files	https://www.bleepingcomputer.com/news/linux/kde-advises-extreme-caution-after-theme-wipes-linux-users-files/	bleepingcomputer	news;Linux;Security;	1	2024-03-21	在主题擦除 Linux 用户文件后, KDE 提示 极端谨慎
8895	EPIC游戏商店将从6月起停止支持Windows 7/8/8.1及32位版Windows 10	https://buaq.net/go-229504.html	buaq	newscopy;	0	2024-03-21	EPIC游戏商店将从6月起停止支持Windows 7/8/8.1及32位版Windows 10
8944	Microsoft confirms Windows Server issue behind domain controller crashes	https://www.bleepingcomputer.com/news/microsoft/microsoft-confirms-windows-server-issue-behind-domain-controller-crashes/	bleepingcomputer	news;Microsoft;	1	2024-03-21	微软在域控制器崩溃后确认 Windows 服务器问题
8946	Windows 11 Notepad finally gets spellcheck and autocorrect	https://www.bleepingcomputer.com/news/microsoft/windows-11-notepad-finally-gets-spellcheck-and-autocorrect/	bleepingcomputer	news;Microsoft;	1	2024-03-21	Windows 11 Notepad 终于得到拼写检查和自动校正
8957	300K Internet Hosts at Risk for 'Devastating' Loop DoS Attack	https://www.darkreading.com/cloud-security/300k-internet-hosts-at-risk-for-devastating-loop-dos-attack	darkreading	news;	1	2024-03-21	300K Internet Hosts at Risk for 'Devastating' Loop DoS Attack
8940	The art and science of product security: A deep dive with Jacob Salassi	https://securityboulevard.com/2024/03/the-art-and-science-of-product-security-a-deep-dive-with-jacob-salassi/	securityboulevard	news;Application Security;Security Bloggers Network;Podcast;Product Security;Threat Modeling;	1	2024-03-21	产品安全的艺术和科学:与Jacob Salassi一起深入潜水
8882	New ‘Loop DoS’ attack may impact up to 300,000 online systems	https://buaq.net/go-229465.html	buaq	newscopy;	0	2024-03-21	新的“Looop doS”攻击可能撞击多达300 000个在线系统
9932	StrelaStealer Malware Hacked 100+ Organizations Across The EU And U.S	https://gbhackers.com/strelastealer-malware-attacks-eu-us/	GBHacker	news;Cyber Attack;Email Security;Malware;cyber security;Cyber Security News;Malware analysis;Phishing Attacks;	1	2024-03-25	Strela Stealer Malware 黑客100+全欧盟和美国的组织
8947	Evasive Sign1 malware campaign infects 39,000 WordPress sites	https://www.bleepingcomputer.com/news/security/evasive-sign1-malware-campaign-infects-39-000-wordpress-sites/	bleepingcomputer	news;Security;	1	2024-03-21	399 000个WordPress网站
9933	Analyse, hunt and classify malware using .NET metadata	https://buaq.net/go-230396.html	buaq	newscopy;	0	2024-03-26	使用.NET元数据分析、追踪和分类恶意软件
9934	Senator demands answers from HHS about $7.5 million cyber theft in 2023	https://buaq.net/go-230412.html	buaq	newscopy;	0	2024-03-26	参议员要求HHHS回答2023年大约750万美元的网络盗窃案
9935	UL NO. 425: The Efficient Security Principle	https://buaq.net/go-230414.html	buaq	newscopy;	0	2024-03-26	UL No 425: 高效安全原则
8948	Exploit released for Fortinet RCE bug used in attacks, patch now	https://www.bleepingcomputer.com/news/security/exploit-released-for-fortinet-rce-bug-used-in-attacks-patch-now/	bleepingcomputer	news;Security;	1	2024-03-21	利用Fortnet RCE 窃听器释放出来 用于攻击的窃听器,现在补丁
8898	House unanimously passes bill to block data brokers from selling Americans’ info to foreign adversaries	https://buaq.net/go-229507.html	buaq	newscopy;	0	2024-03-21	众议院一致通过法案,阻止数据经纪人向外国对手出售美国人的信息
10467	DinodasRAT Linux implant targeting entities worldwide	https://securelist.com/dinodasrat-linux-implant/112284/	securelist	news;Malware descriptions;Backdoor;DinodasRAT;Linux;Malware;Malware Descriptions;Malware Technologies;RedHat;Trojan;Ubuntu;Unix and macOS malware;	1	2024-03-28	针对全世界实体的DinodasRAT Linux植入
10468	AI Apps: A New Game of Cybersecurity Whac-a-Mole | Grip	https://securityboulevard.com/2024/03/ai-apps-a-new-game-of-cybersecurity-whac-a-mole-grip/	securityboulevard	news;Security Bloggers Network;	1	2024-03-28	AI Apps:网络安全的新游戏Whac-a-mole Grip
8954	Windows 11, Tesla, and Ubuntu Linux hacked at Pwn2Own Vancouver	https://www.bleepingcomputer.com/news/security/windows-11-tesla-and-ubuntu-linux-hacked-at-pwn2own-vancouver/	bleepingcomputer	news;Security;Linux;Microsoft;Software;	1	2024-03-21	Windows 11, Tesla, and Ubuntu Linux hacked at Pwn2Own Vancouver
8956	Session Takeover Bug in AWS Apache Airflow Reveals Larger Cloud Risk	https://www.darkreading.com/cloud-security/1-click-takeover-bug-aws-apache-airflow-risk	darkreading	news;	1	2024-03-21	AWS AASTA Apache 气流回流中会话接收错误
8937	How to Strengthen Cybersecurity  in the Healthcare Industry	https://securityboulevard.com/2024/03/how-to-strengthen-cybersecurity-in-the-healthcare-industry/	securityboulevard	news;Governance, Risk & Compliance;Security Bloggers Network;Access Governance;articles;Audit;Cyber Security;	1	2024-03-21	如何加强保健行业的网络安全
8724	Connectivity Standards Alliance Meets Device Security Challenges With a Unified Standard and Certification	https://www.darkreading.com/ics-ot-security/connectivity-standards-alliance-meets-device-security-challenges-with-a-unified-standard-and-certification	darkreading	news;	1	2024-03-20	连接标准联盟以统一标准和认证应对设备安全挑战
8952	Unsaflok flaw can let hackers unlock millions of hotel doors	https://www.bleepingcomputer.com/news/security/unsaflok-flaw-can-let-hackers-unlock-millions-of-hotel-doors/	bleepingcomputer	news;Security;Hardware;	1	2024-03-21	让黑客解锁几百万个酒店门
21373	Cybersecurity jobs available right now: April 10, 2024	https://www.helpnetsecurity.com/2024/04/10/cybersecurity-jobs-available-right-now-april-10-2024/	helpnetsecurity	news;Don't miss;Hot stuff;News;cybersecurity jobs;	1	2024-04-10	网络安全工作: 2024年4月10日
8885	Spa Grand Prix email account hacked to phish banking info from fans	https://buaq.net/go-229477.html	buaq	newscopy;	0	2024-03-21	Spa Grand Prix 电子邮件账户黑入粉丝的菲什银行信息
2670	Airbnb将禁止在房源内安装监控摄像头	https://www.freebuf.com/news/394640.html	freebuf	news;资讯;	1	2024-03-13	Airbnb将禁止在房源内安装监控摄像头
2706	There Are Dark Corners of the Internet. Then There's 764	https://www.wired.com/story/764-com-child-predator-network/	wired	news;Security;Security / Security News;Business / Social Media;	1	2024-03-13	互联网有黑暗角落 然后有764个
9937	Should self posts be allowed here?	https://buaq.net/go-230423.html	buaq	newscopy;	0	2024-03-26	是否应该允许自设职位?
8991	Tesla Hack Team Wins $200K and a New Car	https://www.darkreading.com/threat-intelligence/team-s-tesla-hack-wins-them-200k-and-a-new-car	darkreading	news;	1	2024-03-21	特斯拉哈克队赢了200万元 和一辆新车
8993	Ivanti Keeps Security Teams Scrambling With 2 More Vulns	https://www.darkreading.com/vulnerabilities-threats/ivanti-security-teams-scrambling-2-vulns	darkreading	news;	1	2024-03-21	Ivantis 保持安全小组 与另外2个瓦隆人连成一团
9942	US sanctions crypto exchanges used by Russian darknet market, banks	https://buaq.net/go-230429.html	buaq	newscopy;	0	2024-03-26	俄罗斯黑网市场、银行使用的美国制裁秘密交易
9037	MarineMax	http://www.ransomfeed.it/index.php?page=post_details&id_post=13849	ransomfeed	ransom;rhysida;	1	2024-03-20	海洋最大
16074	Oil &amp; Gas Sector Falls for Fake Car Accident Phishing Emails	https://www.darkreading.com/cyberattacks-data-breaches/oil-gas-sector-falling-for-fake-vehicle-incident-email-lure	darkreading	news;	1	2024-04-03	石油 & amp; 伪造汽车事故的天然气部门倒车
9936	CISA adds FortiClient EMS, Ivanti EPM CSA, Nice Linear eMerge E3-Series bugs to its Known Exploited Vulnerabilities catalog	https://buaq.net/go-230415.html	buaq	newscopy;	0	2024-03-26	CISA在其已知的已知被利用的脆弱程度目录中增加了前置环境监测系统、Ivanti EPM CSA、尼斯线性电子气象E3-系列虫。
16082	TAG Report Reveals Endpoint Backup Is Essential to Improving Data Resiliency	https://www.darkreading.com/endpoint-security/tag-report-reveals-endpoint-backup-is-essential-to-improving-data-resiliency	darkreading	news;	1	2024-04-03	TAG 报告 Revelals 端点备份对于提高数据弹性至关重要
8974	Changing Concepts of Identity Underscore 'Perfect Storm' of Cyber-Risk	https://www.darkreading.com/cybersecurity-operations/changing-concepts-identity-perfect-storm-cyber-risk	darkreading	news;	1	2024-03-21	改变身份概念强调网络风险的“完美风暴”
8965	United Arab Emirates Faces Intensified Cyber-Risk	https://www.darkreading.com/cyber-risk/united-arab-emirates-faces-intensified-cyber-risk	darkreading	news;	1	2024-03-21	阿拉伯联合酋长国面对的网络风险
9039	Wurzbacher	http://www.ransomfeed.it/index.php?page=post_details&id_post=13851	ransomfeed	ransom;raworld;	1	2024-03-21	乌日巴赫
8987	How Can We Reduce Threats From the Initial Access Brokers Market?	https://www.darkreading.com/threat-intelligence/how-to-reduce-threats-from-the-initial-access-brokers-market	darkreading	news;	1	2024-03-21	我们如何减少最初进入经纪人市场带来的威胁?
9003	[Heads-Up] Phishing Campaign Delivers VCURMS RAT	https://blog.knowbe4.com/phishing-campaign-delivers-vcurms-rat	knowbe4	news;Phishing;Security Culture;	1	2024-03-21	[上 钓鱼运动交付VCURMSRAT
9938	It's not just you: ChatGPT is down for many worldwide	https://buaq.net/go-230425.html	buaq	newscopy;	0	2024-03-26	不只是你一个人 全世界很多人都在聊天
9939	It's not just you: ChatGPT is down worldwide	https://buaq.net/go-230426.html	buaq	newscopy;	0	2024-03-26	不只是你 全世界都在聊天
8966	Cyber Warfare: Understanding New Frontiers in Global Conflicts	https://www.darkreading.com/cyberattacks-data-breaches/cyber-warfare-understanding-new-frontiers-in-global-conflicts	darkreading	news;	1	2024-03-21	网络战争:了解全球冲突的新疆界
9943	Designing in the Dark: How to Create Innovative Products with Zero References	https://buaq.net/go-230430.html	buaq	newscopy;	0	2024-03-26	暗暗中设计:如何创建带有零引用的创新产品
8978	NIST's Vuln Database Downshifts, Prompting Questions About Its Future	https://www.darkreading.com/cybersecurity-operations/nist-vuln-database-downshifts-prompting-questions-about-its-future	darkreading	news;	1	2024-03-21	NIST的Vuln数据库低档,提示关于它未来的问题
9038	Suburban-Surgical-Care-Specialists	http://www.ransomfeed.it/index.php?page=post_details&id_post=13850	ransomfeed	ransom;medusa;	1	2024-03-20	城市郊区
21397	Critical 'BatBadBut' Rust Vulnerability Exposes Windows Systems to Attacks	https://thehackernews.com/2024/04/critical-batbadbut-rust-vulnerability.html	feedburner	news;	1	2024-04-10	关键“ BatBadbut ” 鲁氏脆弱度暴露视窗系统对攻击的冲击
21413	Patch Tuesday Update – April 2024	https://securityboulevard.com/2024/04/patch-tuesday-update-april-2024-2/	securityboulevard	news;Security Bloggers Network;Vulnerabilities;Vulnerability Research;	1	2024-04-09	更新2024年4月 - 2024年4月
10470	Empowering Educational Compliance: Navigating the Future with Autonomous Pentesting in Academia	https://securityboulevard.com/2024/03/empowering-educational-compliance-navigating-the-future-with-autonomous-pentesting-in-academia/	securityboulevard	news;Security Bloggers Network;Customer Stories;education;	1	2024-03-28	增强教育合规能力:在学术界利用自动笔试规划未来
8980	Using East-West Network Visibility to Detect Threats in Later Stages of MITRE ATT&amp;CK	https://www.darkreading.com/cybersecurity-operations/using-east-west-network-visibility-detect-threats-mitre-attck	darkreading	news;	1	2024-03-20	Using East-West Network Visibility to Detect Threats in Later Stages of MITRE ATT&amp;CK
2676	DataDome Ad Protect detects fraudulent ad traffic	https://www.helpnetsecurity.com/2024/03/13/datadome-ad-protect/	helpnetsecurity	news;Industry news;DataDome;	1	2024-03-13	DataDome Ad DataDad Protection 侦测欺诈性贩运
8998	CISA Recommends Continuous Cybersecurity Training	https://blog.knowbe4.com/cisa-recommends-continuous-cybersecurity-training	knowbe4	news;Security Awareness Training;KnowBe4;Cybersecurity;	1	2024-03-21	CISA 连续网络安全训练建议
2749	MetaFox 5.1.8 Shell Upload	https://packetstormsecurity.com/files/177564/metafox518-shell.txt	packetstorm	vuln;;	1	2024-03-13	MetaFox 5.1.8 壳牌上传
9947	Crypto Conundrum: Bitcoin Blues, But Altcoins Offer a Glimmer of Hope!	https://buaq.net/go-230434.html	buaq	newscopy;	0	2024-03-26	Bitcoin Blues, 但Altcoins提供一线希望!
9945	Quality Assurance as an Ideal Assistant for Successful Digital Transformations	https://buaq.net/go-230432.html	buaq	newscopy;	0	2024-03-26	作为成功数字变革理想助理的质量保证
9946	How the Approval of Bitcoin ETF Affected the Whole Market	https://buaq.net/go-230433.html	buaq	newscopy;	0	2024-03-26	Bittcoin ETF ETF的核准如何影响整个市场
9948	Is the Revival of NFTs in 2024 a Reality, or Just Another Fairy Tale for Beginners?	https://buaq.net/go-230435.html	buaq	newscopy;	0	2024-03-26	2024年NFT的复兴是真实的 还是刚开始的又一个童话故事?
8911	GitHub Launches AI-Powered Autofix Tool to Assist Devs in Patching Security Flaws	https://thehackernews.com/2024/03/github-launches-ai-powered-autofix-tool.html	feedburner	news;	1	2024-03-21	GitHub 启动 AI 授权自动修补安全条条协助发展部的工具
10474	Over 100 Malicious Packages Target Popular ML PyPi Libraries	https://securityboulevard.com/2024/03/over-100-malicious-packages-target-popular-ml-pypi-libraries/	securityboulevard	news;Security Bloggers Network;	1	2024-03-28	超过100个恶意包 目标目标目标 ML PyPi 大众ML PyPi 图书馆
9944	Enhancing Web Performance: Strategies for Efficient Resource Fetching and Prioritization	https://buaq.net/go-230431.html	buaq	newscopy;	0	2024-03-26	提高网络绩效:高效获取资源和确定优先次序的战略
10457	New Webinar: Avoiding Application Security Blind Spots with OPSWAT and F5	https://thehackernews.com/2024/03/new-webinar-avoiding-application.html	feedburner	news;	1	2024-03-28	新网络研讨会:与OPSWAT和F5合作,避免应用安全隐盲点
8915	Ivanti Releases Urgent Fix for Critical Sentry RCE Vulnerability	https://thehackernews.com/2024/03/ivanti-releases-urgent-fix-for-critical.html	feedburner	news;	1	2024-03-21	关键哨兵RCE脆弱性的Ivanti 释放紧急故障
10472	GoPlus’s Latest Report Highlights How Blockchain Communities Are Leveraging Critical API Security Data To Mitigate Web3 Threats	https://securityboulevard.com/2024/03/gopluss-latest-report-highlights-how-blockchain-communities-are-leveraging-critical-api-security-data-to-mitigate-web3-threats/	securityboulevard	news;Cyberwire;	1	2024-03-28	GoPlus的最新报告重点指出, " 封闭链社区如何利用重要API安全数据利用关键的API安全数据来消除网络3威胁 " 。
8914	How to Accelerate Vendor Risk Assessments in the Age of SaaS Sprawl	https://thehackernews.com/2024/03/how-to-accelerate-vendor-risk.html	feedburner	news;	1	2024-03-21	如何加快在SaaS 漫游时代的供应商风险评估
9951	Constella and Social Links Join Forces to Deliver Transformative OSINT Solutions	https://buaq.net/go-230439.html	buaq	newscopy;	0	2024-03-26	Constella与社会联系联合力量,以交付变革性OSINT解决方案
9949	Cybersecurity in Financial Disclosures: 11 Topics Your Section 1C of 10-K Filings Should Address	https://buaq.net/go-230437.html	buaq	newscopy;	0	2024-03-26	财务披露的网络安全:11个主题:你关于10K申报应处理的第1C节
18138	Solar Spider Spins Up New Malware to Entrap Saudi Arabian Financial Firms	https://www.darkreading.com/threat-intelligence/solar-spider-spins-up-new-malware-to-entrap-saudi-arabian-banks	darkreading	news;	1	2024-04-08	C. 进入沙特阿拉伯金融公司的新恶意
8905	Atlassian Releases Fixes for Over 2 Dozen Flaws, Including Critical Bamboo Bug	https://thehackernews.com/2024/03/atlassian-releases-fixes-for-over-2.html	feedburner	news;	1	2024-03-21	阿特拉斯斯的2个以上法律(包括临界竹虫)的释放修补法
8902	AndroxGh0st Malware Targets Laravel Apps to Steal Cloud Credentials	https://thehackernews.com/2024/03/androxgh0st-malware-targets-laravel.html	feedburner	news;	1	2024-03-21	AndroxGh0st 恶意目标 Laravel Apps 以窃取云体证书
9950	How to Get the Most From Your Secrets Scanning	https://buaq.net/go-230438.html	buaq	newscopy;	0	2024-03-26	如何从你的秘密扫描中 获取最伟大的信息
8916	Making Sense of Operational Technology Attacks: The Past, Present, and Future	https://thehackernews.com/2024/03/making-sense-of-operational-technology.html	feedburner	news;	1	2024-03-21	传播实用技术攻击感:过去、现在和未来
9091	一次有趣的前端加密分析	https://xz.aliyun.com/t/14132	阿里先知实验室	news;	1	2024-03-20	一次有趣的前端加密分析
9098	Hackers Found a Way to Open Any of 3 Million Hotel Keycard Locks in Seconds	https://www.wired.com/story/saflok-hotel-lock-unsaflok-hack-technique/	wired	news;Security;Security / Cyberattacks and Hacks;	1	2024-03-21	黑客找到了一种以秒打开 任何300万个酒店密钥锁的方法
9099	Rescoms rides waves of AceCryptor spam	https://www.welivesecurity.com/en/eset-research/rescoms-rides-waves-acecryptor-spam/	eset	news;	1	2024-03-20	Rescoms 载波于 ACCryptor 垃圾邮件
9124	Red Hat Security Advisory 2024-1362-03	https://packetstormsecurity.com/files/177713/RHSA-2024-1362-03.txt	packetstorm	vuln;;	1	2024-03-21	2024-1362-03红色帽子安保咨询
9125	Red Hat Security Advisory 2024-1438-03	https://packetstormsecurity.com/files/177714/RHSA-2024-1438-03.txt	packetstorm	vuln;;	1	2024-03-21	红帽子安保咨询 2024-1438-03
9126	Ubuntu Security Notice USN-6704-1	https://packetstormsecurity.com/files/177715/USN-6704-1.txt	packetstorm	vuln;;	1	2024-03-21	Ubuntu Ubuntu 安全通知 USN-6704-1
9127	Red Hat Security Advisory 2024-1444-03	https://packetstormsecurity.com/files/177716/RHSA-2024-1444-03.txt	packetstorm	vuln;;	1	2024-03-21	红色帽子安保咨询 2024-1444-03
10475	Reduce False Positives with Dependent Sensitive Data Detections | Impart Security	https://securityboulevard.com/2024/03/reduce-false-positives-with-dependent-sensitive-data-detections-impart-security/	securityboulevard	news;Security Bloggers Network;	1	2024-03-28	减少依赖性敏感数据检测的假阳性
18160	Microsoft Two-Step Phishing Campaign Attack LinkedIn Users	https://gbhackers.com/microsoft-two-step-phishing-campaign/	GBHacker	news;Cyber Security News;Microsoft;Phishing;Uncategorized;phishing;	1	2024-04-08	微软双脚钓鱼运动攻击链接用户
9128	Red Hat Security Advisory 2024-1462-03	https://packetstormsecurity.com/files/177717/RHSA-2024-1462-03.txt	packetstorm	vuln;;	1	2024-03-21	红色帽子安保咨询 2024-1462-03
9129	Ubuntu Security Notice USN-6705-1	https://packetstormsecurity.com/files/177718/USN-6705-1.txt	packetstorm	vuln;;	1	2024-03-21	Ubuntu Ubuntu 安全通知 USN-6705-1
9130	Ubuntu Security Notice USN-6701-2	https://packetstormsecurity.com/files/177719/USN-6701-2.txt	packetstorm	vuln;;	1	2024-03-21	Ubuntu Ubuntu 安全通知 USN-6701-2
9132	Ubuntu Security Notice USN-6702-2	https://packetstormsecurity.com/files/177721/USN-6702-2.txt	packetstorm	vuln;;	1	2024-03-21	Ubuntu Ubuntu 安全通知 USN-6702-2
9133	Ubuntu Security Notice USN-6707-2	https://packetstormsecurity.com/files/177722/USN-6707-2.txt	packetstorm	vuln;;	1	2024-03-21	Ubuntu Ubuntu 安全通知 USN-6707-2
9134	Ubuntu Security Notice USN-6707-1	https://packetstormsecurity.com/files/177723/USN-6707-1.txt	packetstorm	vuln;;	1	2024-03-21	Ubuntu Ubuntu 安全通知 USN-6707-1
9135	Faraday 5.2.1	https://packetstormsecurity.com/files/177724/faraday-5.2.1.tar.gz	packetstorm	vuln;;	1	2024-03-21	法拉第 5.2.1
9136	Debian Security Advisory 5642-1	https://packetstormsecurity.com/files/177725/dsa-5642-1.txt	packetstorm	vuln;;	1	2024-03-21	Debian安全咨询 5642-1
9131	Ubuntu Security Notice USN-6706-1	https://packetstormsecurity.com/files/177720/USN-6706-1.txt	packetstorm	vuln;;	1	2024-03-21	Ubuntu Ubuntu 安全通知 USN-6706-1
9076	Flipper Zero 在加拿大要被禁用了	https://www.freebuf.com/news/395475.html	freebuf	news;资讯;	1	2024-03-21	Flipper Zero 在加拿大要被禁用了
9075	谷歌Firebase泄露1900万明文密码，2.2亿条数据记录	https://www.freebuf.com/news/395473.html	freebuf	news;资讯;	1	2024-03-21	谷歌Firebase泄露1900万明文密码，2.2亿条数据记录
9077	Apricorn releases 24TB hardware encrypted USB drive	https://www.helpnetsecurity.com/2024/03/21/apricorn-24tb-encrypted-drive/	helpnetsecurity	news;Industry news;Apricorn;	1	2024-03-21	Aricorn释放了24TB硬件加密USB驱动器
9060	Hackthebox:Driver 记录	https://www.freebuf.com/articles/web/395399.html	freebuf	news;Web安全;	1	2024-03-20	Hackthebox:Driver 记录
9952	Vans warns customers of data breach	https://buaq.net/go-230441.html	buaq	newscopy;	0	2024-03-26	Vans警告客户数据被破坏
9074	GitHub 推出全新 AI 功能，可自动修复代码漏洞	https://www.freebuf.com/news/395466.html	freebuf	news;资讯;	3	2024-03-21	GitHub 推出全新 AI 功能，可自动修复代码漏洞
9083	LogicGate introduces cyber and operational risk suite offerings	https://www.helpnetsecurity.com/2024/03/21/logicgate-cyber-risk-suite-and-operational-risk-suite/	helpnetsecurity	news;Industry news;LogicGate;	1	2024-03-21	逻辑Gate 推出网络和业务风险套套件
9084	Vishal Rao joins Skyhigh Security as CEO	https://www.helpnetsecurity.com/2024/03/21/skyhigh-security-vishal-rao/	helpnetsecurity	news;Industry news;Skyhigh Security;	1	2024-03-21	Vishal Rao作为首席执行官加入Skyhigh Security公司
9085	Veritas Backup Exec enhancements protect SMBs’ critical data	https://www.helpnetsecurity.com/2024/03/21/veritas-backup-exec/	helpnetsecurity	news;Industry news;Veritas Technologies;	1	2024-03-21	Veritas 备份执行增强保护 SMB 关键数据
9086	WebCopilot: Open-source automation tool enumerates subdomains, detects bugs	https://www.helpnetsecurity.com/2024/03/21/webcopilot-open-source-automation-tool/	helpnetsecurity	news;Don't miss;Hot stuff;News;cybersecurity;GitHub;open source;penetration testing;scanning;software;	1	2024-03-21	Web 协作驾驶: 开放源码自动化工具列出子域, 检测错误
9089	Microsoft Threat Intelligence unveils targets and innovative tactics amidst tax season	https://www.microsoft.com/en-us/security/blog/2024/03/20/microsoft-threat-intelligence-unveils-targets-and-innovative-tactics-amidst-tax-season/	microsoft	news;	1	2024-03-20	微软威胁情报部在税收季节公布目标和创新策略
9092	针对一道面试题样本的详细分析	https://xz.aliyun.com/t/14134	阿里先知实验室	news;	1	2024-03-20	针对一道面试题样本的详细分析
9095	Apple's iMessage Encryption Puts Its Security Practices in the DOJ's Crosshairs	https://www.wired.com/story/apple-doj-antitrust-imessage-encryption/	wired	news;Security;Security / Privacy;Security / Security News;	1	2024-03-21	Apple's iMessage加密将其安全做法置于司法部的十字架上
9164	Windows 11 Notepad finally gets spellcheck and autocorrect	https://buaq.net/go-229766.html	buaq	newscopy;	0	2024-03-22	Windows 11 Notepad 终于得到拼写检查和自动校正
9155	Hackers Claimed to have Breached the Israeli Nuclear Facility’s Networks	https://gbhackers.com/hackers-claimed-nuclear-network/	GBHacker	news;cyber security;Cyber Security News;computer security;	1	2024-03-21	声称破坏以色列核设施网络的黑客组织
9159	Recent Windows Server Updates Trigger Domain Controller Reboots & Crash	https://gbhackers.com/windows-server-updates-trigger-domain-controller-failures-and-reboots/	GBHacker	news;Windows;cyber security;Cyber Security News;	1	2024-03-21	最近的 Windows 服务器更新 触发域控制器重新启动和崩溃
9306	黑客可通过Unsaflok 漏洞获取数百万家酒店房门“万能钥匙”	https://www.freebuf.com/news/395588.html	freebuf	news;资讯;	3	2024-03-22	黑客可通过Unsaflok 漏洞获取数百万家酒店房门“万能钥匙”
9166	Webinar Recap: Generative AI for OSINT – 4 Next-Level Techniques	https://buaq.net/go-229768.html	buaq	newscopy;	0	2024-03-22	网络研讨会摘要:OSINT的创举 - 4 高级技术
9160	独立开发变现周刊（第127期） : 失败了三次，25岁开发月入5万美元的Shopify插件	https://buaq.net/go-229673.html	buaq	newscopy;	0	2024-03-22	独立开发变现周刊（第127期） : 失败了三次，25岁开发月入5万美元的Shopify插件
9154	Hacker Pleads Guilty For Stealing 132,000+ Users Data	https://gbhackers.com/hacker-guilty-data-theft-132k-users/	GBHacker	news;Cyber Crime;Data Breach;Information Security Risks;Cybercrime;Legal Proceedings;	1	2024-03-21	因偷窃132 000+用户数据而认罪
10476	Tax scams: Scams to be aware of this tax season	https://securityboulevard.com/2024/03/tax-scams-scams-to-be-aware-of-this-tax-season/	securityboulevard	news;Careers;SBN News;Security Awareness;Security Bloggers Network;CISO Suite;Cyber Security Risks;Home;Scams;Security News;Seed n soil posts;tax scams;taxes;tips;	1	2024-03-28	税务骗局:要了解这一税收季节的飞毛腿
10277	Frawner	http://www.ransomfeed.it/index.php?page=post_details&id_post=13973	ransomfeed	ransom;play;	1	2024-03-27	伐木者
9307	联合国通过首个全球人工智能决议草案	https://www.freebuf.com/news/395599.html	freebuf	news;资讯;	1	2024-03-22	联合国通过首个全球人工智能决议草案
18169	估值超两千亿，黑灰产扎堆的“小暗网”想要IPO	https://www.freebuf.com/articles/neopoints/397165.html	freebuf	news;观点;	1	2024-04-08	估值超两千亿，黑灰产扎堆的“小暗网”想要IPO
9163	Biden taps cyber policy veteran for new Pentagon post	https://buaq.net/go-229765.html	buaq	newscopy;	0	2024-03-22	为五角大楼新职位的网络政策退伍军人
9161	USENIX Security ’23 – Sparsity Brings Vulnerabilities: Exploring New Metrics in Backdoor Attacks	https://buaq.net/go-229757.html	buaq	newscopy;	0	2024-03-22	USENIX 安全 23 — — 公平带来脆弱性:探索后门攻击的新措施
10278	Alber-Law-Group	http://www.ransomfeed.it/index.php?page=post_details&id_post=13974	ransomfeed	ransom;play;	1	2024-03-27	常设法律小组
10279	Hartz	http://www.ransomfeed.it/index.php?page=post_details&id_post=13975	ransomfeed	ransom;play;	1	2024-03-27	哈兹
10280	Quality-Enclosures	http://www.ransomfeed.it/index.php?page=post_details&id_post=13976	ransomfeed	ransom;play;	1	2024-03-27	质量保证
10281	Lawrence-Semiconductor-Research-Laboratory	http://www.ransomfeed.it/index.php?page=post_details&id_post=13977	ransomfeed	ransom;play;	1	2024-03-27	劳伦斯-半导体-研究-实验室
9167	KDE advises extreme caution after theme wipes Linux user's files	https://buaq.net/go-229769.html	buaq	newscopy;	0	2024-03-22	在主题擦除 Linux 用户文件后, KDE 提示 极端谨慎
9170	Patch Ivanti Standalone Sentry and Ivanti Neurons for ITSM now	https://buaq.net/go-229782.html	buaq	newscopy;	0	2024-03-22	现为ITSM的独立哨兵和Ivanti神经元
9173	AI Security — What Are Sources and Sinks?	https://buaq.net/go-229785.html	buaq	newscopy;	0	2024-03-22	AI 安全——什么是来源和辛克斯?
9172	Critical Fortinet’s FortiClient EMS flaw actively exploited in the wild	https://buaq.net/go-229784.html	buaq	newscopy;	0	2024-03-22	在野外被积极利用的关键Fortinet 的FortiClient EMS 功能缺陷
9171	Wireshark data far cry 3	https://buaq.net/go-229783.html	buaq	newscopy;	0	2024-03-22	Wireshark 数据远端哭泣 3
9176	Why Sam Bankman-Fried Must Get a 40–50 Year Sentence	https://buaq.net/go-229788.html	buaq	newscopy;	0	2024-03-22	为什么Sam Bankman - Fried 得判40 - 50年有期徒刑
9177	Understanding the Severity of Bankman-Fried's Crimes	https://buaq.net/go-229789.html	buaq	newscopy;	0	2024-03-22	了解班克曼 - 弗里德罪行的严重性
9137	Debian Security Advisory 5626-2	https://packetstormsecurity.com/files/177726/dsa-5626-2.txt	packetstorm	vuln;;	1	2024-03-21	Debian安全咨询 5626-2
9178	Sam Bankman-Fried vs. Fraud Sentencing Guidelines	https://buaq.net/go-229790.html	buaq	newscopy;	0	2024-03-22	Sam Bankman-Fried诉欺诈判决准则
9179	How Perjury and Witness Tampering Compounded SBF's Legal Woes	https://buaq.net/go-229791.html	buaq	newscopy;	0	2024-03-22	作伪证和打赌证人如何加深了SBF的法律伤痛
9150	New Application-Layer Loop DoS Attack – 300,000 Online Systems At Risk	https://gbhackers.com/application-layer-loop-dos-attack-risk/	GBHacker	news;Cyber Attack;Cyber Security News;DDOS;Application-Layer Loop;cyber security;DOS attack;	1	2024-03-21	新建应用程序Layer Loop DoS 攻击 — — 300,000个在线系统面临风险
9142	Latest government funding bill makes modest cut to CISA	https://therecord.media/government-funding-bill-makes-modest-cisa-cuts	therecord	ransom;Government;News;Leadership;	1	2024-03-21	最新政府供资法案略微削减了独联体国家银行
9138	OpenNMS Horizon 31.0.7 Remote Command Execution	https://packetstormsecurity.com/files/177727/opennms_horizon_authenticated_rce.rb.txt	packetstorm	vuln;;	1	2024-03-21	31.0.7 远程指令执行
9158	Nemesis Market: Leading Darknet Market Seized	https://gbhackers.com/nemesis-market-leading-darknet-market-seized/	GBHacker	news;Cyber Security News;Dark Web;cyber security;	2	2024-03-21	宿敌市场:黑网市场中的主要黑网市场
9151	Authorities Dismantle Grandoreiro Banking Malware Operation	https://gbhackers.com/dismantle-grandoreiro-malware/	GBHacker	news;Cyber Security News;Malware;	1	2024-03-21	解散Grandoreiro银行业务软件业务
109	Boston Red Sox Choose Centripetal As Cyber Network Security Partner	https://www.darkreading.com/cybersecurity-operations/boston-red-sox-choose-centripetal-as-cyber-network-security-partner	darkreading	news;	1	2024-03-05	波士顿红袜选择中子网网安全伙伴
10282	Lambda-Energy-Resources	http://www.ransomfeed.it/index.php?page=post_details&id_post=13978	ransomfeed	ransom;play;	1	2024-03-27	兰巴达能源资源
8809	Top Signs of Identity Theft	https://www.mcafee.com/blogs/privacy-identity-protection/top-signs-of-identity-theft/	mcafee	news;Privacy & Identity Protection;identity theft;What to do about identity theft;Signs of identity theft;How to report identity theft;	1	2024-03-20	身份盗窃的顶端符号
9174	Navigating the Observability Landscape: Highlights From Grafana Labs’ 2024 Survey	https://buaq.net/go-229786.html	buaq	newscopy;	0	2024-03-22	导航可观测地貌:格拉法纳实验室2024年调查的亮点
8892	Apex Legends Global Series plagued by hackers	https://buaq.net/go-229500.html	buaq	newscopy;	0	2024-03-21	受黑客困扰的顶点传奇全球系列
9156	North Korea’s Kimsuky Group Equipped to Exploit Windows Help files	https://gbhackers.com/kimsuky-group-exploit-windows-help-files/	GBHacker	news;Cyber Attack;Cyber Security News;Windows;computer security;window;	3	2024-03-21	朝鲜的Kimsuky Group 配置为开发窗口帮助文件
9141	Chinese government hacker exploiting ScreenConnect, F5 bugs to attack defense and government entities	https://therecord.media/chinese-government-hacker-exploiting-bugs-to-target-defense-government-sectors	therecord	ransom;Government;Cybercrime;China;News;Nation-state;	4	2024-03-21	中国政府黑客利用屏幕连网、F5窃听器攻击国防和政府实体
9152	GitHub’s New AI Tool that Fixes Your Code Automatically	https://gbhackers.com/githubs-new-ai-tool/	GBHacker	news;cyber security;Cyber Security News;computer security;	1	2024-03-21	GitHub 的新 AI 工具自动修正您的代码
10284	qosinacom	http://www.ransomfeed.it/index.php?page=post_details&id_post=13980	ransomfeed	ransom;cactus;	1	2024-03-27	qosinacom 组织
8922	Russia Hackers Using TinyTurla-NG to Breach European NGO's Systems	https://thehackernews.com/2024/03/russia-hackers-using-tinyturla-ng-to.html	feedburner	news;	3	2024-03-21	俄罗斯黑客利用小Turla-NG利用小Turla-NG侵入欧洲非政府组织系统
9082	Fake data breaches: Countering the damage	https://www.helpnetsecurity.com/2024/03/21/fake-data-breaches/	helpnetsecurity	news;Don't miss;Expert analysis;Expert corner;Hot stuff;News;Cato Networks;CISO;cybersecurity;data breach;opinion;threats;	1	2024-03-21	虚假数据违反:弥补损害
9139	US airlines’ privacy protection practices to get DOT review	https://therecord.media/airlines-airports-dot-passenger-data-privacy-review	therecord	ransom;Industry;Government;Privacy;News;	1	2024-03-21	美国航空公司的隐私保护做法,以获得DOT审查
10285	Tbr-Kowalczyk	http://www.ransomfeed.it/index.php?page=post_details&id_post=13981	ransomfeed	ransom;play;	1	2024-03-27	Tbr- Kowalczyk 翻译: 翻译: Tbr- Kowalczyk 翻译: 翻译: 翻译: 翻译: 翻译: 翻译: Tbr- Kowalczyk
9059	对大型语言模型的安全性能进行基准测试，谁更胜一筹？	https://www.freebuf.com/articles/paper/395370.html	freebuf	news;安全报告;	1	2024-03-20	对大型语言模型的安全性能进行基准测试，谁更胜一筹？
24404	TA547 Hackers Launching AI-Powered Cyber Attacks Targeting Organizations	https://gbhackers.com/ai-powered-cyber-attacks-2/	GBHacker	news;Cyber Attack;Cyber Security News;Malware;computer security;	1	2024-04-11	TA547 Hackers 发射AI授权的网络攻击目标组织
10481	Cisco warns of password-spraying attacks targeting VPN services	https://www.bleepingcomputer.com/news/security/cisco-warns-of-password-spraying-attacks-targeting-vpn-services/	bleepingcomputer	news;Security;	1	2024-03-28	Cisco警告使用密码对VPN服务进行攻击
10286	JM-Thompson	http://www.ransomfeed.it/index.php?page=post_details&id_post=13982	ransomfeed	ransom;play;	1	2024-03-27	JM- 汤普森
10283	Festspielhaus-Baden-Baden	http://www.ransomfeed.it/index.php?page=post_details&id_post=13979	ransomfeed	ransom;play;	1	2024-03-27	费斯斯斯皮尔豪斯-巴登-巴登-巴登
24413	Taxi App Vendor Data Leak: 300K Passengers Data Exposed	https://gbhackers.com/taxi-software-vendor-data-leak/	GBHacker	news;cyber security;Cyber Security News;Data Breach;	1	2024-04-11	出租车App 供应商数据泄漏:300公里旅客数据披露
24434	FreeBuf早报 | 谷歌云联合GenAI创建网络安全强国；消费电子制造商 boAt 遭攻击	https://www.freebuf.com/news/397631.html	freebuf	news;资讯;	1	2024-04-11	FreeBuf早报 | 谷歌云联合GenAI创建网络安全强国；消费电子制造商 boAt 遭攻击
9165	US airlines’ privacy protection practices to get DOT review	https://buaq.net/go-229767.html	buaq	newscopy;	0	2024-03-22	美国航空公司的隐私保护做法,以获得DOT审查
9078	AttackIQ Ready! 2.0 enables organizations to validate their cyber defense	https://www.helpnetsecurity.com/2024/03/21/attackiq-ready-2-0/	helpnetsecurity	news;Industry news;AttackIQ;	1	2024-03-21	攻击Q 准备! 2. 0 使组织能够验证其网络防御
9169	CISA, NSA, Others Outline Security Steps Against Volt Typhoon	https://buaq.net/go-229773.html	buaq	newscopy;	0	2024-03-22	独联体国家、国家安全局、其他国家针对伏特台风采取安全步骤
8936	How To Respond To An AWS Key Honeytoken Trigger: A Detailed Guide	https://securityboulevard.com/2024/03/how-to-respond-to-an-aws-key-honeytoken-trigger-a-detailed-guide/	securityboulevard	news;Security Bloggers Network;Best Practices;honeytokens;	1	2024-03-21	如何响应 AWS 键 蜜调触发器: 详细指南
10477	The Importance of User Roles and Permissions in Cybersecurity Software	https://securityboulevard.com/2024/03/the-importance-of-user-roles-and-permissions-in-cybersecurity-software/	securityboulevard	news;Governance, Risk & Compliance;Security Bloggers Network;Blog;RBAC;security operations;	1	2024-03-28	用户在网络安全软件中的作用和权限的重要性
18179	22% 的员工承认违规使用 AI	https://www.freebuf.com/news/397169.html	freebuf	news;资讯;	1	2024-04-08	22% 的员工承认违规使用 AI
9079	Using cloud development environments to secure source code	https://www.helpnetsecurity.com/2024/03/21/cloud-development-environment-video/	helpnetsecurity	news;Don't miss;Hot stuff;Video;cloud;code;Coder;cybersecurity;DevOps;programming;software development;video;	1	2024-03-21	利用云层开发环境确保源代码安全
64	Announcing Our UK R&D Center and Data Centers in Canada and Germany	https://securityboulevard.com/2024/03/announcing-our-uk-rd-center-and-data-centers-in-canada-and-germany/	securityboulevard	news;Security Bloggers Network;Blog;Product updates;	1	2024-03-11	宣布我们英国R
66	DARPA awards $1 million to Trail of Bits for AI Cyber Challenge	https://securityboulevard.com/2024/03/darpa-awards-1-million-to-trail-of-bits-for-ai-cyber-challenge/	securityboulevard	news;Security Bloggers Network;AIxCC;	1	2024-03-11	DARPA向AI网络挑战的Bits轨迹赔偿100万美元
10996	Hackers Target macOS Users with Malicious Ads Spreading Stealer Malware	https://thehackernews.com/2024/03/hackers-target-macos-users-with.html	feedburner	news;	1	2024-03-30	具有恶意散布窃贼恶意的黑客 目标 macOS 用户
11005	Urgent: Secret Backdoor Found in XZ Utils Library, Impacts Major Linux Distros	https://thehackernews.com/2024/03/urgent-secret-backdoor-found-in-xz.html	feedburner	news;	1	2024-03-30	紧急事件: XZ Utils 图书馆发现秘密后门,
103	First BofA, Now Fidelity: Same Vendor Behind Third-Party Breaches	https://www.darkreading.com/cyberattacks-data-breaches/first-bofa-now-fidelity-same-vendor-third-party-breaches	darkreading	news;	1	2024-03-06	第一次博法协会, " 现为菲菲力:第三方违约背后的同卖家 "
164	一周网安优质PDF资源推荐丨FreeBuf知识大陆	https://www.freebuf.com/news/393842.html	freebuf	news;资讯;	1	2024-03-08	一周网安优质PDF资源推荐丨FreeBuf知识大陆
165	FreeBuf 周报 | 网络安全成两会热议“关键词”；GitHub超过10万存储库被感染	https://www.freebuf.com/news/393844.html	freebuf	news;资讯;	1	2024-03-08	FreeBuf 周报 | 网络安全成两会热议“关键词”；GitHub超过10万存储库被感染
9213	A Practical Guide to the SEC Cybersecurity Rules	https://securityboulevard.com/2024/03/a-practical-guide-to-the-sec-cybersecurity-rules/	securityboulevard	news;DevOps;Security Bloggers Network;Security Culture;	1	2024-03-22	《证安会网络安全规则实用指南》
213	入侵检测之流量分析--SURICATA应用及规则来源梳理	https://xz.aliyun.com/t/13922	阿里先知实验室	news;	1	2024-02-28	入侵检测之流量分析--SURICATA应用及规则来源梳理
260	PHP代码审计-某电商管理系统0Day分析	https://xz.aliyun.com/t/14036	阿里先知实验室	news;	1	2024-03-01	PHP代码审计-某电商管理系统0Day分析
9216	Container Security: Creating an Effective Security Program with Reachability Analysis	https://securityboulevard.com/2024/03/container-security-creating-an-effective-security-program-with-reachability-analysis/	securityboulevard	news;Security Bloggers Network;	1	2024-03-21	集装箱安全:制定有效的安全方案,并进行可达性分析
9202	Russian Hackers Target Ukrainian Telecoms with Upgraded 'AcidPour' Malware	https://thehackernews.com/2024/03/russian-hackers-target-ukrainian.html	feedburner	news;	3	2024-03-22	俄罗斯黑客将乌克兰电信升级为“ ACidPour ” Malware
10484	How Pentesting-as-a-Service can Reduce Overall Security Costs	https://www.bleepingcomputer.com/news/security/how-pentesting-as-a-service-can-reduce-overall-security-costs/	bleepingcomputer	news;Security;	1	2024-03-28	如何降低总体安保费用
10487	PyPI suspends new user registration to block malware campaign	https://www.bleepingcomputer.com/news/security/pypi-suspends-new-user-registration-to-block-malware-campaign/	bleepingcomputer	news;Security;	1	2024-03-28	PyPPI 中止新的用户注册,以阻止恶意软件活动
9218	Paid Cybersecurity Courses: Why They Are Not the Solution for Security Awareness	https://securityboulevard.com/2024/03/paid-cybersecurity-courses-why-they-are-not-the-solution-for-security-awareness/	securityboulevard	news;Security Bloggers Network;Awareness Training;	1	2024-03-22	付费网络安全课程:为什么它们不是提高安全意识的解决方案
9230	Hackers earn $1,132,500 for 29 zero-days at Pwn2Own Vancouver	https://www.bleepingcomputer.com/news/security/hackers-earn-1-132-500-for-29-zero-days-at-pwn2own-vancouver/	bleepingcomputer	news;Security;	1	2024-03-22	在Pwn2Own温哥华,黑客29个零日收入为1 132 500美元
75	Critical Fortinet flaw may impact 150,000 exposed devices	https://www.bleepingcomputer.com/news/security/critical-fortinet-flaw-may-impact-150-000-exposed-devices/	bleepingcomputer	news;Security;	1	2024-03-08	关键的防网缺陷可能影响到150 000个暴露装置
18184	April 2024 Patch Tuesday forecast: New and old from Microsoft	https://www.helpnetsecurity.com/2024/04/08/april-2024-patch-tuesday-forecast/	helpnetsecurity	news;Don't miss;Expert analysis;Hot stuff;News;Adobe;Apple;Google;Microsoft;Mozilla;opinion;Patch Tuesday;Windows;	1	2024-04-08	2024年4月2024日 Patch 星期二预报:微软新旧
9220	Q1 2024 Release Notes	https://securityboulevard.com/2024/03/q1-2024-release-notes/	securityboulevard	news;Security Bloggers Network;Blog;product announcement;	1	2024-03-21	Q1 2024 Q1 2024 发布说明
5572	国际货币基金组织称 2 月份的网络攻击涉及 11 个电子邮件帐户泄露	https://buaq.net/go-228685.html	buaq	newscopy;	0	2024-03-18	国际货币基金组织称 2 月份的网络攻击涉及 11 个电子邮件帐户泄露
187	Hybrid Workplace Vulnerabilities: 4 Ways to Promote Online Safety	https://www.mcafee.com/blogs/internet-security/hybrid-workplace-vulnerabilities-4-ways-to-promote-online-safety/	mcafee	news;Internet Security;Security News;Tips & Tricks;online safety;hybrid workplace;work from home security;workplace security;	1	2024-03-01	工作场所脆弱性:促进在线安全的途径4
8894	Vultr免费服务器到期后开始收费 请各位中奖用户及时销毁机器	https://buaq.net/go-229503.html	buaq	newscopy;	0	2024-03-21	Vultr免费服务器到期后开始收费 请各位中奖用户及时销毁机器
211	密码学——离散对数问题(DLP)	https://xz.aliyun.com/t/13919	阿里先知实验室	news;	1	2024-02-28	密码学——离散对数问题(DLP)
9397	阿里巴巴确认出售哔哩哔哩股票 哔哩哔哩美股/港股均大跌8%	https://buaq.net/go-229821.html	buaq	newscopy;	0	2024-03-22	阿里巴巴确认出售哔哩哔哩股票 哔哩哔哩美股/港股均大跌8%
9390	密码管理器Proton Pass现已支持通行密钥 并且可以导出和共享通行密钥	https://buaq.net/go-229806.html	buaq	newscopy;	0	2024-03-22	密码管理器Proton Pass现已支持通行密钥 并且可以导出和共享通行密钥
9317	Inside the book – See Yourself in Cyber: Security Careers Beyond Hacking	https://www.helpnetsecurity.com/2024/03/22/security-careers-beyond-hacking-book-video/	helpnetsecurity	news;Don't miss;Hot stuff;Video;book;cybersecurity;cybersecurity jobs;Security Innovation;video;	1	2024-03-22	在这本书中 — — 见《网络网路:超越黑客的安全职业》。
9409	《安全可靠 服务器操作系统技术要求》等9项行业标准公开征求意见	https://buaq.net/go-229839.html	buaq	newscopy;	0	2024-03-22	《安全可靠 服务器操作系统技术要求》等9项行业标准公开征求意见
9408	10月1日起施行！5项网络安全国家标准正式发布	https://buaq.net/go-229838.html	buaq	newscopy;	0	2024-03-22	10月1日起施行！5项网络安全国家标准正式发布
9398	黑进APEX锦标赛的黑客称只是好玩而已 同时称APEX存在严重安全漏洞	https://buaq.net/go-229822.html	buaq	newscopy;	0	2024-03-22	黑进APEX锦标赛的黑客称只是好玩而已 同时称APEX存在严重安全漏洞
9395	GB/T 43697-2024《数据安全技术 数据分类分级规则》发布	https://buaq.net/go-229818.html	buaq	newscopy;	0	2024-03-22	GB/T 43697-2024《数据安全技术 数据分类分级规则》发布
4034	实战时代下人机结合的资产风险收敛体系 | FreeBuf 企业安全俱乐部·广州站议题前瞻	https://www.freebuf.com/articles/394763.html	freebuf	news;	1	2024-03-14	实战时代下人机结合的资产风险收敛体系 | FreeBuf 企业安全俱乐部·广州站议题前瞻
9404	A Practical Guide to the SEC Cybersecurity Rules	https://buaq.net/go-229829.html	buaq	newscopy;	0	2024-03-22	《证安会网络安全规则实用指南》
9405	俄乌冲突加剧网络攻击风险 白俄罗斯政府遭APT攻击	https://buaq.net/go-229835.html	buaq	newscopy;	0	2024-03-22	俄乌冲突加剧网络攻击风险 白俄罗斯政府遭APT攻击
9143	Jacksonville Beach and other US municipalities report data breaches following cyberattacks	https://therecord.media/jacksonville-beach-municipalities-hit-by-cyberattacks	therecord	ransom;Cybercrime;Government;News;	1	2024-03-21	Jacksonville Beach 和其他美国城市 报告说在网络攻击后数据被破坏
9402	ISC Stormcast For Friday, March 22nd, 2024 https://isc.sans.edu/podcastdetail/8906, (Fri, Mar 22nd)	https://buaq.net/go-229827.html	buaq	newscopy;	0	2024-03-22	2024年3月22日星期五的ISC风暴预报 https://isc.sans.edu/podcastdetail/8906,(Fri, Mar 22nd)
9396	NASA大幅度削减钱德拉X射线天文台预算让众多天体物理学家感到震惊	https://buaq.net/go-229820.html	buaq	newscopy;	0	2024-03-22	NASA大幅度削减钱德拉X射线天文台预算让众多天体物理学家感到震惊
9401	Russian Hackers Target Ukrainian Telecoms with Upgraded 'AcidPour' Malware	https://buaq.net/go-229825.html	buaq	newscopy;	0	2024-03-22	俄罗斯黑客将乌克兰电信升级为“ ACidPour ” Malware
9314	95% of companies face API security problems	https://www.helpnetsecurity.com/2024/03/22/api-security-importance-for-businesses/	helpnetsecurity	news;Don't miss;News;API security;CISO;cybersecurity;Fastly;report;survey;threats;	1	2024-03-22	95%的公司面临API安全问题
9391	联合国通过首个全球人工智能决议草案	https://buaq.net/go-229813.html	buaq	newscopy;	0	2024-03-22	联合国通过首个全球人工智能决议草案
9394	使用PikaBot 恶意软件呈上升趋势  企业如何加以防范	https://buaq.net/go-229817.html	buaq	newscopy;	0	2024-03-22	使用PikaBot 恶意软件呈上升趋势 企业如何加以防范
10489	Retail chain Hot Topic hit by new credential stuffing attacks	https://www.bleepingcomputer.com/news/security/retail-chain-hot-topic-hit-by-new-credential-stuffing-attacks/	bleepingcomputer	news;Security;	1	2024-03-28	被新的持证塞车袭击击中的热点话题
9400	微软也在Windows 11锁屏界面添加更多小部件 包括股市/交通/体育等	https://buaq.net/go-229824.html	buaq	newscopy;	0	2024-03-22	微软也在Windows 11锁屏界面添加更多小部件 包括股市/交通/体育等
9406	问卷调研 | 2024年我国企业商用密码技术应用状况与挑战	https://buaq.net/go-229836.html	buaq	newscopy;	0	2024-03-22	问卷调研 | 2024年我国企业商用密码技术应用状况与挑战
13585	hrm2024.1.0-Multiple-SQLi	https://www.nu11secur1ty.com/2024/04/hrm202410-multiple-sqli.html	nu11security	vuln;	1	2024-04-02	hrm2024.1.0-多元SQLi
9399	三星A55开始采用谷歌无缝更详细技术 大幅度缩短系统重启需要的时间	https://buaq.net/go-229823.html	buaq	newscopy;	0	2024-03-22	三星A55开始采用谷歌无缝更详细技术 大幅度缩短系统重启需要的时间
9403	Paid Cybersecurity Courses: Why They Are Not the Solution for Security Awareness	https://buaq.net/go-229828.html	buaq	newscopy;	0	2024-03-22	付费网络安全课程:为什么它们不是提高安全意识的解决方案
9316	New infosec products of the week: March 22, 2024	https://www.helpnetsecurity.com/2024/03/22/new-infosec-products-of-the-week-march-22-2024/	helpnetsecurity	news;News;Appdome;Drata;GlobalSign;Ordr;Portnox;Sonatype;Tufin;Zoom;	1	2024-03-22	2024年3月22日 2024年3月22日
13640	Google to Delete Billions of Browsing Records in 'Incognito Mode' Privacy Lawsuit Settlement	https://thehackernews.com/2024/04/google-to-delete-billions-of-browsing.html	feedburner	news;	1	2024-04-02	谷歌删除数十亿张浏览记录 在“ Incognito mode” 隐私法律解决中
13647	 71% Website Vulnerable: API Security Becomes Prime Target for Hackers	https://securityboulevard.com/2024/04/71-website-vulnerable-api-security-becomes-prime-target-for-hackers/	securityboulevard	news;Security Bloggers Network;Threats & Breaches;API security;cyber attacks;Cyber Security;	1	2024-04-02	71%网站弱势:API安全成为黑客的首要目标
9407	另辟蹊「径」，看操作系统的发展	https://buaq.net/go-229837.html	buaq	newscopy;	0	2024-03-22	另辟蹊「径」，看操作系统的发展
10490	Cisco IOS Bugs Allow Unauthenticated, Remote DoS Attacks	https://www.darkreading.com/application-security/cisco-ios-bugs-unauthenticated-remote-dos-attacks	darkreading	news;	1	2024-03-28	Cisco IOS 错误允许未经认证的远程 doS 攻击
28443	新发现，37% 的公开共享文件正在泄露敏感信息	https://www.freebuf.com/news/397926.html	freebuf	news;资讯;	1	2024-04-15	新发现，37% 的公开共享文件正在泄露敏感信息
8259	How the New NIST 2.0 Guidelines Help Detect SaaS Threats	https://www.bleepingcomputer.com/news/security/how-the-new-nist-20-guidelines-help-detect-saas-threats/	bleepingcomputer	news;Security;	1	2024-03-18	新 NIST 2. 0 指南如何帮助检测SaaS威胁
9441	Microsoft releases emergency fix for Windows Server crashes	https://www.bleepingcomputer.com/news/microsoft/microsoft-releases-emergency-fix-for-windows-server-crashes/	bleepingcomputer	news;Microsoft;	1	2024-03-22	微软发布Windows服务器撞车紧急修补
8272	Saudi Arabia's National Cybersecurity Authority Announces the GCF Annual Meeting 2024	https://www.darkreading.com/cybersecurity-operations/saudi-arabia-s-national-cybersecurity-authority-announces-the-gcf-annual-meeting-2024	darkreading	news;	1	2024-03-18	沙特阿拉伯国家网络安全管理局宣布2024年全球合作框架年度会议
9444	Darknet marketplace Nemesis Market seized by German police	https://www.bleepingcomputer.com/news/security/darknet-marketplace-nemesis-market-seized-by-german-police/	bleepingcomputer	news;Security;	2	2024-03-22	被德国警方查封的暗网市场
9455	Kenya to TikTok: Prove Compliance With Our Privacy Laws	https://www.darkreading.com/cyber-risk/kenya-to-tiktok-prove-compliance-with-our-privacy-laws	darkreading	news;	1	2024-03-22	肯尼亚至TikTok:证明遵守我们的隐私法
9464	Why AI Obituary Scams Are a Cyber-Risk for Businesses	https://www.darkreading.com/threat-intelligence/why-ai-obituary-scams-cyber-risk-businesses	darkreading	news;	1	2024-03-22	为何AI 性记事录相片是商业界的网络风险
8412	Nigerian court orders Binance to release user data, as company execs continue to be held without charge	https://buaq.net/go-228846.html	buaq	newscopy;	0	2024-03-19	尼日利亚法院命令 " Binance " 发布用户数据,因为公司执行人员继续被免费拘留
9458	8 Strategies for Enhancing Code Signing Security	https://www.darkreading.com/cybersecurity-operations/8-strategies-enhancing-code-signing-security	darkreading	news;	1	2024-03-22	8 增强安保法规签署安全的战略
10493	Pervasive LLM Hallucinations Expand Code Developer Attack Surface	https://www.darkreading.com/application-security/pervasive-llm-hallucinations-expand-code-developer-attack-surface	darkreading	news;	1	2024-03-28	扩展代码开发者攻击表面
10498	Suspected MFA Bombing Attacks Target Apple iPhone Users	https://www.darkreading.com/cloud-security/mfa-bombing-attacks-target-apple-iphone-users	darkreading	news;	2	2024-03-28	疑似MFA轰炸攻击目标苹果iPhone用户
10500	3 Strategies to Future-Proof Data Privacy	https://www.darkreading.com/cyber-risk/3-strategies-to-future-proof-data-privacy	darkreading	news;	1	2024-03-28	3 未来数据隐私战略
20278	通过ModSecurity防御一个C段IP发起的CC、扫描、采集等恶意行为	https://www.freebuf.com/articles/web/279881.html	freebuf	news;Web安全;	1	2024-04-07	通过ModSecurity防御一个C段IP发起的CC、扫描、采集等恶意行为
9442	Microsoft to shut down 50 cloud services for Russian businesses	https://www.bleepingcomputer.com/news/microsoft/microsoft-to-shut-down-50-cloud-services-for-russian-businesses/	bleepingcomputer	news;Microsoft;Cloud;Legal;	3	2024-03-23	微软关闭俄罗斯企业的50台云服务
9447	Mozilla fixes two Firefox zero-day bugs exploited at Pwn2Own	https://www.bleepingcomputer.com/news/security/mozilla-fixes-two-firefox-zero-day-bugs-exploited-at-pwn2own/	bleepingcomputer	news;Security;	1	2024-03-22	Mozilla 修补在Pwn2Own开发的两个火狐零天虫
9461	Strata Identity Releases New Authentication Recipes	https://www.darkreading.com/identity-access-management-security/strata-identity-releases-new-authentication-recipes	darkreading	news;	1	2024-03-21	Strata 身份发布新认证食谱
9448	New GoFetch attack on Apple Silicon CPUs can steal crypto keys	https://www.bleepingcomputer.com/news/security/new-gofetch-attack-on-apple-silicon-cpus-can-steal-crypto-keys/	bleepingcomputer	news;Security;Apple;	1	2024-03-22	对苹果硅CPU的新 GoFetch 攻击可以窃取加密密钥
9457	Russian APT Releases More Deadly Variant of AcidRain Wiper Malware	https://www.darkreading.com/cyberattacks-data-breaches/russian-apt-releases-more-deadly-variant-of-acidrain-wiper-malware	darkreading	news;	4	2024-03-22	APT 俄罗斯释放的酸光Wiper Wiper Malware 更致命的替代物
23788	Digimarc and DataTrails join forces to provide proof of digital content authenticity	https://www.helpnetsecurity.com/2024/04/11/digimarc-datatrails-partnership/	helpnetsecurity	news;Industry news;DataTrails;Digimarc;	1	2024-04-11	Digimarc和DataTrails联手提供数字内容真实性的证据
9454	AWS CISO: Pay Attention to How AI Uses Your Data	https://www.darkreading.com/cloud-security/aws-ciso-cloud-customers-need-secure-ai-workloads	darkreading	news;	1	2024-03-22	AWS CISO:注意AI如何使用您的数据
9478	 Sign1 恶意软件感染了 3.9 万个 WordPress 网站	https://www.freebuf.com/news/395610.html	freebuf	news;资讯;	2	2024-03-22	Sign1 恶意软件感染了 3.9 万个 WordPress 网站
9470	shiro漏洞	https://www.freebuf.com/articles/network/395579.html	freebuf	news;网络安全;	3	2024-03-22	shiro漏洞
13652	On Hiatus	https://securityboulevard.com/2024/04/on-hiatus/	securityboulevard	news;Security Bloggers Network;	1	2024-04-02	在 Hiatus 上
9465	Apple Stingy With Details About Latest iOS Update	https://www.darkreading.com/vulnerabilities-threats/apple-is-sparse-with-details-in-latest-ios-update	darkreading	news;	1	2024-03-22	Apple Stingy 含有最新iOS最新更新细节的苹果存储器
9483	Thales SafeNet Sentinel HASP LDK本地提权漏洞（CVE-2024-0197）分析与复现	https://www.freebuf.com/vuls/395553.html	freebuf	news;漏洞;	5	2024-03-21	Thales SafeNet Sentinel HASP LDK本地提权漏洞（CVE-2024-0197）分析与复现
9481	AWS曝一键式漏洞，攻击者可接管Apache Airflow服务	https://www.freebuf.com/news/395687.html	freebuf	news;资讯;	3	2024-03-22	AWS曝一键式漏洞，攻击者可接管Apache Airflow服务
9469	一周网安优质PDF资源推荐丨FreeBuf知识大陆	https://www.freebuf.com/articles/395686.html	freebuf	news;资讯;	1	2024-03-22	一周网安优质PDF资源推荐丨FreeBuf知识大陆
9479	FreeBuf 周报 | 敲击键盘也可能泄露敏感信息？；日本科技巨头富士通遭遇网络攻击	https://www.freebuf.com/news/395630.html	freebuf	news;资讯;	1	2024-03-22	FreeBuf 周报 | 敲击键盘也可能泄露敏感信息？；日本科技巨头富士通遭遇网络攻击
9480	FreeBuf 早报 | API安全漏洞对企业财务的影响；Synopsys出售应用安全部门	https://www.freebuf.com/news/395663.html	freebuf	news;资讯;	3	2024-03-22	FreeBuf 早报 | API安全漏洞对企业财务的影响；Synopsys出售应用安全部门
8454	Understanding Your Attack Surface: AI or bust	https://securityboulevard.com/2024/03/understanding-your-attack-surface-ai-or-bust/	securityboulevard	news;Security Bloggers Network;asset inventory;CAASM;	1	2024-03-19	了解您的攻击表面: AI 或 bust
9414	China-Linked Group Breaches Networks via Connectwise, F5 Software Flaws	https://thehackernews.com/2024/03/china-linked-group-breaches-networks.html	feedburner	news;	4	2024-03-22	通过连接、F5软件法的中国连通集团违反网络
9413	AWS Patches Critical 'FlowFixation' Bug in Airflow Service to Prevent Session Hijacking	https://thehackernews.com/2024/03/aws-patches-critical-flowfixation-bug.html	feedburner	news;	1	2024-03-22	AWS 防止会中劫持的空气流服务中 关键“修花虫”错误的 AWS 补丁
9421	N. Korea-linked Kimsuky Shifts to Compiled HTML Help Files in Ongoing Cyberattacks	https://thehackernews.com/2024/03/n-korea-linked-kimsuky-shifts-to.html	feedburner	news;	3	2024-03-24	N. 将韩国链接的Kimsuky 转换为当前网络攻击中编译的 HTML 帮助文件
10511	Indian Government, Oil Companies Breached by 'HackBrowserData'	https://www.darkreading.com/cyberattacks-data-breaches/indian-government-breached-by-hackbrowserdata-information-stealer	darkreading	news;	1	2024-03-28	印度政府、石油公司被“黑帐公司Data”破坏
9420	Massive Sign1 Campaign Infects 39,000+ WordPress Sites with Scam Redirects	https://thehackernews.com/2024/03/massive-sign1-campaign-infects-39000.html	feedburner	news;	1	2024-03-22	大规模信号1 运动感染39,000个+有闪光中转的WordPress站点
9426	Russian Hackers Use 'WINELOADER' Malware to Target German Political Parties	https://thehackernews.com/2024/03/russian-hackers-use-wineloader-malware.html	feedburner	news;	3	2024-03-23	俄罗斯黑客使用 WINELOADEER 恶意攻击德国政党
9418	Implementing Zero Trust Controls for Compliance	https://thehackernews.com/2024/03/implementing-zero-trust-controls-for.html	feedburner	news;	1	2024-03-22	执行零信任控制履约
8535	Urban-Strategies	http://www.ransomfeed.it/index.php?page=post_details&id_post=13832	ransomfeed	ransom;medusa;	1	2024-03-19	城市战略
10501	A CISO's Guide to Materiality and Risk Determination	https://www.darkreading.com/cyber-risk/a-ciso-s-guide-to-materiality-and-risk-determination	darkreading	news;	1	2024-03-27	A. 独联体组织《重要性和风险确定指南》
10505	Corporations With Cyber Governance Create Almost 4X More Value	https://www.darkreading.com/cyber-risk/study-corporations-with-cyber-governance-create-almost-4x-more-value	darkreading	news;	1	2024-03-28	拥有网络治理的公司 创造近4X 更多价值
9415	German Police Seize 'Nemesis Market' in Major International Darknet Raid	https://thehackernews.com/2024/03/german-police-seize-nemesis-market-in.html	feedburner	news;	2	2024-03-24	德国警方在主要国际暗网突袭中发现“Nemesis市场”
9435	USENIX Security ’23 – ASSET: Robust Backdoor Data Detection Across a Multiplicity of Deep Learning Paradigms	https://securityboulevard.com/2024/03/usenix-security-23-asset-robust-backdoor-data-detection-across-a-multiplicity-of-deep-learning-paradigms/	securityboulevard	news;Security Bloggers Network;Security Conferences;USENIX;USENIX Security ’23;	1	2024-03-22	USENIX 安全 23 - ASSSET: 跨越多种深学习范式的强有力的后门数据探测
10506	US Puts Up $10M Bounty on BlackCat Ransomware Gang Members	https://www.darkreading.com/cyber-risk/us-10m-bounty-blackcat-ransomware-members	darkreading	news;	2	2024-03-28	美军对黑卡公司Ransomware Gang成员加注1 000万博恩蒂
9427	U.S. Justice Department Sues Apple Over Monopoly and Messaging Security	https://thehackernews.com/2024/03/us-justice-department-sues-apple-over.html	feedburner	news;	1	2024-03-22	美国司法部Sues Apple over 垄断和通信安全
10525	10 Steps to Detect, Prevent, and Remediate the Terrapin Vulnerability	https://www.darkreading.com/vulnerabilities-threats/10-steps-to-detect-prevent-and-remediate-the-terrapin-vulnerability	darkreading	news;	1	2024-03-27	10 检测、预防和补救Terripant脆弱性的步骤
9430	Federal, State, Local Cyber Leaders Meet to Discuss Threats	https://securityboulevard.com/2024/03/federal-state-local-cyber-leaders-meet-to-discuss-threats/	securityboulevard	news;Security Bloggers Network;	1	2024-03-24	联邦、州、州、地方网络领导人开会讨论威胁
9433	Splunk, Azure, or Sentinel for FedRAMP/NIST Compliance	https://securityboulevard.com/2024/03/splunk-azure-or-sentinel-for-fedramp-nist-compliance/	securityboulevard	news;Governance, Risk & Compliance;Security Bloggers Network;Compliance;	1	2024-03-23	美联储RAMP/NIST 合规的球体、Azure或哨兵
18187	How can the energy sector bolster its resilience to ransomware attacks?	https://www.helpnetsecurity.com/2024/04/08/energy-sector-attacks-resilience/	helpnetsecurity	news;Don't miss;Expert analysis;Expert corner;Hot stuff;News;access management;cybercriminals;cybersecurity;Delinea;energy sector;identity management;opinion;penetration testing;ransomware;strategy;	2	2024-04-08	能源部门如何加强其应对赎金软件袭击的复原力?
9422	New StrelaStealer Phishing Attacks Hit Over 100 Organizations in E.U. and U.S.	https://thehackernews.com/2024/03/new-strelastealer-phishing-attacks-hit.html	feedburner	news;	1	2024-03-22	美国和美国的100多个组织遭到新Strela Stealer Phishing攻击。
9840	Teton-Orthopaedics	http://www.ransomfeed.it/index.php?page=post_details&id_post=13929	ransomfeed	ransom;dragonforce;	1	2024-03-25	静脉矫形器
9431	Get A Day’s Schedule From Fantastical On The Command Line With Shortcuts	https://securityboulevard.com/2024/03/get-a-days-schedule-from-fantastical-on-the-command-line-with-shortcuts/	securityboulevard	news;Security Bloggers Network;macos;programming;	1	2024-03-23	使用快捷键从命令行的极妙列表中获取“一天”的调度表
9844	《银行保险机构数据安全管理办法（征求意见稿）》发布	https://www.freebuf.com/articles/395812.html	freebuf	news;	1	2024-03-25	《银行保险机构数据安全管理办法（征求意见稿）》发布
9434	Unsafelok Threat Highlights It’s About Both IoT Devices and Applications	https://securityboulevard.com/2024/03/unsafelok-threat-highlights-its-about-both-iot-devices-and-applications/	securityboulevard	news;IoT & ICS Security;Security Bloggers Network;Vulnerabilities;Blog;cyber;iot;remediation;	1	2024-03-23	有关 IoT 设备和应用的亮点
8859	House unanimously passes bill to block data brokers from selling Americans’ info to foreign adversaries	https://therecord.media/house-passes-bill-to-block-data-brokers-from-selling-info-to-foreign-adversaries	therecord	ransom;China;News;Privacy;	1	2024-03-21	众议院一致通过法案,阻止数据经纪人向外国对手出售美国人的信息
9487	CISA: Here’s how you can foil DDoS attacks	https://www.helpnetsecurity.com/2024/03/22/guidance-ddos-attacks/	helpnetsecurity	news;Don't miss;News;CISA;DDoS;guide;	1	2024-03-22	CISA:这里是如何挫败DDoS攻击的
9000	Social Engineering The #1 Root Cause Behind Most Cyber Crimes In FBI Report	https://blog.knowbe4.com/did-you-notice-how-much-fbi-other-crime-is-really-social-engineering	knowbe4	news;Social Engineering;Phishing;	1	2024-03-21	在联邦调查局的报告中, 大部分网络犯罪背后的第1号根本原因
18209	Google Sues App Developers Over Fake Crypto Investment App Scam	https://thehackernews.com/2024/04/google-sues-app-developers-over-fake.html	feedburner	news;	1	2024-04-08	Google Sues App 开发者克服假密码投资 App Scam
9493	Week in review: Ivanti fixes RCE vulnerability, Nissan breach affects 100,000 individuals	https://www.helpnetsecurity.com/2024/03/24/week-in-review-ivanti-fixes-rce-vulnerability-nissan-breach-affects-100000-individuals/	helpnetsecurity	news;News;Week in review;	1	2024-03-24	审查周:伊万提(Ivanti)解决了RCE脆弱性问题,尼桑违约影响到100 000人
9494	Bringing Access Back — Initial Access Brokers Exploit F5 BIG-IP (CVE-2023-46747) and ScreenConnect	https://www.mandiant.com/resources/blog/initial-access-brokers-exploit-f5-screenconnect	mandiant	news;	3	2024-03-21	利用F5 BIG-IP(CVE-2023-46747)和屏幕连接
9499	AceCryptor attacks surge in Europe – Week in security with Tony Anscombe	https://www.welivesecurity.com/en/videos/acecryptor-attacks-europe-week-security-tony-anscombe/	eset	news;	1	2024-03-22	在欧洲, 埃斯密人攻击事件激增 — — 与托尼·安斯科姆的“安全周 ” 。
9500	Hack The Box: Analytics Machine Walkthrough – Easy Difficulty	https://threatninja.net/2024/03/hack-the-box-analytics-machine-walkthrough-easy-difficulty/	threatninja	sectest;Easy Machine;BurpSuite;Challenges;CVE-2021-3493;CVE-2023-2640;CVE-2023-32629;CVE-2023-38646;docker;HackTheBox;Linux;Penetration Testing;python3;	1	2024-03-23	黑盒:分析机器走过 — — 容易困难
9501	Chenarkhayyam - Sql Injection And Waf , Cdn Bypass	https://cxsecurity.com/issue/WLB-2024030051	cxsecurity	vuln;	1	2024-03-24	Chenarkhayyyam - Sql 注射和Waf, Cdn Bypass
9502	minaliC 2.0.0 Denied of Service	https://cxsecurity.com/issue/WLB-2024030054	cxsecurity	vuln;	1	2024-03-24	2.0.0 拒绝服役
9504	Win32.STOP.Ransomware (smokeloader) / Remote Code Execution (MITM)	https://cxsecurity.com/issue/WLB-2024030052	cxsecurity	vuln;	2	2024-03-24	Win32.STOP.Ransomware(制烟器)/远程代码执行(MITM)
9505	Youtube Open Redirect Vulnerability	https://cxsecurity.com/issue/WLB-2024030053	cxsecurity	vuln;	1	2024-03-24	Youtube 开放式中转脆弱性
9506	Microsoft Outlook Remote Code Execution Vulnerability - CVE-2024-21413	https://cxsecurity.com/issue/WLB-2024030055	cxsecurity	vuln;	3	2024-03-24	微软 Outlook 远程代码执行脆弱性 -- -- CVE-2024-21413
9507	Quick-Cms_v6.7-en-2023-update SQLi	https://cxsecurity.com/issue/WLB-2024030056	cxsecurity	vuln;	1	2024-03-24	Quick-Cms_v6.7-en-2023 - 更新 SQLi
10527	Saudi Arabia, UAE Top List of APT-Targeted Nations in the Middle East	https://www.darkreading.com/vulnerabilities-threats/saudi-arabia-uae-top-list-of-apt-targeted-nations-in-middle-east	darkreading	news;	2	2024-03-28	沙特阿拉伯、阿联酋中东亚洲防止酷刑协会目标国家最高名单
10537	[New Feature] Start Coaching Your Users in Real Time With the New Google Chat Integration for KnowBe4's SecurityCoach	https://blog.knowbe4.com/securitycoach-google-chat-integration	knowbe4	news;Security Awareness Training;Security Culture;	1	2024-03-28	以新的谷歌聊天整合方式, 开始在实时训练您的用户, 用于 Knowbe4 的安全 Coach 。
10539	Agenda Ransomware Targets ESXi and vCenter Servers	https://threats.wiz.io/all-incidents/agenda-ransomware-targets-esxi-and-vcenter-servers	wizio	incident;	2	2024-03-28	Ransomware 目标 ESXi 和 vCenter 服务器
9521	Red Hat Security Advisory 2024-1468-03	https://packetstormsecurity.com/files/177728/RHSA-2024-1468-03.txt	packetstorm	vuln;;	1	2024-03-22	红色帽子安保咨询 2024-1468-03
9522	Red Hat Security Advisory 2024-1472-03	https://packetstormsecurity.com/files/177729/RHSA-2024-1472-03.txt	packetstorm	vuln;;	1	2024-03-22	红色帽子安保咨询 2024-1472-03
9523	Red Hat Security Advisory 2024-1473-03	https://packetstormsecurity.com/files/177730/RHSA-2024-1473-03.txt	packetstorm	vuln;;	1	2024-03-22	红色帽子安保咨询 2024-1473-03
9527	Ubuntu Security Notice USN-6708-1	https://packetstormsecurity.com/files/177734/USN-6708-1.txt	packetstorm	vuln;;	1	2024-03-22	Ubuntu Ubuntu 安全通知 USN-6708-1
9528	Debian Security Advisory 5643-1	https://packetstormsecurity.com/files/177735/dsa-5643-1.txt	packetstorm	vuln;;	1	2024-03-22	Debian安全咨询 5643-1
9526	Ubuntu Security Notice USN-6709-1	https://packetstormsecurity.com/files/177733/USN-6709-1.txt	packetstorm	vuln;;	1	2024-03-22	Ubuntu Ubuntu 安全通知 USN-6709-1
9524	Ubuntu Security Notice USN-6704-2	https://packetstormsecurity.com/files/177731/USN-6704-2.txt	packetstorm	vuln;;	1	2024-03-22	Ubuntu Ubuntu 安全通知 USN-6704-2
9530	Task Management System 1.0 SQL Injection	https://packetstormsecurity.com/files/177737/scphptms10-sql.txt	packetstorm	vuln;;	1	2024-03-22	任务管理系统1.0 SQL 输入
9537	Meta to shutter key disinformation tracking tool before 2024 election	https://therecord.media/meta-to-shutter-crowdtangle-disinformation-tracking-tool-before-election	therecord	ransom;Government;Industry;News;Technology;Elections;	1	2024-03-22	在2024年选举前将主要假信息追踪工具
9538	UN probing 58 alleged crypto heists by North Korea worth $3 billion	https://therecord.media/north-korea-cryptocurrency-hacks-un-experts	therecord	ransom;Nation-state;Cybercrime;News;	3	2024-03-22	联合国调查的58个 被北朝鲜指控的 加密谋杀者 价值30亿美元
9531	Proxmark3 4.18341 Custom Firmware	https://packetstormsecurity.com/files/177738/proxmark3-4.18341.tar.gz	packetstorm	vuln;;	1	2024-03-22	4.18341 定制企业
9557	Pentest-Muse-Cli - AI Assistant Tailored For Cybersecurity Professionals	https://buaq.net/go-230188.html	buaq	newscopy;	0	2024-03-24	Pentest-Muse-Cli - AI 网络安全专业人员助理助理
9558	Netflix 的《三体》在中国社媒平台引发争论	https://buaq.net/go-230189.html	buaq	newscopy;	0	2024-03-24	Netflix 的《三体》在中国社媒平台引发争论
9560	多邻国上线 DIY 虚拟头像制作功能：捏脸	https://buaq.net/go-230199.html	buaq	newscopy;	0	2024-03-24	多邻国上线 DIY 虚拟头像制作功能：捏脸
9556	想找一个带提醒功能，记录日常生活消耗品的工具｜电动牙刷头、净水器滤芯、汽车机油等	https://buaq.net/go-230187.html	buaq	newscopy;	0	2024-03-24	想找一个带提醒功能，记录日常生活消耗品的工具｜电动牙刷头、净水器滤芯、汽车机油等
9559	政府电脑限制采购英特尔 AMD 处理器	https://buaq.net/go-230190.html	buaq	newscopy;	0	2024-03-24	政府电脑限制采购英特尔 AMD 处理器
8250	USENIX Security ’23 – Network Responses To Russia’s Invasion of Ukraine In 2022: A Cautionary Tale For Internet Freedom	https://securityboulevard.com/2024/03/usenix-security-23-network-responses-to-russias-invasion-of-ukraine-in-2022-a-cautionary-tale-for-internet-freedom/	securityboulevard	news;Security Bloggers Network;Open Access Research;Security Conferences;Security Research;USENIX;USENIX Security ’23;	3	2024-03-18	USENIX 安全 23 - 2022年俄罗斯入侵乌克兰的网络反应:互联网自由的警告性故事
9562	怀孕会增加孕妇的生理年龄，但这一趋势能逆转	https://buaq.net/go-230201.html	buaq	newscopy;	0	2024-03-24	怀孕会增加孕妇的生理年龄，但这一趋势能逆转
9565	How to Build a $300 AI Computer for the GPU-Poor	https://buaq.net/go-230208.html	buaq	newscopy;	0	2024-03-24	如何为 GPU-poor 建立300 美元 AI 计算机
9564	Security Affairs newsletter Round 464 by Pierluigi Paganini – INTERNATIONAL EDITION	https://buaq.net/go-230207.html	buaq	newscopy;	0	2024-03-24	《安全事务通讯》第464期,
9568	抖音: 重定向跳转 -> XSS漏洞 -> 升级高危	https://buaq.net/go-230211.html	buaq	newscopy;	0	2024-03-24	抖音: 重定向跳转 -> XSS漏洞 -> 升级高危
9569	Mozilla rilascia aggiornamenti d’emergenza per Firefox dopo il Pwn2Own Vancouver 2024	https://buaq.net/go-230212.html	buaq	newscopy;	0	2024-03-25	2024年温哥华
9570	Read The Manual (RTM) Group: The Interview	https://buaq.net/go-230213.html	buaq	newscopy;	0	2024-03-25	阅读《手册(RTM)小组:访谈》
9571	Shrouded Horizons: My Passage to the Dark Web Marketplaces	https://buaq.net/go-230214.html	buaq	newscopy;	0	2024-03-25	破碎的地平线:我的黑暗网络市场通道
9572	How to Test Multiple Variations of Generative AI Prompts	https://buaq.net/go-230215.html	buaq	newscopy;	0	2024-03-25	如何测试生成 AI 提示的多种变化
9573	The Noonification: Effective Workarounds for SQL-Style Joins in Elasticsearch (3/24/2024)	https://buaq.net/go-230216.html	buaq	newscopy;	0	2024-03-25	说明:为SQL-Style Insearch中的SQL-Style 联合企业有效变通工作(3/24/2024)
9393	AI影片處理工具 VideoProc 限時免費 | 62% 折扣（立即購買並永久保留）	https://buaq.net/go-229816.html	buaq	newscopy;	0	2024-03-22	AI影片處理工具 VideoProc 限時免費 | 62% 折扣（立即購買並永久保留）
9541	Skytrack - Planespotting And Aircraft OSINT Tool Made Using Python	http://www.kitploit.com/2024/03/skytrack-planespotting-and-aircraft.html	kitploit	tool;Aircraft;Cybersecurity;Cybersecurity Tools;Planes;Planespotting;Skytrack;	1	2024-03-22	Skytrak - 利用Python制造的浮点和飞机OSINT工具
9543	绿盟科技威胁周报（2024.03.11-2024.03.17）	https://blog.nsfocus.net/weeklyreport202411/	绿盟	news;威胁通告;周报;威胁防护;	1	2024-03-22	绿盟科技威胁周报（2024.03.11-2024.03.17）
9545	GoFetch Side-Channel Attack Impact Apple CPUs: Attackers Steal Secret Keys	https://gbhackers.com/gofetch-side-channel-attack/	GBHacker	news;Apple;Cyber Security News;computer security;Vulnerability;	1	2024-03-23	GoFetch 侧气道攻击冲击冲击苹果 CPU:攻击者窃取秘密密钥
9546	Hackers Deploy STRRAT & VCURMS Malware on Windows Via GitHub	https://gbhackers.com/hackers-deploy-strrat-vcurms-malware-on-windows-via-github/	GBHacker	news;ANY RUN;Malware;Phishing;Spam;Cyber Security News;	1	2024-03-23	Hackers 在Windows Via GitHub上部署STRAT和VCUMS 磁盘
9547	One-Click AWS Vulnerability Let Attackers Takeover User’s Web Management Panel	https://gbhackers.com/one-click-aws-vulnerability/	GBHacker	news;Amazon AWS;AWS;Cyber Security News;Vulnerability;computer security;	1	2024-03-22	让攻击者接管用户的网络管理面板
9548	DHCP Hacked to Escalate Privileges in Windows Domains	https://gbhackers.com/researched-hacked-dhcp/	GBHacker	news;Cyber Security News;Hacks;Uncategorized;Windows;cyber security;	1	2024-03-22	DHCP 入入 Windows 域域的 Escalate 权限
9549	Sign1 Malware Hijacked 39,000 WordPress Websites	https://gbhackers.com/sign1-malware-hijacks-wordpress-sites/	GBHacker	news;Cyber Security News;Malware;Wordpress;Cybersecurity Analysis;malware campaign;WordPress security;	1	2024-03-24	恶意劫持39 000个WordPress网站
9550	TeamCity Vulnerability Exploits Leads to Surge in Ransomware Attacks	https://gbhackers.com/teamcity-vulnerability-exploits/	GBHacker	news;Cyber Attack;Cyber Security News;ransomware;	2	2024-03-22	导致Ransomware袭击暴增的团队脆弱性爆炸
9551	TinyTurla Evolved TTPs To Stealthly Attack Enterprise Organizations	https://gbhackers.com/tinyturla-evolved-ttps-stealth-attacks/	GBHacker	news;Cyber Attack;Cyber Security News;Malware;APT;cyber security;Malware Tactics;	1	2024-03-22	Tiny Turla 向隐形攻击企业组织发展TTPs
10544	制造业信息安全实践——企业信息安全运营规划	https://www.freebuf.com/articles/security-management/393411.html	freebuf	news;安全管理;	1	2024-03-26	制造业信息安全实践——企业信息安全运营规划
10545	libFuzzer漏洞挖掘总结教程	https://www.freebuf.com/articles/system/395965.html	freebuf	news;系统安全;	3	2024-03-26	libFuzzer漏洞挖掘总结教程
9554	Cybercriminals Accelerate Online Scams During Ramadan and Eid Fitr	https://buaq.net/go-230176.html	buaq	newscopy;	0	2024-03-24	斋月与斋月及斋月开斋节期间,
9555	Update: metatool.py Version 0.0.4	https://buaq.net/go-230186.html	buaq	newscopy;	0	2024-03-24	更新:元工具.py 0.0.4版本
10558	印度国防部被黑客打穿，泄露8.8GB数据	https://www.freebuf.com/news/396179.html	freebuf	news;资讯;	1	2024-03-28	印度国防部被黑客打穿，泄露8.8GB数据
9540	Pentest-Muse-Cli - AI Assistant Tailored For Cybersecurity Professionals	http://www.kitploit.com/2024/03/pentest-muse-cli-ai-assistant-tailored.html	kitploit	tool;Openai Api;Pentest;Pentest-Muse-Cli;Pentesting;Python;Testing;	1	2024-03-24	Pentest-Muse-Cli - AI 网络安全专业人员助理助理
9563	免费享受Dynu的DDNS服务：13个子域名任你挑选	https://buaq.net/go-230206.html	buaq	newscopy;	0	2024-03-25	免费享受Dynu的DDNS服务：13个子域名任你挑选
10559	Facebook被指控曾利用用户设备监视竞品软件	https://www.freebuf.com/news/396187.html	freebuf	news;资讯;	1	2024-03-28	Facebook被指控曾利用用户设备监视竞品软件
10555	中国银行业协会发布《银行业数据资产估值指南》	https://www.freebuf.com/news/396123.html	freebuf	news;资讯;	1	2024-03-27	中国银行业协会发布《银行业数据资产估值指南》
10561	thinkphp多语言RCE原理分析	https://www.freebuf.com/vuls/382680.html	freebuf	news;漏洞;	1	2024-03-28	thinkphp多语言RCE原理分析
9553	Microsoft Xbox Gaming Services Flaw Let Attackers Gain SYSTEM Privileges	https://gbhackers.com/xbox-gaming-services-privilege-escalation/	GBHacker	news;CVE/vulnerability;Cyber Security News;Exploit;cyber security;PrivilegeEscalation;XboxGamingServices;	1	2024-03-23	微软 Xbox 赌博服务
10546	浅谈Sql注入总结笔记整理(超详细)	https://www.freebuf.com/articles/web/339118.html	freebuf	news;Web安全;	1	2024-03-27	浅谈Sql注入总结笔记整理(超详细)
10557	FreeBuf 早报 | 印度国防、能源部门遭遇攻击；越南头部券商被黑导致服务中断	https://www.freebuf.com/news/396170.html	freebuf	news;资讯;	1	2024-03-28	FreeBuf 早报 | 印度国防、能源部门遭遇攻击；越南头部券商被黑导致服务中断
9532	GoFetch: Breaking Constant-Time Cryptographic Implementations Using Data Memory-Dependent Prefetchers	https://packetstormsecurity.com/files/177739/gofetch.pdf	packetstorm	vuln;;	1	2024-03-22	GoFetch: 使用数据内存依赖的预取工具断开常时加密功能
9439	A threat-informed roadmap for securing Kubernetes clusters (KubeCon EU 2024)	https://securitylabs.datadoghq.com/articles/threat-informed-roadmap-kubernetes-kubecon-eu-2024/	datadog	news;Research; kubernetes ; container security ;	1	2024-03-22	保障Kubernetes集群安全的威胁知情路线图(KUBCON EU 2024)
9497	Apple Chip Flaw Leaks Secret Encryption Keys	https://www.wired.com/story/apple-m-chip-flaw-leak-encryption-keys/	wired	news;Security;Security / Cyberattacks and Hacks;Security / National Security;Security / Privacy;Security / Security News;	1	2024-03-23	Apple Chip Flaw Leaks 秘密加密密钥
9536	Massive Russian missile barrage causes blackouts, internet outages across Ukraine	https://therecord.media/massive-missile-russian-barrage-internet-outages-blackouts	therecord	ransom;News;Nation-state;	3	2024-03-22	俄罗斯大规模导弹炮轰造成乌克兰全国的断电、互联网断电和断电
9544	Exploit Released For Critical Fortinet RCE Flaw: Patch Soon!	https://gbhackers.com/exploit-fortinet-rce-flaw-patch/	GBHacker	news;CVE/vulnerability;Cyber Security News;Exploit;CVE-2023-48788;cyber security;Fortinet RCE Flaw;	1	2024-03-22	利用它释放出的关键的Fortinet RCE Flaw: 帕奇快!
8637	US Defense Dept received 50,000 vulnerability reports since 2016	https://buaq.net/go-229091.html	buaq	newscopy;	0	2024-03-20	自2016年以来,美国国防部收到50 000份脆弱性报告
10549	北漂安服仔坦白局｜“月入一万”的副业分享	https://www.freebuf.com/fevents/396340.html	freebuf	news;活动;	1	2024-03-28	北漂安服仔坦白局｜“月入一万”的副业分享
8569	Can Thieves Steal Identities With Only a Name and Address?	https://www.mcafee.com/blogs/privacy-identity-protection/can-thieves-steal-identities-with-only-a-name-and-address/	mcafee	news;Privacy & Identity Protection;identity theft;Can someone steal identity with name and address?;Can identity be stolen with name and address;how to check if someone is using my address;	1	2024-03-19	只有姓名和地址的盗贼能窃取身份吗?
10548	FB 赠书第 106 期 | 《内网安全攻防：红队之路》 助你成为红队专家	https://www.freebuf.com/fevents/396244.html	freebuf	news;活动;	1	2024-03-28	FB 赠书第 106 期 | 《内网安全攻防：红队之路》 助你成为红队专家
10471	Google: Zero-Day Attacks Rise, Spyware and China are Dangers	https://securityboulevard.com/2024/03/google-zero-day-attacks-rise-spyware-and-china-are-dangers/	securityboulevard	news;Cloud Security;Cybersecurity;Data Security;Featured;Malware;Mobile Security;Network Security;News;Security Boulevard (Original);Social - Facebook;Social - LinkedIn;Social - X;Spotlight;Threat Intelligence;Vulnerabilities;China-linked Hackers;google-security;spyware;Zero Day Attacks;	4	2024-03-28	谷歌:零日攻击上升,间谍和中国是危险
8588	ZoneMinder Snapshots Remote Code Execution	https://packetstormsecurity.com/files/177639/zonemindersnapshots-exec.txt	packetstorm	vuln;;	1	2024-03-19	ZoneMinder 区抓图远程代码执行
9525	Ubuntu Security Notice USN-6700-2	https://packetstormsecurity.com/files/177732/USN-6700-2.txt	packetstorm	vuln;;	1	2024-03-22	Ubuntu Ubuntu 安全通知 USN-6700-2
10547	权限维持小记-ssh	https://www.freebuf.com/defense/382376.html	freebuf	news;攻防演练;	1	2024-03-28	权限维持小记-ssh
9486	Ex-Secret Service agent and convicted hacker share stage at GISEC Global	https://www.helpnetsecurity.com/2024/03/22/gisec-global-2024-session/	helpnetsecurity	news;Industry news;conferences;GISEC;	1	2024-03-22	刑侦局前特工和被定罪黑客分享GISEC全球股份
10560	iPhone 用户注意了，新型 Darcula 网络钓鱼“盯上”你们了	https://www.freebuf.com/news/396192.html	freebuf	news;资讯;	2	2024-03-28	iPhone 用户注意了，新型 Darcula 网络钓鱼“盯上”你们了
9492	Attackers are targeting financial departments with SmokeLoader malware	https://www.helpnetsecurity.com/2024/03/22/smokeloader-phishing/	helpnetsecurity	news;Don't miss;Hot stuff;News;finance;government;malware;Palo Alto Networks;phishing;spear-phishing;Ukraine;	1	2024-03-22	攻击者正在针对财务部门 使用烟雾操作器恶意软件
9651	Regina-Dental-Group	http://www.ransomfeed.it/index.php?page=post_details&id_post=13909	ransomfeed	ransom;medusa;	1	2024-03-23	Reginin- 期组
9485	US organizations targeted with emails delivering NetSupport RAT	https://www.helpnetsecurity.com/2024/03/22/emails-delivering-netsupport-rat/	helpnetsecurity	news;Don't miss;Hot stuff;News;malware;Perception Point;phishing;remote access trojan;social engineering;	1	2024-03-22	以提供网络支持RAT的电子邮件针对的美国组织
9567	USENIX Security ’23 – Jinwen Wang, Yujie Wang, Ao Li, Yang Xiao, Ruide Zhang, Wenjing Lou, Y. Thomas Hou, Ning Zhang – ARI: Attestation of Real-time Mission Execution Integrity	https://buaq.net/go-230210.html	buaq	newscopy;	0	2024-03-24	USENIX 安全 23 — — 金文王、王玉洁、秋李、杨晓、张瑞德、张文京、吴文京卢、Y.托马斯霍、张宁 — — 阿里:实时任务执行完整性的证明
9657	Gasconteccom	http://www.ransomfeed.it/index.php?page=post_details&id_post=13915	ransomfeed	ransom;cloak;	1	2024-03-24	天然气
8712	Hackers Posing as Law Firms Phish Global Orgs in Multiple Languages	https://www.darkreading.com/cyberattacks-data-breaches/hackers-posing-law-firms-phish-global-orgs-multiple-languages	darkreading	news;	1	2024-03-20	作为律师事务所的黑客游说者组织
9659	ACS	http://www.ransomfeed.it/index.php?page=post_details&id_post=13917	ransomfeed	ransom;hunters;	1	2024-03-24	ACS ACS ACS ACS ACS ACS ACS ACS ACS ACS ACS ACS ACS ACS ACS ACS ACS ACS ACS ACS ACS ACS
9646	newagesyscom	http://www.ransomfeed.it/index.php?page=post_details&id_post=13904	ransomfeed	ransom;cactus;	1	2024-03-22	新旧eagesscom
9756	Weekly Retro 1	https://buaq.net/go-230219.html	buaq	newscopy;	0	2024-03-25	每周回调1
8649	Imposter Syndrome Is an Invention: Interview With Angelina Severino, Design Lead at Gamgee Amsterdam	https://buaq.net/go-229111.html	buaq	newscopy;	0	2024-03-20	假冒综合症是一种发明:与Angelina Severino的访谈,Gamgee阿姆斯特丹的设计铅
10564	How CISOs tackle business payment fraud	https://www.helpnetsecurity.com/2024/03/28/cisos-payments-worry-video/	helpnetsecurity	news;Don't miss;Hot stuff;Video;artificial intelligence;BEC scams;CISO;cybersecurity;email;fraud;supply chain;Trustmi;video;	1	2024-03-28	CISO如何对付商业支付欺诈
9652	Impac-Mortgage-Holdings	http://www.ransomfeed.it/index.php?page=post_details&id_post=13910	ransomfeed	ransom;medusa;	1	2024-03-23	缺陷 - 流动 -- -- 托架
10563	AppViewX partners with Fortanix to address critical enterprise security challenges	https://www.helpnetsecurity.com/2024/03/28/appviewx-fortanix-partnership/	helpnetsecurity	news;Industry news;AppViewX;Fortanix;	1	2024-03-28	与Fortanix的AppViewX合作伙伴应对企业安全面临的关键挑战
10565	Patch actively exploited Microsoft SharePoint bug, CISA orders federal agencies (CVE-2023-24955)	https://www.helpnetsecurity.com/2024/03/28/cve-2023-24955-exploited/	helpnetsecurity	news;Don't miss;Hot stuff;News;CISA;enterprise;government;Synopsys;vulnerability;	3	2024-03-28	CISA命令联邦机构(CVE-2023-24955),并积极利用微软SharePoint错误(CVE-2023-24955)
9655	Pascoe-International	http://www.ransomfeed.it/index.php?page=post_details&id_post=13913	ransomfeed	ransom;raworld;	1	2024-03-23	帕斯科国际
8615	Pharmaceutical development company investigating cyberattack after LockBit posting	https://therecord.media/pharmaceutical-development-company-investigating-cyber-incident-lockbit	therecord	ransom;Cybercrime;Industry;News;	2	2024-03-19	Lock Bit张贴后调查网络攻击的制药公司
9757	Sandfly Security Receives Seed Funding from Gula Tech Adventures & Sorenson Capital	https://buaq.net/go-230220.html	buaq	newscopy;	0	2024-03-25	沙飞安全从古拉技术冒险和索伦森首都获得种子资金
9643	ptsmicoid	http://www.ransomfeed.it/index.php?page=post_details&id_post=13899	ransomfeed	ransom;qilin;	1	2024-03-21	Ptsmod 类固醇
9647	kelsononca	http://www.ransomfeed.it/index.php?page=post_details&id_post=13905	ransomfeed	ransom;cactus;	1	2024-03-22	Kelsononca( 开 开 开 开 开 开 开 开 开 开 开 开 开 开 开 开 开 开 开 开 开 开 开 开 开 开 开 开 开 开 开 开 开 开 开 开 开 开 开 开 开 开 开 开 开
9649	Bira-91	http://www.ransomfeed.it/index.php?page=post_details&id_post=13907	ransomfeed	ransom;bianlian;	1	2024-03-22	Bira-91比拉
9755	镜视界 | DevSecOps CI/CD 管道中数字供应链安全的集成策略	https://buaq.net/go-230218.html	buaq	newscopy;	0	2024-03-25	镜视界 | DevSecOps CI/CD 管道中数字供应链安全的集成策略
9658	Equatorial-Energia	http://www.ransomfeed.it/index.php?page=post_details&id_post=13916	ransomfeed	ransom;cloak;	1	2024-03-24	赤道-能源消耗
9656	Vhs-vaterstettende	http://www.ransomfeed.it/index.php?page=post_details&id_post=13914	ransomfeed	ransom;cloak;	1	2024-03-24	Vhs- vaterstettettende( 立方体)
9758	Understanding API Hashing and build a rainbow table for LummaStealer	https://buaq.net/go-230221.html	buaq	newscopy;	0	2024-03-25	理解 API 为 Lumma Steal 建造彩虹桌
9644	Casa-Santiveri	http://www.ransomfeed.it/index.php?page=post_details&id_post=13900	ransomfeed	ransom;qilin;	1	2024-03-22	Casa-Santiveri 保护组织
8652	供应链投毒预警 | 恶意Py组件tohoku-tus-iot-automation开展窃密木马投毒攻击	https://buaq.net/go-229121.html	buaq	newscopy;	0	2024-03-20	供应链投毒预警 | 恶意Py组件tohoku-tus-iot-automation开展窃密木马投毒攻击
8643	Ukraine cyber police arrested crooks selling 100 million compromised accounts	https://buaq.net/go-229097.html	buaq	newscopy;	0	2024-03-20	乌克兰网络警察逮捕了 卖一亿折损账户的骗子
9648	Chambers-Construction-Co	http://www.ransomfeed.it/index.php?page=post_details&id_post=13906	ransomfeed	ransom;bianlian;	1	2024-03-22	分庭-建筑合作会
9645	flynncompaniescom	http://www.ransomfeed.it/index.php?page=post_details&id_post=13901	ransomfeed	ransom;blackbasta;	1	2024-03-22	随身携带
9654	Title-Management-Inc	http://www.ransomfeed.it/index.php?page=post_details&id_post=13912	ransomfeed	ransom;raworld;	1	2024-03-23	标题-管理-Inc
9653	SchwarzGrantz	http://www.ransomfeed.it/index.php?page=post_details&id_post=13911	ransomfeed	ransom;raworld;	1	2024-03-23	施瓦兹-格兰茨
28668	OpenTable won't add first names, photos to old reviews after backlash	https://buaq.net/go-234214.html	buaq	newscopy;	0	2024-04-15	Opentable 在反弹后不会在旧评论中添加名、 照片
28669	Weekly Update 395	https://buaq.net/go-234222.html	buaq	newscopy;	0	2024-04-15	《每周最新更新》395
28670	微软4月安全更新多个产品高危漏洞通告	https://buaq.net/go-234224.html	buaq	newscopy;	0	2024-04-15	微软4月安全更新多个产品高危漏洞通告
10583	LMS-PHP-byoretnom23-v1.0 Multiple-SQLi	https://www.nu11secur1ty.com/2024/03/lms-php-byoretnom23-v10-multiple-sqli.html	nu11security	vuln;	1	2024-03-28	LMS-PHPP- byoretnonum23- v1.0 多SQLi
2684	Trellix secures sensitive and proprietary information with new protections for macOS	https://www.helpnetsecurity.com/2024/03/13/trellix-data-loss-prevention-endpoint-complete/	helpnetsecurity	news;Industry news;Trellix;	1	2024-03-13	Trellix 安全敏感和专有信息,为macOS提供新的保护
2974	MobSF: Open-source security research platform for mobile apps	https://www.helpnetsecurity.com/2024/03/14/mobsf-open-source-mobile-security-framework/	helpnetsecurity	news;Don't miss;Hot stuff;News;Android;code analysis;cybersecurity;GitHub;iOS;mobile;mobile apps;mobile devices;open source;software;	1	2024-03-14	MobSF:移动应用程序开放源安全研究平台
10566	Enterprises increasingly block AI transactions over security concerns	https://www.helpnetsecurity.com/2024/03/28/enterprise-ai-transactions/	helpnetsecurity	news;News;artificial intelligence;attacks;ChatGPT;cybersecurity;data protection;Generative AI;report;Zscaler;	1	2024-03-28	企业越来越多地以安全考虑为由阻止AI交易
10568	NHS Scotland confirms ransomware attackers leaked patients’ data	https://www.helpnetsecurity.com/2024/03/28/nhs-scotland-ransomware/	helpnetsecurity	news;Don't miss;Hot stuff;News;data leak;extortion;healthcare;ransomware;UK;	2	2024-03-28	NHS Scottland确认赎金软件袭击者泄露的病人数据
8872	Azorult Malware Abuses Google Sites To Steal Login Credentials	https://gbhackers.com/azorult-malware-google-sites/	GBHacker	news;Cyber Attack;Cyber Security News;Malware;AZORult Malware;cyber security;HTML Smuggling;	1	2024-03-20	Azorult 恶意恶意滥用谷歌网站以窃取登录证书
8868	对美国防部《2025财年国防预算申请报告》分析和解读	https://blog.nsfocus.net/defense-budget-reguest/	绿盟	news;安全分享;	1	2024-03-20	对美国防部《2025财年国防预算申请报告》分析和解读
2714	Election cybersecurity: Protecting the ballot box and building trust in election integrity	https://www.welivesecurity.com/en/critical-infrastructure/election-cybersecurity-protecting-ballot-box-building-trust-election-integrity/	eset	news;	1	2024-03-12	选举网络安全:保护投票箱,建立对选举廉正的信任
2689	Microsoft Copilot for Security is generally available on April 1, 2024, with new capabilities	https://www.microsoft.com/en-us/security/blog/2024/03/13/microsoft-copilot-for-security-is-generally-available-on-april-1-2024-with-new-capabilities/	microsoft	news;	1	2024-03-13	通常在2024年4月1日提供有新能力的微软安保副副驾驶员
2742	MSMS-PHP 1.0 SQL Injection	https://packetstormsecurity.com/files/177557/msmsphp10-sql.txt	packetstorm	vuln;;	1	2024-03-13	MSMS-PHP 1.0 SQL 注射
2757	LockBit administrator sentenced to almost four years in prison after guilty plea	https://therecord.media/lockbit-administrator-mikhail-vasiliev-sentenced-canada	therecord	ransom;Cybercrime;News;	2	2024-03-13	LockBit管理员在认罪后被判处近四年监禁
10574	Guide: Protecting Your Digital Identity	https://www.mcafee.com/blogs/privacy-identity-protection/guide-protecting-your-digital-identity/	mcafee	news;Internet Security;Privacy & Identity Protection;digital identity;identity security;	1	2024-03-28	指南:保护你的数字身份
4881	Membership Management System 1.0 SQL Injection / Shell Upload	https://packetstormsecurity.com/files/177608/mms10-sqlshell.txt	packetstorm	vuln;;	1	2024-03-15	成员管理系统1.0 SQL 注射/壳牌上传
10567	Cybercriminals use cheap and simple infostealers to exfiltrate data	https://www.helpnetsecurity.com/2024/03/28/identity-based-attacks-rise/	helpnetsecurity	news;News;cybercrime;data breach;identity;malware;passwords;report;SpyCloud;survey;	1	2024-03-28	网络犯罪分子利用廉价和简单的信息偷盗者来撤出数据
8839	Red Hat Security Advisory 2024-1424-03	https://packetstormsecurity.com/files/177694/RHSA-2024-1424-03.txt	packetstorm	vuln;;	1	2024-03-20	红色帽子安保咨询 2024-1424-03
10580	古董级木马？Delphi木马之CyberGate RAT加解密技术剖析	https://xz.aliyun.com/t/14192	阿里先知实验室	news;	1	2024-03-27	古董级木马？Delphi木马之CyberGate RAT加解密技术剖析
8772	interluxurycom	http://www.ransomfeed.it/index.php?page=post_details&id_post=13844	ransomfeed	ransom;blackbasta;	1	2024-03-20	通 通 通 通 通 通 通 通 通 通 通 通 通 通 通 通 通 通 通 通 通 通 通 通 通 通 通 通 通 通 通 通 通 通 通 通 通 通 通 通 通 通 通 通 通 通 通 通 通 通 通 通 通 通 通 通 通 通 通 通 通 通 通 通 通 通 通 通 通 通 通
10570	Debunking compliance myths in the digital era	https://www.helpnetsecurity.com/2024/03/28/soc-2-report-compliance/	helpnetsecurity	news;Don't miss;Expert analysis;Expert corner;Hot stuff;News;auditing;compliance;cybersecurity;framework;MJD Advisors;opinion;security testing;	1	2024-03-28	在数字时代破解守法神话
10571	Zero-day exploitation surged in 2023, Google finds	https://www.helpnetsecurity.com/2024/03/28/zero-day-exploitation-2023/	helpnetsecurity	news;Don't miss;Hot stuff;News;0-day;APT;cybercrime;exploit;Google;Mandiant;spyware;	1	2024-03-28	2023年零日开采在2023年猛增 谷歌发现
10572	Teen Slang – What You Need To Know To Understand Your Teen	https://www.mcafee.com/blogs/family-safety/teen-slang-what-you-need-to-know-to-understand-your-teen/	mcafee	news;Family Safety;	1	2024-03-28	青少年-你需要知道什么才能理解你的青少年
3076	Saveitforparts: Building a Satellite Antenna from an Emergency Blanket and a Rotator from an old Security Camera Mount	https://buaq.net/go-228014.html	buaq	newscopy;	0	2024-03-14	Saveitforparts: 从应急毯子和从旧的安保摄像头挂起的旋转器中 建立一个卫星天线
8726	After LockBit, ALPHV Takedowns, RaaS Startups Go on a Recruiting Drive	https://www.darkreading.com/threat-intelligence/after-lockbit-alphv-takedowns-raas-recruiting-drive	darkreading	news;	2	2024-03-20	在LockBit,ALPHV 收起后,RaaS 启动后,
10581	连接器内存马-handle	https://xz.aliyun.com/t/14199	阿里先知实验室	news;	1	2024-03-27	连接器内存马-handle
10582	AsyncRAT C2 服务端主动发现工具	https://xz.aliyun.com/t/14201	阿里先知实验室	news;	1	2024-03-27	AsyncRAT C2 服务端主动发现工具
10569	Snowflake Data Clean Rooms helps organizations preserve the privacy of their data	https://www.helpnetsecurity.com/2024/03/28/snowflake-data-clean-rooms/	helpnetsecurity	news;Industry news;Snowflake;	1	2024-03-28	雪花数据清洁室帮助各组织保护其数据的隐私
28894	lockbit：持续进化的勒索威胁	https://buaq.net/go-234247.html	buaq	newscopy;	0	2024-04-15	lockbit：持续进化的勒索威胁
28895	TLS指纹在Bot对抗中的应用实践	https://buaq.net/go-234248.html	buaq	newscopy;	0	2024-04-15	TLS指纹在Bot对抗中的应用实践
186	How to Identify and Protect Yourself From Venmo Scams and Other Cash App Scams	https://www.mcafee.com/blogs/internet-security/how-to-identify-and-protect-yourself-from-venmo-scams-and-other-cash-app-scams/	mcafee	news;Internet Security;venmo scams;cashapp scams;	1	2024-03-06	如何识别和保护自己免受Venmo Scams和其他现金应用程序垃圾夹的影响
9144	DNS-Tunnel-Keylogger - Keylogging Server And Client That Uses DNS Tunneling/Exfiltration To Transmit Keystrokes	http://www.kitploit.com/2024/03/dns-tunnel-keylogger-keylogging-server.html	kitploit	tool;Cybersecurity;Dns Exfiltration;DNS Tunneling;DNS-Tunnel-Keylogger;Post Exploitation;Tunnel;Windows;	1	2024-03-21	DNS-Tunnel-Keylogger - Keylogging Server And Client That Uses DNS Tunneling/Exfiltration To Transmit Keystrokes
10606	Workout Journal App 1.0 Cross Site Scripting	https://packetstormsecurity.com/files/177821/workoutjournal10-xss.txt	packetstorm	vuln;;	1	2024-03-28	《日刊》第1.0号 跨站点脚本
335	Simple Inventory Management System v1.0 email SQL Injection	https://cxsecurity.com/issue/WLB-2024020090	cxsecurity	vuln;	1	2024-02-27	简单库存管理系统 v1.0 电子邮件 SQL 输入
9438	VulnCheck’s Free Community KEV & CVE APIs  (Code & Golang CLI Utility)	https://securityboulevard.com/2024/03/vulnchecks-free-community-kev-cve-apis-code-golang-cli-utility/	securityboulevard	news;Security Bloggers Network;Vulnerabilities;APIs;Cybersecurity;	3	2024-03-23	Vulncheck的自由社区 KEV 和 CVE APIs (Code & Goloneg CLI 公用事业)
737	Merchant-ID-	http://www.ransomfeed.it/index.php?page=post_details&id_post=13622	ransomfeed	ransom;ransomhub;	1	2024-03-07	商机 商机 商机 商机 商机 商机 商机 商机 商机 商机 商机 商机 商机 商机 商机 商机 商机 商机 商机 商机 商机
9482	全国网安标委发布 GBT 43697-2024《数据安全技术 数据分类分级规则》	https://www.freebuf.com/news/395695.html	freebuf	news;资讯;	1	2024-03-22	全国网安标委发布 GBT 43697-2024《数据安全技术 数据分类分级规则》
9542	Sr2T - Converts Scanning Reports To A Tabular Format	http://www.kitploit.com/2024/03/sr2t-converts-scanning-reports-to.html	kitploit	tool;RDP;Scanning;SMB;Sr2T;SSH;TLS;VNC;Weakness;Windows;XSS;	1	2024-03-23	Sr2T - 将扫描报告转换为表格格式
10602	LMS-PHP-byoretnom23-v1.0 Multiple-SQLi	https://cxsecurity.com/issue/WLB-2024030067	cxsecurity	vuln;	1	2024-03-28	LMS-PHPP- byoretnonum23- v1.0 多SQLi
10587	Jeffrey Epstein’s Island Visitors Exposed by Data Broker	https://www.wired.com/story/jeffrey-epstein-island-visitors-data-broker-leak/	wired	news;Security;Security / Privacy;Security / Security News;	1	2024-03-28	Jeffrey Epstein的《岛岛访客》,由数据经纪人举办
10605	LMS PHP 1.0 SQL Injection	https://packetstormsecurity.com/files/177820/lmsphp10-sql.txt	packetstorm	vuln;;	1	2024-03-28	LMS LMS PHP 1.0 SQL 注射
5871	随着互联网的发展BitTorrent不再是流量王者 网盘和在线视频杀死了BT协议	https://buaq.net/go-228716.html	buaq	newscopy;	0	2024-03-18	随着互联网的发展BitTorrent不再是流量王者 网盘和在线视频杀死了BT协议
8942	USENIX Security ’23 – Sparsity Brings Vulnerabilities: Exploring New Metrics in Backdoor Attacks	https://securityboulevard.com/2024/03/usenix-security-23-sparsity-brings-vulnerabilities-exploring-new-metrics-in-backdoor-attacks/	securityboulevard	news;Security Bloggers Network;Open Access Research;Security Conferences;USENIX;USENIX Security ’23;	1	2024-03-21	USENIX 安全 23 — — 公平带来脆弱性:探索后门攻击的新措施
10607	Purei CMS 1.0 SQL Injection	https://packetstormsecurity.com/files/177822/pureicms10-sql.txt	packetstorm	vuln;;	1	2024-03-28	Purei CMS 1.0 SQL 注射
8447	Threat landscape for industrial automation systems. H2 2023	https://securelist.com/threat-landscape-for-industrial-automation-systems-h2-2023/112153/	securelist	news;Industrial threats;Industrial control systems;Malware Statistics;Miner;Phishing;Ransomware;Spyware;Trojan;Worm;Industrial threats;	1	2024-03-19	工业自动化系统面临的威胁环境。
9566	C#: From Fundamentals to Advanced Techniques - A Beginner-Friendly CheatSheet	https://buaq.net/go-230209.html	buaq	newscopy;	0	2024-03-24	C # C: 从基本原理到先进技术 - 初学者亲爱的剪刀
9972	Daniel Stori’s ‘The Real Reason Not To Use sigkill (Revamp)’	https://securityboulevard.com/2024/03/daniel-storis-the-real-reason-not-to-use-sigkill-revamp/	securityboulevard	news;Security Bloggers Network;Daniel Stori;Linux Commands;Linux Sarcasm;Linux Satire;turnoff.us;	1	2024-03-26	Daniel Storori的《不使用igkill(Revamp)的真正理由》(Revamp)》
10604	Siklu MultiHaul TG series <  2.0.0 unauthenticated credential disclosure	https://cxsecurity.com/issue/WLB-2024030069	cxsecurity	vuln;	1	2024-03-28	Siklu MultiHaul TG系列 < 2.0.0 未认证的证书披露
10603	KiTTY 0.76.1.13 Start Duplicated Session Hostname Buffer Overflow	https://cxsecurity.com/issue/WLB-2024030068	cxsecurity	vuln;	1	2024-03-28	KTTTY 0.76.1.1.13 开始重复的会话 Hostname 缓冲缓冲流
9863	8 cybersecurity predictions shaping the future of cyber defense	https://www.helpnetsecurity.com/2024/03/25/cybersecurity-leaders-strategic-planning/	helpnetsecurity	news;News;access management;CISO;cybersecurity;data loss prevention;Gartner;Generative AI;identity management;regulation;report;risk management;strategy;zero trust;	1	2024-03-25	形成网络防御未来的8项网络安全预测
8800	Ivanti fixes RCE vulnerability reported by NATO cybersecurity researchers (CVE-2023-41724)	https://www.helpnetsecurity.com/2024/03/20/cve-2023-41724-cve-2023-46808/	helpnetsecurity	news;Don't miss;Hot stuff;News;enterprise;Ivanti;NATO;security update;vulnerability;	3	2024-03-20	Ivanti修复北约网络安全研究人员报告的RCE脆弱性(CVE-2023-41724)
10610	Red Hat Security Advisory 2024-1538-03	https://packetstormsecurity.com/files/177825/RHSA-2024-1538-03.txt	packetstorm	vuln;;	1	2024-03-28	红色帽子安保咨询2024-1538-03
24439	Ivanti empowers IT and security teams with new solutions and enhancements	https://www.helpnetsecurity.com/2024/04/11/ivanti-neurons-for-easm/	helpnetsecurity	news;Industry news;Ivanti;	1	2024-04-11	Ivanti 赋予信息技术和安保团队以新的解决方案和加强新解决方案的能力
24442	Ransomware group maturity should influence ransom payment decision	https://www.helpnetsecurity.com/2024/04/11/ransomware-payment-decision/	helpnetsecurity	news;Don't miss;Hot stuff;News;cybercriminals;extortion;GuidePoint Security;ransomware;SMBs;tips;	2	2024-04-11	Ransomware 集体成熟度应影响赎金支付决定
24444	CISA warns about Sisense data breach	https://www.helpnetsecurity.com/2024/04/11/sisense-data-breach/	helpnetsecurity	news;Don't miss;Hot stuff;News;CISA;credentials;data breach;Sisense;	1	2024-04-11	CISA警告Sissense数据被破坏
24450	The Best Personal Safety Devices, Apps, and Wearables (2024)	https://www.wired.com/story/best-personal-safety-tech/	wired	news;Gear;Gear / Buying Guides;Gear / Products / Lifestyle;Security;	1	2024-04-11	最佳个人安全装置、辅助装置和服装(2024年)
22189	攻亦是防，防亦是攻---Linux内核视角看权限维持	https://www.freebuf.com/articles/system/397481.html	freebuf	news;系统安全;	1	2024-04-10	攻亦是防，防亦是攻---Linux内核视角看权限维持
24455	Apple notifies users in 92 countries about mercenary spyware attacks	https://therecord.media/apple-spyware-notifications-92-countries	therecord	ransom;Privacy;Technology;News;Nation-state;	1	2024-04-11	苹果公司向92个国家的用户通报雇佣军间谍器械攻击事件
24456	CISA: Email from federal agencies possibly accessed in Russian breach of Microsoft	https://therecord.media/cisa-microsoft-breach-emergency-directive	therecord	ransom;Government;Nation-state;News;	3	2024-04-11	CISA: 联邦机构发来的电子邮件 可能因俄罗斯违反微软
24457	Vulnerabilities in end-of-life D-Link devices are being exploited, CISA says	https://therecord.media/dlink-devices-exploited-vulnerabilities-cisa	therecord	ransom;Technology;News;News Briefs;	1	2024-04-11	CISA指出,正在对报废D-链接装置的脆弱程度进行利用。
10174	USENIX Security ’23 – Automata-Guided Control-Flow-Sensitive Fuzz Driver Generation	https://securityboulevard.com/2024/03/usenix-security-23-automata-guided-control-flow-sensitive-fuzz-driver-generation/	securityboulevard	news;Security Bloggers Network;Open Access Research;Security Conferences;Security Research;USENIX;USENIX Security ’23;	1	2024-03-27	USENIX 安全 23 — — 自动马塔制导控制 — — 敏敏度低的引信驱动器生成
10612	Red Hat Security Advisory 2024-1544-03	https://packetstormsecurity.com/files/177827/RHSA-2024-1544-03.txt	packetstorm	vuln;;	1	2024-03-28	红色帽子安保咨询 2024-1544-03
10613	Red Hat Security Advisory 2024-1545-03	https://packetstormsecurity.com/files/177828/RHSA-2024-1545-03.txt	packetstorm	vuln;;	1	2024-03-28	红色帽子安保咨询2024-1545-03
3809	Debian Security Advisory 5639-1	https://packetstormsecurity.com/files/177607/dsa-5639-1.txt	packetstorm	vuln;;	1	2024-03-14	Debian安全咨询 5639-1
10611	Red Hat Security Advisory 2024-1543-03	https://packetstormsecurity.com/files/177826/RHSA-2024-1543-03.txt	packetstorm	vuln;;	1	2024-03-28	红色帽子安保咨询 2024-1543-03
72	USENIX Security ’23 – PELICAN: Exploiting Backdoors of Naturally Trained Deep Learning Models In Binary Code Analysis	https://securityboulevard.com/2024/03/usenix-security-23-pelican-exploiting-backdoors-of-naturally-trained-deep-learning-models-in-binary-code-analysis/	securityboulevard	news;Security Bloggers Network;Open Access Research;Security Conferences;Security Research;USENIX;USENIX Security ’23;	1	2024-03-11	USENIX 安全 23 - PELICAN:在二进制代码分析中利用天然训练深学习模型的后门
23104	THM — Grep	https://infosecwriteups.com/thm-grep-f360bbc9fb24?source=rss----7b722bfd1b8d---4	infosecwriteups	tech;writing;technology;medium;learning;tryhackme;	1	2024-04-11	THM - 转
8561	Drata unveils Adaptive Automation for streamlined compliance	https://www.helpnetsecurity.com/2024/03/19/drata-adaptive-automation/	helpnetsecurity	news;Industry news;Drata;	2	2024-03-19	Drata 揭开简化合规的适应性自动化
8243	Mastering X and Twitter Takedowns: How to Handle Brand Impersonations	https://securityboulevard.com/2024/03/mastering-x-and-twitter-takedowns-how-to-handle-brand-impersonations/	securityboulevard	news;Security Bloggers Network;advertisement;brand impersonation;brand protection;Cybersecurity;delete;fake;Impersonation Takedown;page;post;profile;remove;social media;spoofing;takedown;Twitter;Twitter Impersonation;website takedown;X;	1	2024-03-18	掌握X和Twitter的上台:如何处理品牌的面孔
2539	Microsoft’s February 2024 Patch Tuesday Addresses 2 Zero-Days and 73 Vulnerabilities	https://securityboulevard.com/2024/03/microsofts-february-2024-patch-tuesday-addresses-2-zero-days-and-73-vulnerabilities-2/	securityboulevard	news;Security Bloggers Network;Blog;	1	2024-03-13	2024年2月 微软2024年2月
24459	Attack on data analytics company Sisense prompts alert from CISA	https://therecord.media/sisense-cyberattack-cisa-warning	therecord	ransom;Technology;Industry;News;	1	2024-04-11	攻击数据分析公司Sissense 促使CISA发出警报
10608	Apple Security Advisory 03-25-2024-2	https://packetstormsecurity.com/files/177823/APPLE-SA-03-25-2024-2.txt	packetstorm	vuln;;	1	2024-03-28	苹果安全咨询 03-25-2024-2
24471	Python's PyPI Reveals Its Secrets	https://thehackernews.com/2024/04/gitguardian-report-pypi-secrets.html	feedburner	news;	1	2024-04-11	Python的PypPI 泄露其秘密
10609	Ubuntu Security Notice USN-6686-5	https://packetstormsecurity.com/files/177824/USN-6686-5.txt	packetstorm	vuln;;	1	2024-03-28	Ubuntu Ubuntu 安全通知 USN6686-5
9140	Biden taps cyber policy veteran for new Pentagon post	https://therecord.media/biden-taps-cyber-policy-veteran-for-new-pentagon-post	therecord	ransom;Government;Leadership;News;News Briefs;People;	1	2024-03-21	为五角大楼新职位的网络政策退伍军人
28898	企业需要实施的10项重点网络（信息）安全策略	https://buaq.net/go-234251.html	buaq	newscopy;	0	2024-04-15	企业需要实施的10项重点网络（信息）安全策略
28899	产业观察 | Zscaler意向收购初创SASE安全厂商 Airgap Network	https://buaq.net/go-234252.html	buaq	newscopy;	0	2024-04-15	产业观察 | Zscaler意向收购初创SASE安全厂商 Airgap Network
28900	A week in security (April 8 &#8211; April 14)	https://buaq.net/go-234253.html	buaq	newscopy;	0	2024-04-15	安全一周( 4月8日 8211; 4月14日)
28901	/r/ReverseEngineering's Weekly Questions Thread	https://buaq.net/go-234254.html	buaq	newscopy;	0	2024-04-15	/r/反反工程周刊问题线索
8458	Oracle warns that macOS 14.4 update breaks Java on Apple CPUs	https://www.bleepingcomputer.com/news/apple/oracle-warns-that-macos-144-update-breaks-java-on-apple-cpus/	bleepingcomputer	news;Apple;	1	2024-03-19	Oracle 警告 苹果 CPU 上的 MacOS 14. 4 更新 Java 休息时间
9529	Debian Security Advisory 5644-1	https://packetstormsecurity.com/files/177736/dsa-5644-1.txt	packetstorm	vuln;;	1	2024-03-22	Debian安全咨询 5644-1
302	Here Come the AI Worms	https://www.wired.com/story/here-come-the-ai-worms/	wired	news;Security;Security / Cyberattacks and Hacks;Security / Security News;Business / Artificial Intelligence;	1	2024-03-01	来来来来来来来来来来来来来来来来来来来来来来来来来来来来来来来来来
10614	Red Hat Security Advisory 2024-1549-03	https://packetstormsecurity.com/files/177829/RHSA-2024-1549-03.txt	packetstorm	vuln;;	1	2024-03-28	红色帽子安保咨询2024-1549-03
18291	Inno-soft-Info-Systems-Pte-Ltd	http://www.ransomfeed.it/index.php?page=post_details&id_post=14150	ransomfeed	ransom;8base;	1	2024-04-08	无软信息系统- Pte- In- Soft- Info- Systems- Pte- Ltd
10617	Dell Security Management Server Privilege Escalation	https://packetstormsecurity.com/files/177832/dsms-escalate.txt	packetstorm	vuln;;	1	2024-03-28	戴尔安全管理服务器
10622	FusionPBX Session Fixation	https://packetstormsecurity.com/files/177837/fusionpbx-fixation.txt	packetstorm	vuln;;	1	2024-03-28	FisionPBX 会话固定
10629	Ubuntu Security Notice USN-6715-1	https://packetstormsecurity.com/files/177844/USN-6715-1.txt	packetstorm	vuln;;	1	2024-03-28	Ubuntu Ubuntu 安全通知 USN-6715-1
10628	Ubuntu Security Notice USN-6719-1	https://packetstormsecurity.com/files/177843/USN-6719-1.txt	packetstorm	vuln;;	1	2024-03-28	Ubuntu Ubuntu 安全通知 USN-6719-1
10618	Red Hat Security Advisory 2024-1554-03	https://packetstormsecurity.com/files/177833/RHSA-2024-1554-03.txt	packetstorm	vuln;;	1	2024-03-28	红色帽子安保咨询2024-1554-03
10625	util-linux wall Escape Sequence Injection	https://packetstormsecurity.com/files/177840/utillinuxwall-inject.txt	packetstorm	vuln;;	1	2024-03-28	util-linux 墙
10615	Red Hat Security Advisory 2024-1552-03	https://packetstormsecurity.com/files/177830/RHSA-2024-1552-03.txt	packetstorm	vuln;;	1	2024-03-28	红色帽子安保咨询 2024-1552-03
9981	Windows 11 KB5035942 update enables Moment 5 features for everyone	https://www.bleepingcomputer.com/news/microsoft/windows-11-kb5035942-update-enables-moment-5-features-for-everyone/	bleepingcomputer	news;Microsoft;	1	2024-03-26	Windows 11 KB5035942 更新 Windows 11 KB5035942 启用每个人的5分钟功能
9971	Complex Supply Chain Attack Targets GitHub Developers	https://securityboulevard.com/2024/03/complex-supply-chain-attack-targets-github-developers/	securityboulevard	news;Cloud Security;Cybersecurity;Data Security;DevOps;Featured;Identity & Access;Incident Response;Industry Spotlight;Malware;Network Security;News;Security Boulevard (Original);Social - Facebook;Social - LinkedIn;Social - X;Spotlight;developers;GitHub;software supply chain attack;	1	2024-03-26	复杂供应链攻击目标
9432	RaaS Groups Go Recruiting in Wake of LockBit, BlackCat Takedowns	https://securityboulevard.com/2024/03/raas-groups-go-recruiting-in-wake-of-lockbit-blackcat-takedowns/	securityboulevard	news;Cyberlaw;Cybersecurity;Data Security;Featured;Malware;Network Security;News;Security Boulevard (Original);Social - Facebook;Social - LinkedIn;Social - X;Spotlight;Threat Intelligence;affiliates;RaaS;Ransomware;	2	2024-03-22	RaaS集团在洛克比醒来后招募新兵,
10616	Red Hat Security Advisory 2024-1553-03	https://packetstormsecurity.com/files/177831/RHSA-2024-1553-03.txt	packetstorm	vuln;;	1	2024-03-28	红色帽子安保咨询2024-1553-03
10620	Red Hat Security Advisory 2024-1557-03	https://packetstormsecurity.com/files/177835/RHSA-2024-1557-03.txt	packetstorm	vuln;;	1	2024-03-28	红色帽子安保咨询2024-1557-03
10621	Apple Security Advisory 03-25-2024-1	https://packetstormsecurity.com/files/177836/APPLE-SA-03-25-2024-1.txt	packetstorm	vuln;;	1	2024-03-28	苹果安全咨询 03-25-2024-1
10619	Red Hat Security Advisory 2024-1555-03	https://packetstormsecurity.com/files/177834/RHSA-2024-1555-03.txt	packetstorm	vuln;;	1	2024-03-28	红色帽子安保咨询2024-1555-03
10623	Circontrol Raption Buffer Overflow / Command Injection	https://packetstormsecurity.com/files/177838/circontrolraption-overflowexec.txt	packetstorm	vuln;;	2	2024-03-28	中枢控制 呼吸缓冲 过流 / 命令喷射
10626	Event Management 1.0 SQL Injection	https://packetstormsecurity.com/files/177841/eventmanagement10-sql.txt	packetstorm	vuln;;	1	2024-03-28	事件管理 1.0 SQL 注射
9980	Windows 10 KB5035941 update released with lock screen widgets	https://www.bleepingcomputer.com/news/microsoft/windows-10-kb5035941-update-released-with-lock-screen-widgets/	bleepingcomputer	news;Microsoft;	1	2024-03-26	Windows 10 KB5035941 以锁定屏幕部件发布最新消息
9978	The Path to 90-Day Certificate Validity: Challenges Facing Organizations	https://securityboulevard.com/2024/03/the-path-to-90-day-certificate-validity-challenges-facing-organizations/	securityboulevard	news;Security Bloggers Network;Certificate Services;	1	2024-03-26	90天证书有效期之路:各组织面临的挑战
10627	Wireshark Analyzer 4.2.4	https://packetstormsecurity.com/files/177842/wireshark-4.2.4.tar.xz	packetstorm	vuln;;	1	2024-03-28	4.2.4 无线电电阻分析器 4.2.4
18290	DUNN-PITTMAN-SKINNER-and-CUSHMAN-PLLC	http://www.ransomfeed.it/index.php?page=post_details&id_post=14149	ransomfeed	ransom;8base;	1	2024-04-08	DUNN-PITMAN-SKINNER-SKINNER-CUSHM-PLLC (德国)
10624	IWCC 2024 Call For Papers	https://packetstormsecurity.com/files/177839/iwcc2024-cfp.txt	packetstorm	vuln;;	1	2024-03-28	IWPC 2024呼吁提供文件
9491	Shadow AI is the latest cybersecurity threat you need to prepare for	https://www.helpnetsecurity.com/2024/03/22/shadow-ai-risks/	helpnetsecurity	news;Don't miss;Expert analysis;Expert corner;Hot stuff;News;artificial intelligence;cybersecurity;Generative AI;opinion;risk;shadow IT;Snow Software;	1	2024-03-22	影子AI是最新的网络安全威胁 你需要做好准备
9561	Obs158｜Copilot for Obsidian自訂提示詞與命令	https://buaq.net/go-230200.html	buaq	newscopy;	0	2024-03-24	Obs158｜Copilot for Obsidian自訂提示詞與命令
18296	Cloudflare Acquires Baselime to Enhance Serverless Performance	https://gbhackers.com/cloudflare-acquires-baselime/	GBHacker	news;cyber security;Cyber Security News;	1	2024-04-08	提高无服务器性能的巴塞尔公约
10630	Hillary Clinton: AI and deepfakes pose a ‘totally different type of threat’	https://therecord.media/hillary-clinton-ai-deepfakes-election-threat	therecord	ransom;Government;Cybercrime;Elections;Leadership;News;News Briefs;Privacy;	1	2024-03-28	希拉里·克林顿:大赦国际和深层假象构成了“完全不同的威胁类型”。
10639	2 Chrome Zero-Days Exploited at Pwn2Own 2024: Patch Now	https://gbhackers.com/2-chrome-zero-days-exploited/	GBHacker	news;Chrome;Cyber Security News;Zero-Day;cyber security;	1	2024-03-28	2024年在Pwn2Own Pwn2Own 2024被开采的2个铬零天零天:立即补丁
10634	White House orders federal agencies to implement AI safeguards, councils	https://therecord.media/white-house-federal-agencies-ai-safeguards	therecord	ransom;Government;News;Technology;Privacy;Leadership;	1	2024-03-28	白宫命令联邦机构执行大赦国际的保障措施、理事会
10632	Popular PyPI site for developers temporarily blocks functions due to malware campaign	https://therecord.media/pypl-python-developer-site-malware-campaign	therecord	ransom;Industry;News;Technology;	1	2024-03-28	由于恶意软件活动,开发者为开发者设置的广受欢迎的PyPPI网站临时阻塞功能
10645	iPhone Users Beware! Darcula Phishing Service Attacking Via iMessage	https://gbhackers.com/iphone-users-darcula-phishing-imessage/	GBHacker	news;Apple;cyber security;Phishing;Cyber Security News;iMessage Security;phishing;	2	2024-03-28	iPhone 用户要小心! Darcula Phishing Service 攻击 Via iMessage
10638	Rrgen - A Header Only C++ Library For Storing Safe, Randomly Generated Data Into Modern Containers	http://www.kitploit.com/2024/03/rrgen-header-only-c-library-for-storing.html	kitploit	tool;C++;Containers;Distribution;Rrgen;Schiavone;	1	2024-03-28	Rrgen - 用于安全存储、随机生成数据进入现代容器的唯一 C++ 信头库
10631	Pentagon lays out strategy to improve defense industrial base cybersecurity	https://therecord.media/pentagon-unveils-first-ever-defense-industrial-base-strategy	therecord	ransom;Government;Cybercrime;Leadership;News;	1	2024-03-28	五角大楼制定了改善国防工业基础网络安全的战略
10643	GoPlus’s Latest Report Highlights How Blockchain Communities Are Leveraging Critical API Security Data To Mitigate Web3 Threats	https://gbhackers.com/gopluss/	GBHacker	news;Computer Security;cyber security;Cyber Security News;computer security;	1	2024-03-28	GoPlus的最新报告重点指出, " 封闭链社区如何利用重要API安全数据利用关键的API安全数据来消除网络3威胁 " 。
10633	Wagner-linked influence operations remain active after leader’s death	https://therecord.media/wagner-group-linked-influence-operations-continue	therecord	ransom;Nation-state;News;Elections;	1	2024-03-28	领袖死后, Wagner 与Wagner 关联的影响力行动依然活跃
18292	Z-Development-Services-LLC	http://www.ransomfeed.it/index.php?page=post_details&id_post=14152	ransomfeed	ransom;8base;	1	2024-04-08	Z-发展-服务-LLC
10640	C2A Security’s EVSec Risk Management and Automation Platform Gains Automotive Industry Favor as Companies Pursue Regulatory Compliance	https://gbhackers.com/c2a-securitys-evsec-risk-management-and-automation-platform/	GBHacker	news;Cyber Security News;	1	2024-03-28	C2A 安全公司EVSE 风险管理和自动化平台在公司实行监管合规时获得汽车工业利益
8687	USENIX Security ’23 – Rasmus Dahlberg, Tobias Pulls – Timeless Timing Attacks And Preload Defenses In Tor’s DNS Cache	https://securityboulevard.com/2024/03/usenix-security-23-rasmus-dahlberg-tobias-pulls-timeless-timing-attacks-and-preload-defenses-in-tors-dns-cache/	securityboulevard	news;Security Bloggers Network;Open Access Research;Security Conferences;USENIX;USENIX Security ’23;	1	2024-03-20	USENIX 安全 23 - Rasmus Dahlberg, Tobias Pulls 的拉斯穆斯·达尔贝格 — — 在托尔的 DNS Cache 中进行无时无时无刻的攻击和预先装载防御
1182	Stanford: Data of 27,000 people stolen in September ransomware attack	https://www.bleepingcomputer.com/news/security/stanford-data-of-27-000-people-stolen-in-september-ransomware-attack/	bleepingcomputer	news;Security;	2	2024-03-12	斯坦福:27,000人的数据 在9月赎金软件袭击中被盗
70	Oh No! My JSON Keys and Values are Separated! How Can I Extract Them For My Searches?	https://securityboulevard.com/2024/03/oh-no-my-json-keys-and-values-are-separated-how-can-i-extract-them-for-my-searches/	securityboulevard	news;Security Bloggers Network;Splunk Tutorials;	1	2024-03-12	哦,我的JSON钥匙和价值被分开了!我怎样才能为我的搜索提取这些钥匙和价值呢?
178	Hackers leverage 1-day vulnerabilities to deliver custom Linux malware	https://www.helpnetsecurity.com/2024/03/12/custom-linux-malware/	helpnetsecurity	news;Don't miss;Hot stuff;News;backdoor;Check Point;exploit;Linux;malware;vulnerability;Windows;	1	2024-03-12	黑客利用每天1天的脆弱性提供定制的 Linux 恶意软件
1173	Microsoft March 2024 Patch Tuesday fixes 60 flaws, 18 RCE bugs	https://www.bleepingcomputer.com/news/microsoft/microsoft-march-2024-patch-tuesday-fixes-60-flaws-18-rce-bugs/	bleepingcomputer	news;Microsoft;Security;	1	2024-03-12	2024年3月 2024年3月 帕奇周二修补了60个缺陷 18个RCE错误
1185	Brave: Sharp increase in installs after iOS DMA update in EU	https://www.bleepingcomputer.com/news/technology/brave-sharp-increase-in-installs-after-ios-dma-update-in-eu/	bleepingcomputer	news;Technology;Software;	1	2024-03-12	勇敢:欧盟对iOS DMA进行更新后,安装量急剧增加
10025	FreeBuf 早报 | 外交部称不能将网络安全问题政治化；美国上千万卡车容易受蠕虫攻击	https://www.freebuf.com/news/395814.html	freebuf	news;资讯;	1	2024-03-25	FreeBuf 早报 | 外交部称不能将网络安全问题政治化；美国上千万卡车容易受蠕虫攻击
1528	Russian independent media outlet Meduza faces ‘most intense cyber campaign’ ever	https://buaq.net/go-227705.html	buaq	newscopy;	0	2024-03-13	俄国独立媒体网友Meduza面临「有史以来最激烈的网络运动」,
10646	The Moon Malware Hacked 6,000 ASUS Routers in 72hours to Use for Proxy	https://gbhackers.com/the-moon-malware-for-proxy/	GBHacker	news;Cyber Security News;Hacks;computer security;cyber security;	1	2024-03-28	月亮Malware在72小时内将6 000台ASUS路由器用于代理服务器
10647	Wireshark 4.2.4 Released: What’s New!	https://gbhackers.com/wireshark-4-2-4-released/	GBHacker	news;cyber security;Cyber Security News;	1	2024-03-28	网络4.2.4 发布:什么是新消息?
10648	Zoom Unveils AI-Powered All-In-One AI Work Workplace	https://gbhackers.com/zoom-unveils-ai-powered/	GBHacker	news;Cyber AI;cyber security;Cyber Security News;	1	2024-03-28	AI授权的 " 全体一体行动 " 工作场所
23516	Microsoft’s April 2024 Patch Tuesday: Updates for 150 Vulnerabilities and Two Zero-Days	https://securityboulevard.com/2024/04/microsofts-april-2024-patch-tuesday-updates-for-150-vulnerabilities-and-two-zero-days/	securityboulevard	news;Security Bloggers Network;Blog;	1	2024-04-10	2024年4月 微软的2024年4月的补丁: 星期二:150个脆弱性和两个零日的最新消息
1243	Dodging Digital Deception: How to Spot Fake Recruiters and Shield Your Career Search from Phishing Scams	https://blog.knowbe4.com/phishing-scams-target-job-seekers	knowbe4	news;Social Engineering;Phishing;Security Culture;	1	2024-03-12	假冒数字欺骗:如何发现虚假招募者并保护你的职业搜索,
9791	New ZenHammer memory attack impacts AMD Zen CPUs	https://www.bleepingcomputer.com/news/security/new-zenhammer-memory-attack-impacts-amd-zen-cpus/	bleepingcomputer	news;Security;Hardware;	1	2024-03-25	新的ZenHammer内存攻击撞击AMD Zen CPUs
24078	CISA Opens Its Internal Malware Analysis Tool for Public Use	https://gbhackers.com/malware-next-gen/	GBHacker	news;Cyber Security News;Malware;computer security;cyber security;	1	2024-04-11	CISA 打开内部恶意分析工具供公众使用
442	xAI 将开源其 AI 聊天机器人 Grok	https://buaq.net/go-227515.html	buaq	newscopy;	0	2024-03-12	xAI 将开源其 AI 聊天机器人 Grok
24086	SQL注入原理与防范	https://www.freebuf.com/articles/neopoints/344317.html	freebuf	news;观点;	1	2024-04-09	SQL注入原理与防范
24088	一个人的信息安全部（2）——不间断信息安全提升计划	https://www.freebuf.com/articles/security-management/386929.html	freebuf	news;安全管理;	1	2024-04-11	一个人的信息安全部（2）——不间断信息安全提升计划
24125	DuckDuckGo Is Taking Its Privacy Fight to Data Brokers	https://www.wired.com/story/duckduckgo-vpn-data-removal-tool-privacy-pro/	wired	news;Security;Security / Privacy;	1	2024-04-11	DuckDuckGo正与数据经纪人进行隐私斗争
443	App+1 | 寻找最适合写小说的工具——novelWriter	https://buaq.net/go-227524.html	buaq	newscopy;	0	2024-03-12	App+1 | 寻找最适合写小说的工具——novelWriter
757	Fincasrevuelta	http://www.ransomfeed.it/index.php?page=post_details&id_post=13645	ransomfeed	ransom;everest;	1	2024-03-09	芬卡罗维韦尔塔语Name
9989	TheMoon malware infects 6,000 ASUS routers in 72 hours for proxy service	https://www.bleepingcomputer.com/news/security/themoon-malware-infects-6-000-asus-routers-in-72-hours-for-proxy-service/	bleepingcomputer	news;Security;	1	2024-03-26	The Moon 恶意软件在72小时内感染6 000个ASUS 路由器,用于代理服务
793	Kaplan	http://www.ransomfeed.it/index.php?page=post_details&id_post=13686	ransomfeed	ransom;hunters;	1	2024-03-12	卡普兰
3	Lazarus Hackers Exploited Windows Kernel Flaw as Zero-Day in Recent Attacks	https://thehackernews.com/2024/02/lazarus-hackers-exploited-windows.html	feedburner	news;	1	2024-02-29	Lazarus Hackers 利用Windows Kernnel Flaw 成为最近袭击的零日
21438	Top MITRE ATT&amp;CK Techniques and How to Defend Against Them	https://www.darkreading.com/cyberattacks-data-breaches/top-mitre-attack-techniques-how-to-defend-against	darkreading	news;	1	2024-04-10	最大 MITRE ATT& CK 技术和如何防御这些技术
158	FreeBuf 早报 | 香港私隐公署开展人工智能合规检查；Meta旗下社交媒体全球范围宕机	https://www.freebuf.com/news/393643.html	freebuf	news;资讯;	1	2024-03-07	FreeBuf 早报 | 香港私隐公署开展人工智能合规检查；Meta旗下社交媒体全球范围宕机
288	employee_akpoly-management-system-1.0-2024 Multiple-SQLi by puncher_SQLi_bypass_authentication-BCheck module	https://www.nu11secur1ty.com/2024/03/employeeakpoly-10-2024-multiple-sqli.html	nu11security	vuln;	1	2024-03-01	使用 punder_ SQLi_ bypass_ expass_ accoply- management- system- 1.0-2024 多SQLi 模块
10660	Bytes and Bias– Unraveling the Influence of Gender Dynamics in Open Source Software	https://buaq.net/go-231177.html	buaq	newscopy;	0	2024-03-29	Bytes和Bias - 消除开放源码软件中性别动态的影响
10035	Apps secretly turning devices into proxy network nodes removed from Google Play	https://www.helpnetsecurity.com/2024/03/26/smartphone-apps-proxy-network/	helpnetsecurity	news;Don't miss;Hot stuff;News;consumer;enterprise;HUMAN Security;mobile apps;Orange Cyberdefense;Proxy;research;Sekoia.io;	1	2024-03-26	从 Google Play 中删除的将设备秘密转换为代理服务器网络节点的应用程序
10649	独立开发变现周刊（第128期） : 一个互动问答工具年收入300万美元	https://buaq.net/go-231094.html	buaq	newscopy;	0	2024-03-29	独立开发变现周刊（第128期） : 一个互动问答工具年收入300万美元
10662	Account Abstraction, Analysed: Conclusion & References	https://buaq.net/go-231179.html	buaq	newscopy;	0	2024-03-29	账户摘要,分析:结论和参考
2775	SAP Security: Code Injection & Other Vulnerabilities Patched	https://gbhackers.com/sap-security-patch-code-injection-alert/	GBHacker	news;CVE/vulnerability;Cyber Security News;Security Update;Code Injection Vulnerability;SAP Security Patch Day;SAP Vulnerability Patching;	1	2024-03-13	SAPS安全:代码注射
10652	Activision investigating password-stealing malware targeting game players	https://buaq.net/go-231163.html	buaq	newscopy;	0	2024-03-29	调查针对游戏玩家的密码窃窃恶意软件
4912	PwnAdventure: A Unique Blend of MMORPG and Cybersecurity Training	https://infosecwriteups.com/pwnadventure-a-unique-blend-of-mmorpg-and-cybersecurity-training-ed7003f1dc63?source=rss----7b722bfd1b8d---4	infosecwriteups	tech;ctf;education;gaming;cybersecurity;pwnadventure;	1	2024-03-15	PwNAdventure:MMMOPG和网络安全培训的独特组合
10656	Popular PyPI site for developers temporarily blocks functions due to malware campaign	https://buaq.net/go-231167.html	buaq	newscopy;	0	2024-03-29	由于恶意软件活动,开发者为开发者设置的广受欢迎的PyPPI网站临时阻塞功能
10653	White House orders federal agencies to implement AI safeguards, councils	https://buaq.net/go-231164.html	buaq	newscopy;	0	2024-03-29	白宫命令联邦机构执行大赦国际的保障措施、理事会
10964	How to Analyse .NET Malware? – Reverse Engineering Snake Keylogger	https://gbhackers.com/how-to-analyse-net-malware/	GBHacker	news;Malware;What is;Cyber Security News;	1	2024-03-29	如何分析.NET Maware? — 反向工程蛇键格
10655	Wagner-linked influence operations remain active after leader’s death	https://buaq.net/go-231166.html	buaq	newscopy;	0	2024-03-29	领袖死后, Wagner 与Wagner 关联的影响力行动依然活跃
10667	The Importance of User Roles and Permissions in Cybersecurity Software	https://buaq.net/go-231185.html	buaq	newscopy;	0	2024-03-29	用户在网络安全软件中的作用和权限的重要性
10663	Account Abstraction, Analysed: Security Analysis	https://buaq.net/go-231180.html	buaq	newscopy;	0	2024-03-29	账户摘要:安全分析
10665	Account Abstraction, Analysed: Ethereum Accounts	https://buaq.net/go-231182.html	buaq	newscopy;	0	2024-03-29	账户摘要,分析后: Etheum 账户
2531	The State of Stalkerware in 2023–2024	https://securelist.com/state-of-stalkerware-2023/112135/	securelist	news;Publications;Cyberbullying;Google Android;Mobile security;Privacy;Stalkerware;Stalkerware statistics;Mobile threats;	1	2024-03-13	2023年至2024年的 " 跟踪者国家 " 。
2644	vsexshopru	http://www.ransomfeed.it/index.php?page=post_details&id_post=13710	ransomfeed	ransom;werewolves;	1	2024-03-13	性血清
10661	Account Abstraction, Analysed: Further Discussions	https://buaq.net/go-231178.html	buaq	newscopy;	0	2024-03-29	账户摘要,分析:进一步讨论
10659	Thread Hijacking: Phishes That Prey on Your Curiosity	https://buaq.net/go-231175.html	buaq	newscopy;	0	2024-03-29	抢劫: 你的好奇心上那颗小珍珠的幻象
10657	喜报 | 御安信息获评江西省电信与互联网网络安全优秀技术支撑单位	https://buaq.net/go-231173.html	buaq	newscopy;	0	2024-03-29	喜报 | 御安信息获评江西省电信与互联网网络安全优秀技术支撑单位
10650	Security Today Govies Award	https://buaq.net/go-231161.html	buaq	newscopy;	0	2024-03-29	今日安全国庆奖
10651	Decade-old Linux ‘wall’ bug helps make fake SUDO prompts, steal passwords	https://buaq.net/go-231162.html	buaq	newscopy;	0	2024-03-29	十年前的Linux“墙壁”错误帮助伪造SUDO提示,窃取密码
412	SSH-Private-Key-Looting-Wordlists - A Collection Of Wordlists To Aid In Locating Or Brute-Forcing SSH Private Key File Names	http://www.kitploit.com/2024/03/ssh-private-key-looting-wordlists.html	kitploit	tool;Lateral;LFI;Password Cracking;SSH-Private-Key-Looting-Wordlists;	1	2024-03-09	SSH - 私有键盘浏览列表 - 帮助查找或强制使用 SSH 私有密钥文件名的单词列表集
10658	深信服「安全托管服务MSS+保险」方案入围工信部试点目录！	https://buaq.net/go-231174.html	buaq	newscopy;	0	2024-03-29	深信服「安全托管服务MSS+保险」方案入围工信部试点目录！
10668	Tax scams: Scams to be aware of this tax season	https://buaq.net/go-231186.html	buaq	newscopy;	0	2024-03-29	税务骗局:要了解这一税收季节的飞毛腿
24923	CISA ：恶意软件分析平台Malware Next-Gen全新升级	https://www.freebuf.com/news/397708.html	freebuf	news;资讯;	2	2024-04-12	CISA ：恶意软件分析平台Malware Next-Gen全新升级
10666	Account Abstraction, Analysed: Abstract & Introduction	https://buaq.net/go-231183.html	buaq	newscopy;	0	2024-03-29	账户摘要,分析:摘要和导言
24924	机器人攻击仍然是2024年的最大威胁	https://www.freebuf.com/news/397714.html	freebuf	news;资讯;	1	2024-04-12	机器人攻击仍然是2024年的最大威胁
3383	尼日利亚政府称被拘留的两名币安高管至少在3月20日前不会被释放	https://buaq.net/go-228051.html	buaq	newscopy;	0	2024-03-14	尼日利亚政府称被拘留的两名币安高管至少在3月20日前不会被释放
10664	Account Abstraction, Analysed: Account Abstraction	https://buaq.net/go-231181.html	buaq	newscopy;	0	2024-03-29	账户摘要: 账户摘要,分析: 账户摘要
2650	Felda-Global-Ventures-Holdings-Berhad	http://www.ransomfeed.it/index.php?page=post_details&id_post=13717	ransomfeed	ransom;qilin;	1	2024-03-13	费尔达 -- 全球 -- 全球 -- 全球 -- 全球 -- 全球 -- -- 虚拟 -- -- 挂号 -- -- 布拉德
3456	Tech support firms Restoro, Reimage fined $26 million for scare tactics	https://www.bleepingcomputer.com/news/security/tech-support-firms-restoro-reimage-fined-26-million-for-scare-tactics/	bleepingcomputer	news;Security;	1	2024-03-14	技术支援公司Restoro Restoro, Reimage因恐吓战术罚款2 600万美元
3708	Android Phishing Scam Using Malware-as-a-Service on the Rise in India	https://www.mcafee.com/blogs/other-blogs/mcafee-labs/android-phishing-scam-using-malware-as-a-service-on-the-rise-in-india/	mcafee	news;McAfee Labs;	2	2024-03-14	在印度崛起时使用Malware - as - a - service
24131	Lindy Cameron, former UK cybersecurity chief, appointed British High Commissioner to India	https://therecord.media/lindy-cameron-ncsc-british-high-commissioner-india	therecord	ransom;Government;News;News Briefs;Leadership;People;	1	2024-04-11	联合王国前网络安全主任Lindy Cameron被任命为英国驻印度高级专员
3800	Ubuntu Security Notice USN-6686-2	https://packetstormsecurity.com/files/177598/USN-6686-2.txt	packetstorm	vuln;;	1	2024-03-14	Ubuntu Ubuntu 安全通知 USN6686-2
24139	Python's PyPI Reveals Its Secrets	https://thehackernews.com/2024/04/blog-post.html	feedburner	news;	1	2024-04-11	Python的PypPI 泄露其秘密
24154	TA547 Phishing Attack Hits German Firms with Rhadamanthys Stealer	https://thehackernews.com/2024/04/ta547-phishing-attack-hits-german-firms.html	feedburner	news;	1	2024-04-11	TA547 用Rhadamanthys盗贼袭击德国公司
3805	Hunting Down The HVCI Bug In UEFI	https://packetstormsecurity.com/files/177603/hvci-bug.pdf	packetstorm	vuln;;	1	2024-03-14	猎取HVCI 在UEFI的错误
419	Mastering Cross-Site Scripting (XSS): Risks, Detection, and Prevention — Beginner’s Guide	https://infosecwriteups.com/mastering-cross-site-scripting-xss-risks-detection-and-prevention-3cee199d2fff?source=rss----7b722bfd1b8d---4	infosecwriteups	tech;cybersecurity;xss-attack;bug-bounty;programming;xss-vulnerability;	1	2024-03-04	掌握交叉版本(XSS):风险、侦查和预防——初学者指南
3801	Apple Security Advisory 03-12-2024-1	https://packetstormsecurity.com/files/177599/APPLE-SA-03-12-2024-1.txt	packetstorm	vuln;;	1	2024-03-14	苹果安全咨询 03-12-12-2024-1
3802	Ubuntu Security Notice USN-6587-5	https://packetstormsecurity.com/files/177600/USN-6587-5.txt	packetstorm	vuln;;	1	2024-03-14	Ubuntu Ubuntu 安全通知 USN-6587-5
3807	Vinchin Backup And Recovery 7.2 Command Injection	https://packetstormsecurity.com/files/177605/vbr72-exec.txt	packetstorm	vuln;;	1	2024-03-14	7.2 指令注射
8639	White House cyber official urges UnitedHealth to provide third-party certification of network safety	https://buaq.net/go-229093.html	buaq	newscopy;	0	2024-03-20	白宫网络官员敦促联合卫生组织为网络安全提供第三方认证
4924	StopCrypt Ransomware Utilizing Multi-Stage Shellcodes To Attack Windows	https://gbhackers.com/stopcrypt-ransomware/	GBHacker	news;cyber security;Malware;Ransomware;ransomware;	2	2024-03-17	使用多系统 Shellcode 来攻击窗口
4913	Story of Lock up users’ account by DOS attack cost $1,100	https://infosecwriteups.com/story-of-lock-up-users-account-by-dos-attack-cost-1-100-87b47d06a7c1?source=rss----7b722bfd1b8d---4	infosecwriteups	tech;hacker;hacking;bug-bounty;security;bug-bounty-tips;	1	2024-03-15	由DOS攻击锁定用户账户的记录费用为1 100美元
4925	New acoustic attack determines keystrokes from typing patterns	https://buaq.net/go-228636.html	buaq	newscopy;	0	2024-03-17	新的声学攻击决定了打字模式的按键
3679	mioagov	http://www.ransomfeed.it/index.php?page=post_details&id_post=13728	ransomfeed	ransom;stormous;	1	2024-03-14	米奥阿戈
3746	How to share sensitive files securely online	https://www.welivesecurity.com/en/how-to/share-sensitive-files-securely-online/	eset	news;	1	2024-03-13	如何在网上安全共享敏感文件
10333	How security leaders can ease healthcare workers’ EHR-related burnout	https://www.helpnetsecurity.com/2024/03/27/how-security-leaders-can-ease-healthcare-workers-ehr-related-burnout/	helpnetsecurity	news;Don't miss;Expert analysis;Expert corner;Hot stuff;News;access management;authentication;burnout;CISO;cybersecurity;healthcare;Hypori;opinion;	1	2024-03-27	安全领导人如何能够减轻保健工作者与EHR有关的烧伤
9055	keralapolicegovin	http://www.ransomfeed.it/index.php?page=post_details&id_post=13897	ransomfeed	ransom;killsec;	1	2024-03-21	Kerala警察govin
4926	TLP WHITE:	https://buaq.net/go-228637.html	buaq	newscopy;	0	2024-03-17	TLP 白:
8680	How to Build a Phishing Playbook Part 3: Playbook Development	https://securityboulevard.com/2024/03/how-to-build-a-phishing-playbook-part-3-playbook-development/	securityboulevard	news;DevOps;Incident Response;Security Awareness;Security Bloggers Network;automated response;Cybersecurity;dkim;dmarc;email security;phishing playbook;playbook development;Playbook Editor;Smart SOAR;SOAR;spf;utility commands;	1	2024-03-20	如何建立《钓钓鱼游览手册》第三部分:《书书发展》
3806	Ubuntu Security Notice USN-6673-2	https://packetstormsecurity.com/files/177604/USN-6673-2.txt	packetstorm	vuln;;	1	2024-03-14	Ubuntu Ubuntu 安全通知 USN6673-2
3804	Fortinet FortiOS Out-Of-Bounds Write	https://packetstormsecurity.com/files/177602/CVE-2024-21762.txt	packetstorm	vuln;;	1	2024-03-14	Fortinet FortiOS FortiOS 离岸外写作
3684	Cosmocolor	http://www.ransomfeed.it/index.php?page=post_details&id_post=13733	ransomfeed	ransom;hunters;	1	2024-03-14	宇宙色
3803	JetBrains TeamCity Unauthenticated Remote Code Execution	https://packetstormsecurity.com/files/177601/jetbrains_teamcity_rce_cve_2024_27198.rb.txt	packetstorm	vuln;;	1	2024-03-14	未经认证的远程代码执行
3787	Red Hat Security Advisory 2024-1310-03	https://packetstormsecurity.com/files/177585/RHSA-2024-1310-03.txt	packetstorm	vuln;;	1	2024-03-14	2024-1310-03红色帽子安保咨询
3799	Apple Security Advisory 03-07-2024-7	https://packetstormsecurity.com/files/177597/APPLE-SA-03-07-2024-7.txt	packetstorm	vuln;;	1	2024-03-14	苹果安全咨询 03-07-2024-7
8953	What the Latest Ransomware Attacks Teach About Defending Networks	https://www.bleepingcomputer.com/news/security/what-the-latest-ransomware-attacks-teach-about-defending-networks/	bleepingcomputer	news;Security;	2	2024-03-21	最新的核磁器袭击 如何教导防御网络
670	Kool-air	http://www.ransomfeed.it/index.php?page=post_details&id_post=13550	ransomfeed	ransom;play;	1	2024-03-01	库尔空气
4158	基于欧盟法律要求微软也宣布取消Microsoft Azure迁移流量费 每月至少100GB	https://buaq.net/go-228241.html	buaq	newscopy;	0	2024-03-15	基于欧盟法律要求微软也宣布取消Microsoft Azure迁移流量费 每月至少100GB
4471	Overcoming our “bossypants” bias	https://securityboulevard.com/2024/03/overcoming-our-bossypants-bias/	securityboulevard	news;CISO Suite;Security Bloggers Network;Leadership;Lean In;management;	1	2024-03-15	克服我们的“龙头”偏见
4153	新观点| 对照物理世界看网络空间抗勒索策略	https://buaq.net/go-228234.html	buaq	newscopy;	0	2024-03-15	新观点| 对照物理世界看网络空间抗勒索策略
9081	Attackers are exploiting JetBrains TeamCity flaw to deliver a variety of malware	https://www.helpnetsecurity.com/2024/03/21/exploiting-cve-2024-27198/	helpnetsecurity	news;Don't miss;Hot stuff;News;exploit;JetBrains;malware;ransomware;remote access trojan;Trend Micro;vulnerability;	1	2024-03-21	攻击者正在利用喷气系统团队 城市的缺陷来提供各种恶意软件
8941	USENIX Security ’23 – A Data-Free Backdoor Injection Approach In Neural Networks	https://securityboulevard.com/2024/03/usenix-security-23-a-data-free-backdoor-injection-approach-in-neural-networks/	securityboulevard	news;Security Bloggers Network;Open Access Research;Security Conferences;Security Research;USENIX;USENIX Security ’23;	1	2024-03-21	USENIX 安全 ' 23 - 神经网络中无数据输入后门注射方法
9062	大模型赋能安全运营实践 | FreeBuf 企业安全俱乐部·广州站议题前瞻	https://www.freebuf.com/fevents/395470.html	freebuf	news;活动;	1	2024-03-21	大模型赋能安全运营实践 | FreeBuf 企业安全俱乐部·广州站议题前瞻
9219	Proven Methods for the Quiet Security Professional To Own Their Narrative	https://securityboulevard.com/2024/03/proven-methods-for-the-quiet-security-professional-to-own-their-narrative/	securityboulevard	news;Security Bloggers Network;article;	1	2024-03-21	经证明的 " 静悄悄保安专业人员掌握其叙述式 " 方法
4754	Admin of major stolen account marketplace gets 42 months in prison	https://www.bleepingcomputer.com/news/security/admin-of-major-stolen-account-marketplace-gets-42-months-in-prison/	bleepingcomputer	news;Security;	1	2024-03-15	重大被盗账户市场管理者可被监禁42个月
9080	Kyndryl partners with Cloudflare to help enterprises migrate to next-generation networks	https://www.helpnetsecurity.com/2024/03/21/cloudflare-kyndryl-alliance/	helpnetsecurity	news;Industry news;Cloudflare;Kyndryl;	1	2024-03-21	Kyndryryl与云花合作,帮助企业向下一代网络迁移
4941	Debunking the Go Community's Conventional Wisdom on Internal Directories	https://buaq.net/go-228677.html	buaq	newscopy;	0	2024-03-18	以内局为据,揭开Go社区在内部事务上的常规智慧
9162	Chinese government hacker exploiting ScreenConnect, F5 bugs to attack defense and government entities	https://buaq.net/go-229764.html	buaq	newscopy;	0	2024-03-22	中国政府黑客利用屏幕连网、F5窃听器攻击国防和政府实体
4749	USENIX Security ’23 – Tanusree Sharma, Zhixuan Zhou, Andrew Miller, Yang Wang – A Mixed-Methods Study Of Security Practices Of Smart Contract Developers	https://securityboulevard.com/2024/03/usenix-security-23-tanusree-sharma-zhixuan-zhou-andrew-miller-yang-wang-a-mixed-methods-study-of-security-practices-of-smart-contract-developers/	securityboulevard	news;Security Bloggers Network;Open Access Research;Security Conferences;Security Research;USENIX;USENIX Security ’23;	1	2024-03-17	USENIX 安全 23 — — 塔努斯里·夏尔马、周志泉、安德鲁·米勒、杨王 — — 智能合同开发商安全做法混合方法研究
9123	Xbox GamingService Arbitrary Folder Move	https://packetstormsecurity.com/files/177712/GamingServiceEoP-main.zip	packetstorm	vuln;;	1	2024-03-21	Xbox Xbox 游戏服务任意文件夹移动
4760	PornHub now also blocks Texas over age verification laws	https://www.bleepingcomputer.com/news/security/pornhub-now-also-blocks-texas-over-age-verification-laws/	bleepingcomputer	news;Security;Government;Technology;	1	2024-03-15	现在PornHub也封锁得克萨斯州 超过年龄核查法
9168	Securing All The Things - Josh Corman - PSW #821	https://buaq.net/go-229770.html	buaq	newscopy;	0	2024-03-22	保护所有东西——Josh Corman — PSW #821
3609	PoC for critical Arcserve UDP vulnerabilities published (CVE-2024-0799, CVE-2024-0800)	https://www.helpnetsecurity.com/2024/03/14/cve-2024-0799-cve-2024-0800/	helpnetsecurity	news;Don't miss;Hot stuff;News;Arcserve;backup;disaster recovery;enterprise;exploit;PoC;SMBs;Tenable;	3	2024-03-14	出版的关于关键Arcserve UDP脆弱性的PoC(CVE-2024-0799,CVE-2024-0800)
28673	不明黑客利用 0day 漏洞对 Palo Alto Networks 防火墙进行后门攻击	https://buaq.net/go-234228.html	buaq	newscopy;	0	2024-04-15	不明黑客利用 0day 漏洞对 Palo Alto Networks 防火墙进行后门攻击
28674	CISA 就 Sisense 数据泄露事件发出警告	https://buaq.net/go-234229.html	buaq	newscopy;	0	2024-04-15	CISA 就 Sisense 数据泄露事件发出警告
28675	英伟达也将游戏崩溃问题归咎于英特尔 即13/14代CPU的硬件质量问题	https://buaq.net/go-234230.html	buaq	newscopy;	0	2024-04-15	英伟达也将游戏崩溃问题归咎于英特尔 即13/14代CPU的硬件质量问题
28677	现有的Windows Server 2022服务器系统被推送安装Copilot 原因未知	https://buaq.net/go-234232.html	buaq	newscopy;	0	2024-04-15	现有的Windows Server 2022服务器系统被推送安装Copilot 原因未知
28678	比某丁还不要脸？屏幕录像软件ScreenStudio被国内公司像素级盗版	https://buaq.net/go-234233.html	buaq	newscopy;	0	2024-04-15	比某丁还不要脸？屏幕录像软件ScreenStudio被国内公司像素级盗版
28679	[技巧] 微软在Windows 11开始菜单中展示推荐广告 下面是禁用方法	https://buaq.net/go-234234.html	buaq	newscopy;	0	2024-04-15	[技巧] 微软在Windows 11开始菜单中展示推荐广告 下面是禁用方法
28681	安全动态回顾 | 数据分类分级国标十月一日起实施 间谍软件试图攻击92个国家的iPhone用户	https://buaq.net/go-234236.html	buaq	newscopy;	0	2024-04-15	安全动态回顾 | 数据分类分级国标十月一日起实施 间谍软件试图攻击92个国家的iPhone用户
28682	GitHub 上泄露了超过 1200 万个身份验证秘密和密钥	https://buaq.net/go-234237.html	buaq	newscopy;	0	2024-04-15	GitHub 上泄露了超过 1200 万个身份验证秘密和密钥
8686	USENIX Security ’23 – How The Great Firewall Of China Detects And Blocks Fully Encrypted Traffic	https://securityboulevard.com/2024/03/usenix-security-23-how-the-great-firewall-of-china-detects-and-blocks-fully-encrypted-traffic/	securityboulevard	news;Security Bloggers Network;Open Access Research;USENIX;USENIX Security ’23;	4	2024-03-20	USENIX 安全 23 — — 中国大防火墙是如何完全加密交通的
16094	ST Smart Things Sentinel - Advanced Security Tool To Detect Threats Within The Intricate Protocols utilized By IoT Devices	http://www.kitploit.com/2024/04/st-smart-things-sentinel-advanced.html	kitploit	tool;Firmware;Iot;Protocols;Python;Python3;Scan;Threat;TP-LINK;	1	2024-04-03	SST智能事物哨兵 -- -- 用于检测IoT装置使用的具体协议内威胁的高级安全工具
1171	USENIX Security ’23 – Piet De Vaere, Adrian Perrig – Hey Kimya, Is My Smart Speaker Spying On Me? Taking Control Of Sensor Privacy Through Isolation And Amnesia	https://securityboulevard.com/2024/03/usenix-security-23-piet-de-vaere-adrian-perrig-hey-kimya-is-my-smart-speaker-spying-on-me-taking-control-of-sensor-privacy-through-isolation-and-amnesia/	securityboulevard	news;Security Bloggers Network;Open Access Research;Security Conferences;Security Research;USENIX;USENIX Security ’23;	1	2024-03-12	USENIX 安全 23 — — Piet De Vaere, Adrian Perrig — — Hey Kimya, 我的聪明演讲人是否在监视我? 通过隔离和失忆控制感官隐私
4857	Healthcare still a prime target for cybercrime gangs – Week in security with Tony Anscombe	https://www.welivesecurity.com/en/videos/healthcare-target-cybercrime-week-security-tony-anscombe/	eset	news;	1	2024-03-15	医疗保健仍是网络犯罪团伙的首要目标 — — 与托尼·安斯科姆(Tony Anscombe)的“安全周”
21513	WEF Cybercrime Atlas: Researchers are creating new insights to fight cybercrime	https://www.helpnetsecurity.com/2024/04/10/sean-doyle-wef-cybercrime-atlas/	helpnetsecurity	news;Don't miss;Features;Hot stuff;News;collaboration;cybercrime;information sharing;World Economic Forum;	1	2024-04-10	WEF 网络犯罪地图集:研究人员正在创造打击网络犯罪的新见解
8339	Fujitsu finds malware on company systems, investigates possible data breach	https://www.helpnetsecurity.com/2024/03/18/fujitsu-data-breach/	helpnetsecurity	news;Don't miss;Hot stuff;News;cyberattack;data breach;data theft;Fujitsu;Japan;malware;	1	2024-03-18	藤津在公司系统上发现恶意软件 调查可能发生数据泄漏
61	Spam and phishing in 2023	https://securelist.com/spam-phishing-report-2023/112015/	securelist	news;Spam and phishing reports;Malicious spam;Malware;Phishing;Phishing websites;QakBot;Spam Letters;Spam Statistics;Spammer techniques;Spear phishing;Telegram;Thematic phishing;Thematic spam;Trojan;Spam and Phishing;	1	2024-03-07	2023年的垃圾和钓鱼
8934	CISA, NSA, Others Outline Security Steps Against Volt Typhoon	https://securityboulevard.com/2024/03/cisa-nsa-others-outline-security-steps-against-volt-typhoon/	securityboulevard	news;Cloud Security;Cybersecurity;Data Security;Featured;Industry Spotlight;Network Security;News;Security Awareness;Security Boulevard (Original);Social - Facebook;Social - LinkedIn;Social - X;Spotlight;Threat Intelligence;china espionage;Five Eyes alliance;Volt Typhoon;	1	2024-03-21	独联体国家、国家安全局、其他国家针对伏特台风采取安全步骤
3423	USENIX Security ’23 – Powering for Privacy: Improving User Trust in Smart Speaker Microphones with Intentional Powering and Perceptible Assurance	https://securityboulevard.com/2024/03/usenix-security-23-powering-for-privacy-improving-user-trust-in-smart-speaker-microphones-with-intentional-powering-and-perceptible-assurance/	securityboulevard	news;Security Bloggers Network;Open Access Research;Security Conferences;Security Research;USENIX;USENIX Security ’23;	1	2024-03-14	USENIX 安全 23 — 隐私权力:提高用户对有有意授权和可感知保证的智能话筒的用户信任
9451	Opera sees big jump in EU users on iOS, Android after DMA update	https://www.bleepingcomputer.com/news/technology/opera-sees-big-jump-in-eu-users-on-ios-android-after-dma-update/	bleepingcomputer	news;Technology;Software;	2	2024-03-23	Opera看到欧盟用户在iOS上大跳跃,在DMA更新后 Android上大跳跃。
8685	Randall Munroe’s XKCD ‘Schwa’	https://securityboulevard.com/2024/03/randall-munroes-xkcd-schwa/	securityboulevard	news;Humor;Security Bloggers Network;Randall Munroe;Sarcasm;satire;XKCD;	1	2024-03-20	Randall Munroe的 XKCD “Shwa” XKCD “Schwa”
10105	Detained execs, a bold escape, and tax evasion charges: Nigeria takes aim at Binance	https://therecord.media/binance-executives-nigeria-click-here-podcast-feature	therecord	ransom;News;People;Government;Industry;	1	2024-03-26	拘留出境、大胆逃跑和逃税指控:尼日利亚的目标是Binance
4466	Crypto Phishing Kit Impersonating Login Pages: Stay Informed	https://securityboulevard.com/2024/03/crypto-phishing-kit-impersonating-login-pages-stay-informed/	securityboulevard	news;Identity & Access;Security Bloggers Network;Crypto Fraud Prevention;Crypto Phishing;CryptoChameleon;Cryptocurrency Security;Cybersecurity;Cybersecurity News;Financial Institutions Security;LabHost;LabRat;Phishing;smishing;SMS Spamming;two factor authentication;	1	2024-03-15	加密钓鱼工具 冒名登录页面: 保持知情
9392	黑客可通过Unsaflok 漏洞获取数百万家酒店房门“万能钥匙”	https://buaq.net/go-229814.html	buaq	newscopy;	0	2024-03-22	黑客可通过Unsaflok 漏洞获取数百万家酒店房门“万能钥匙”
5588	The TikTok Ban Bill, Your Car is Spying on You, Signal’s Username Update	https://securityboulevard.com/2024/03/the-tiktok-ban-bill-your-car-is-spying-on-you-signals-username-update/	securityboulevard	news;Data Security;Security Bloggers Network;Cyber Security;Cybersecurity;Data Privacy;Digital Privacy;Episodes;Federal Privacy Law;Information Security;Infosec;insurance;Insurance Companies;messaging;phone numbers;Podcast;Podcasts;Privacy;secure messaging;security;signal;surveillance;technology;TikTok;TikTok Ban;tracking;US government;usernames;Weekly Edition;	1	2024-03-18	TikTok Ban Bill, 你的汽车正在监视你, 信号用户名更新
28685	微软解除英特尔SST音频驱动造成的兼容性阻止 现在用户可以升级Win11	https://buaq.net/go-234243.html	buaq	newscopy;	0	2024-04-15	微软解除英特尔SST音频驱动造成的兼容性阻止 现在用户可以升级Win11
28686	HTB CTF: Cracking Passwords with Hashcat	https://buaq.net/go-234244.html	buaq	newscopy;	0	2024-04-15	HTB CTF: 使用 Hashcat 破碎密码
28711	Red Hat Security Advisory 2024-1784-03	https://packetstormsecurity.com/files/178025/RHSA-2024-1784-03.txt	packetstorm	vuln;;	1	2024-04-12	2024-1784-03红色帽子安保咨询
28712	Red Hat Security Advisory 2024-1785-03	https://packetstormsecurity.com/files/178026/RHSA-2024-1785-03.txt	packetstorm	vuln;;	1	2024-04-12	红色帽子安保咨询2024-1785-03
28713	Red Hat Security Advisory 2024-1786-03	https://packetstormsecurity.com/files/178027/RHSA-2024-1786-03.txt	packetstorm	vuln;;	1	2024-04-12	红帽子安保咨询2024-1786-03
10287	Weld-Plus	http://www.ransomfeed.it/index.php?page=post_details&id_post=13983	ransomfeed	ransom;play;	1	2024-03-27	焊化加
10291	pstranscom	http://www.ransomfeed.it/index.php?page=post_details&id_post=13987	ransomfeed	ransom;blackbasta;	1	2024-03-27	psstranscom 转换器
10299	amerluxcom	http://www.ransomfeed.it/index.php?page=post_details&id_post=13995	ransomfeed	ransom;blackbasta;	1	2024-03-27	奢侈品
9305	FreeBuf 早报 | 温哥华Pwn2Own首日特斯拉又被黑；UDP 协议被曝漏洞	https://www.freebuf.com/news/395527.html	freebuf	news;资讯;	3	2024-03-21	FreeBuf 早报 | 温哥华Pwn2Own首日特斯拉又被黑；UDP 协议被曝漏洞
10289	northamericansignscom	http://www.ransomfeed.it/index.php?page=post_details&id_post=13985	ransomfeed	ransom;blackbasta;	1	2024-03-27	北美信使委员会
18821	Wyden Releases Draft Legislation to End Federal Dependence on Insecure, Proprietary Software	https://www.darkreading.com/application-security/wyden-releases-draft-legislation-to-end-federal-dependence-on-insecure-proprietary-software	darkreading	news;	1	2024-04-08	结束联邦对无保障、产权软件的依赖的立法草案
10292	viliscom	http://www.ransomfeed.it/index.php?page=post_details&id_post=13988	ransomfeed	ransom;blackbasta;	1	2024-03-27	viliscom
1280	Netskope and Egress partner to enhance behavioral-based threat detection and response	https://www.helpnetsecurity.com/2024/03/12/netskope-and-egress-partner-to-enhance-behavioral-based-threat-detection-and-response/	helpnetsecurity	news;Industry news;Egress;Netskope;	1	2024-03-12	Netskope和Egress伙伴加强基于行为的威胁探测和应对
21514	Why are many businesses turning to third-party security partners?	https://www.helpnetsecurity.com/2024/04/10/third-party-security-partnerships/	helpnetsecurity	news;Don't miss;Expert analysis;Expert corner;Hot stuff;News;access management;cybersecurity;opinion;privacy;professional;regulation;SaaS;SailPoint;	1	2024-04-10	为什么许多企业转向第三方担保伙伴?
18400	AI-As-A-Service Providers Vulnerability Let Attackers Perform Cross-Tenant Attacks	https://gbhackers.com/ai-as-a-service-cross-tenant-attacks/	GBHacker	news;Artificial Intelligence;cyber security;Cyber Security News;Vulnerability;	1	2024-04-08	AI-A-A-服务提供者
16706	Carrozzeria-Aretusa-srl-	http://www.ransomfeed.it/index.php?page=post_details&id_post=14138	ransomfeed	ransom;ransomhub;	1	2024-04-06	Carrozzeria -ARTUSA -SRL -卡罗兹里亚 -阿雷图萨
10295	pctinternationalcom	http://www.ransomfeed.it/index.php?page=post_details&id_post=13991	ransomfeed	ransom;blackbasta;	1	2024-03-27	商 商 商 商
10290	fpdcompanycom	http://www.ransomfeed.it/index.php?page=post_details&id_post=13986	ransomfeed	ransom;blackbasta;	1	2024-03-27	Fpdcourccom 公司
10294	theshootingwarehousecom	http://www.ransomfeed.it/index.php?page=post_details&id_post=13990	ransomfeed	ransom;blackbasta;	1	2024-03-27	射击软件库com
293	Hackers Behind the Change Healthcare Ransomware Attack Just Received a $22 Million Payment	https://www.wired.com/story/alphv-change-healthcare-ransomware-payment/	wired	news;Security;Security / Cyberattacks and Hacks;Security / Security News;	2	2024-03-04	变化后的保健疗养疗养疗程软件攻击背后的黑客刚收到一笔2 200万美元的付款
413	Tinyfilemanager-Wh1Z-Edition - Effortlessly Browse And Manage Your Files With Ease Using Tiny File Manager [WH1Z-Edition], A Compact Single-File PHP File Manager	http://www.kitploit.com/2024/03/tinyfilemanager-wh1z-edition.html	kitploit	tool;File Management System;Folder Viewer;Online Ide;Tinyfilemanager;Tinyfilemanager-Wh1Z-Edition;Url Upload;Web File Storage;	1	2024-03-03	Tinyfilemanager- Wh1Z- Edition - 不费力的浏览和管理您的文件, 使用微小文件管理器 [WH1Z- Edition] , 压缩单文件 PHP 文件管理器
10297	mjcelcocom	http://www.ransomfeed.it/index.php?page=post_details&id_post=13993	ransomfeed	ransom;blackbasta;	1	2024-03-27	mjcelcocom( mjcelcocom )
10293	Mermet	http://www.ransomfeed.it/index.php?page=post_details&id_post=13989	ransomfeed	ransom;akira;	1	2024-03-27	美美
10300	ero-etikettcom	http://www.ransomfeed.it/index.php?page=post_details&id_post=13996	ransomfeed	ransom;blackbasta;	1	2024-03-27	
10296	kmbdgcom	http://www.ransomfeed.it/index.php?page=post_details&id_post=13992	ransomfeed	ransom;blackbasta;	1	2024-03-27	kmbdgcom( kmbdgcom )
10298	organizedlivingcom	http://www.ransomfeed.it/index.php?page=post_details&id_post=13994	ransomfeed	ransom;blackbasta;	1	2024-03-27	组织有组织活 活
9859	How immersive AI transforms skill development	https://www.helpnetsecurity.com/2024/03/25/ai-skills-development-video/	helpnetsecurity	news;Don't miss;Hot stuff;Video;artificial intelligence;cybersecurity;machine learning;Pluralsight;privacy;sandbox;skill development;video;	1	2024-03-25	深入的人工智能如何改变技能发展
10301	carolinafoodsinccom	http://www.ransomfeed.it/index.php?page=post_details&id_post=13997	ransomfeed	ransom;blackbasta;	1	2024-03-27	卡罗莱纳食品辛康
9533	Win32.STOP.Ransomware (Smokeloader) MVID-2024-0676 Remote Code Execution	https://packetstormsecurity.com/files/177740/MVID-2024-0676.txt	packetstorm	vuln;;	2	2024-03-22	MVID-2024-0676远程代码执行
10302	lagunitascom	http://www.ransomfeed.it/index.php?page=post_details&id_post=13998	ransomfeed	ransom;blackbasta;	1	2024-03-27	落后标准
135	AI and Ransomware Top the List of Mid-Market IT Cyber Threats	https://blog.knowbe4.com/ai-and-ransomware-top-list-of-mid-market-it-cyber-threat	knowbe4	news;Security Awareness Training;Ransomware;Security Culture;	2	2024-03-07	AI和Ransomwar公司是中市IT网络威胁中名列榜首
10288	otrwheelcom	http://www.ransomfeed.it/index.php?page=post_details&id_post=13984	ransomfeed	ransom;blackbasta;	1	2024-03-27	ot 转轮式
9508	OpenNMS Horizon 31.0.7 Remote Command Execution	https://cxsecurity.com/issue/WLB-2024030057	cxsecurity	vuln;	1	2024-03-24	31.0.7 远程指令执行
406	Mhf - Mobile Helper Framework - A Tool That Automates The Process Of Identifying The Framework/Technology Used To Create A Mobile Application	http://www.kitploit.com/2024/03/mhf-mobile-helper-framework-tool-that.html	kitploit	tool;iOS;Mhf;reFlutter;Reverse Engineering;Sensitive Information;	1	2024-03-05	Mhf - 移动辅助工具框架 -- -- 一种工具,使识别用于创建移动应用的框架/技术的过程自动化
18430	92,000+ internet-facing D-Link NAS devices accessible via “backdoor” account (CVE-2024-3273)	https://www.helpnetsecurity.com/2024/04/08/cve-2024-3273/	helpnetsecurity	news;Don't miss;Hot stuff;News;D-Link;NAS;vulnerability;	3	2024-04-08	92,000+可通过“后门”账户(CVE-2024-3273)进入互联网的D-Link NAS装置
10252	Crimsgroup	http://www.ransomfeed.it/index.php?page=post_details&id_post=13936	ransomfeed	ransom;everest;	1	2024-03-26	反黑组
10209	DHS Proposes Critical Infrastructure Reporting Rules	https://www.darkreading.com/cybersecurity-operations/dhs-releases-unpublished-circia-document-proposing-new-rule	darkreading	news;	1	2024-03-27	国土安全部提出《关键基础设施报告规则》
10250	regencymediacomau	http://www.ransomfeed.it/index.php?page=post_details&id_post=13933	ransomfeed	ransom;lockbit3;	1	2024-03-26	中 额 中 额 额 额 额 额 额 额 额 额 额 额 额 额 额 额 额 额 额 额 额 额
10253	Ministry-of-Defense-of-Peru	http://www.ransomfeed.it/index.php?page=post_details&id_post=13949	ransomfeed	ransom;ransomexx;	1	2024-03-26	秘鲁国防部
10254	Koi-Design	http://www.ransomfeed.it/index.php?page=post_details&id_post=13950	ransomfeed	ransom;akira;	1	2024-03-26	科伊设计
10225	The Number of New Pieces of Malware Per Minute Has Quadrupled in Just One Year	https://blog.knowbe4.com/number-new-pieces-malware-per-minute-quadrupled	knowbe4	news;Social Engineering;Phishing;Malware;	1	2024-03-27	每分钟的马拉威新片数量 在短短的一年中已经翻了四番
2679	New Relic empowers IT and engineering teams to focus on real application security problems	https://www.helpnetsecurity.com/2024/03/13/new-relic-iast/	helpnetsecurity	news;Industry news;New Relic;	1	2024-03-13	新的Relic使信息技术和工程小组能够集中精力解决应用程序的实际安全问题
10227	[SCARY] Research Shows Weaponized GenAI Worm That Gets Distributed Via A Zero Click Phishing Email	https://blog.knowbe4.com/scary-research-shows-weaponized-genai-worm-that-gets-distributed-via-a-zero-click-phishing-email	knowbe4	news;	1	2024-03-27	[SCARY] 研究显示,武器化的基因虫子 得到分布的Via A零点击捕捉邮件
10217	Millions of Hotel Rooms Worldwide Vulnerable to Door Lock Exploit	https://www.darkreading.com/vulnerabilities-threats/millions-hotel-rooms-worldwide-vulnerable-door-lock-exploit	darkreading	news;	1	2024-03-27	全世界数百万旅馆客房 易受门锁的利用
10249	wblightcom	http://www.ransomfeed.it/index.php?page=post_details&id_post=13932	ransomfeed	ransom;lockbit3;	1	2024-03-25	wbblight 网络
10255	Tanis-Brush	http://www.ransomfeed.it/index.php?page=post_details&id_post=13951	ransomfeed	ransom;akira;	1	2024-03-26	塔尼斯笔刷
4201	Secure Software Development Attestation Form: Sonatype helps you comply	https://securityboulevard.com/2024/03/secure-software-development-attestation-form-sonatype-helps-you-comply/	securityboulevard	news;SBN News;Security Bloggers Network;CISA best practices;FEATURED;Federal;government;News and Views;secure software supply chain;	1	2024-03-14	安全软件开发表格: Sonatype 帮助您遵守
10210	Getting Security Remediation on the Boardroom Agenda	https://www.darkreading.com/cybersecurity-operations/getting-security-remediation-on-boardroom-agenda	darkreading	news;	1	2024-03-27	使安全得到补救列入会议室议程
10228	A Simple 'Payment is Underway' Phishing Email Downloads RATs from AWS, GitHub	https://blog.knowbe4.com/simple-payment-underway-phishing-email-downloads-rats	knowbe4	news;Phishing;Security Culture;	1	2024-03-27	简单的“ 付款在地下 ” , 从 AWS, GitHub 下载 RAT 邮件
10213	'Darcula' Phishing-as-a-Service Operation Bleeds Victims Worldwide	https://www.darkreading.com/endpoint-security/-darcula-phishing-as-a-service-operation-bleeds-victims-worldwide	darkreading	news;	1	2024-03-27	“Darcula”“全球血受害者救助行动”
10248	CLARK-Material-Handling-Company	http://www.ransomfeed.it/index.php?page=post_details&id_post=13931	ransomfeed	ransom;hunters;	1	2024-03-25	CLAC-MIT-Handling-Company 克拉里昂-马列-Handling-Company 克拉里昂-马列-Handling-Company 克拉里昂-马列-Handling-Company 克拉里昂-马列-Handling-CLACRK-马列-Handling-Company
10251	Woodsboro-ISD	http://www.ransomfeed.it/index.php?page=post_details&id_post=13934	ransomfeed	ransom;ransomhub;	1	2024-03-26	森林 -- -- ISD
10256	Lieberman-LLP	http://www.ransomfeed.it/index.php?page=post_details&id_post=13952	ransomfeed	ransom;bianlian;	1	2024-03-26	利伯曼-LLP
1485	Gtfocli - GTFO Command Line Interface For Easy Binaries Search Commands That Can Be Used To Bypass Local Security Restrictions In Misconfigured Systems	http://www.kitploit.com/2024/03/gtfocli-gtfo-command-line-interface-for.html	kitploit	tool;Gtfocli;Unix;Windows;	1	2024-03-12	Gtfocli - GTfocli - GTFO 用于可用来绕过错误配置系统中的本地安全限制的简易二进制搜索命令的 GTFO 命令线界面
10230	UNC5174 ScreenConnect and F5 BIG-IP exploitation	https://threats.wiz.io/all-incidents/unc5174-screenconnect-and-f5-big-ip-exploitation	wizio	incident;	1	2024-03-27	UNC5174 屏幕监视和F5 大IG-IP剥削
10257	Barrie-and-Community-Family-Health-Team	http://www.ransomfeed.it/index.php?page=post_details&id_post=13953	ransomfeed	ransom;incransom;	1	2024-03-26	律师-社区-家庭-健康-工作队
2758	Russia claims US and 'Western countries' are trying to hack its presidential election	https://therecord.media/russia-presidential-election-hack-claims-united-states-putin	therecord	ransom;Government;Elections;News;Nation-state;Leadership;	3	2024-03-13	俄国声称美国和西方国家正试图黑其总统选举,
18425	全球网络安全产业3月投融资简报	https://www.freebuf.com/news/397214.html	freebuf	news;资讯;	1	2024-04-08	全球网络安全产业3月投融资简报
10212	WiCyS and ISC2 Launch Spring Camp for Cybersecurity Certification	https://www.darkreading.com/cybersecurity-operations/wicys-and-isc2-launch-spring-camp-for-cybersecurity-certification	darkreading	news;	1	2024-03-27	WicCyS和ICSC2网络安全认证春季启动营地
10216	Zero-Day Bonanza Drives More Exploits Against Enterprises	https://www.darkreading.com/threat-intelligence/zero-day-bonanza-exploits-enterprises	darkreading	news;	1	2024-03-27	Bonanza车道 " 零日 " 活动对企业的更多剥削
28716	Red Hat Security Advisory 2024-1795-03	https://packetstormsecurity.com/files/178030/RHSA-2024-1795-03.txt	packetstorm	vuln;;	1	2024-04-12	红帽子安保咨询2024-1795-03
28717	MinIO Privilege Escalation	https://packetstormsecurity.com/files/178031/minio-escalate.txt	packetstorm	vuln;;	1	2024-04-12	MINIO 特权升级
28718	WordPress Playlist For Youtube 1.32 Cross Site Scripting	https://packetstormsecurity.com/files/178032/wpplfy132-xss.txt	packetstorm	vuln;;	1	2024-04-12	Youtube 1. 32 WordPress 播放列表跨站点脚本
16367	DataBank	http://www.ransomfeed.it/index.php?page=post_details&id_post=14102	ransomfeed	ransom;hunters;	1	2024-04-03	数据银行
9534	German political parties are latest targets of Russian cyber spies	https://therecord.media/german-political-parties-russia-espionage-svr	therecord	ransom;Government;Nation-state;News;	3	2024-03-22	德国政党是俄罗斯网络间谍的最新目标
16380	Sit	http://www.ransomfeed.it/index.php?page=post_details&id_post=14118	ransomfeed	ransom;play;	1	2024-04-04	坐席 坐席
16368	Beaver-Run-Resort	http://www.ransomfeed.it/index.php?page=post_details&id_post=14103	ransomfeed	ransom;hunters;	1	2024-04-03	Beaver- 运行中Resort
16366	Interface	http://www.ransomfeed.it/index.php?page=post_details&id_post=14101	ransomfeed	ransom;hunters;	1	2024-04-03	界面界面
16364	Intersport	http://www.ransomfeed.it/index.php?page=post_details&id_post=14099	ransomfeed	ransom;hunters;	1	2024-04-03	间接
16373	Remitano---Cryptocurrency-Exchange	http://www.ransomfeed.it/index.php?page=post_details&id_post=14110	ransomfeed	ransom;incransom;	1	2024-04-04	雷米诺-克里普托货币兑换
16376	Orientrose-Contracts-	http://www.ransomfeed.it/index.php?page=post_details&id_post=14113	ransomfeed	ransom;medusa;	1	2024-04-04	东方合同
16365	BeneCare-Dental-Insurance	http://www.ransomfeed.it/index.php?page=post_details&id_post=14100	ransomfeed	ransom;hunters;	1	2024-04-03	养恤金 -- -- 定期 -- -- 保险
16363	Citi-Trends	http://www.ransomfeed.it/index.php?page=post_details&id_post=14098	ransomfeed	ransom;hunters;	1	2024-04-03	花点趋势
16379	Everbrite	http://www.ransomfeed.it/index.php?page=post_details&id_post=14117	ransomfeed	ransom;play;	1	2024-04-04	易食
16377	Sutton-Dental-Arts	http://www.ransomfeed.it/index.php?page=post_details&id_post=14114	ransomfeed	ransom;medusa;	1	2024-04-04	音乐艺术
16375	Radiant-Canada	http://www.ransomfeed.it/index.php?page=post_details&id_post=14112	ransomfeed	ransom;akira;	1	2024-04-04	加拿大拉迪安特
16369	Benetton-Group	http://www.ransomfeed.it/index.php?page=post_details&id_post=14104	ransomfeed	ransom;hunters;	1	2024-04-03	Bennetton 群組
10562	AI weaponization becomes a hot topic on underground forums	https://www.helpnetsecurity.com/2024/03/28/ai-automation-threat/	helpnetsecurity	news;News;artificial intelligence;automation;cybercrime;cybersecurity;ReliaQuest;report;survey;	1	2024-03-28	AII武器化成为地下论坛热门话题
16361	Norman-Urology-Associates	http://www.ransomfeed.it/index.php?page=post_details&id_post=14095	ransomfeed	ransom;incransom;	1	2024-04-03	诺曼-城市协会
16381	Guys-Floor-Service	http://www.ransomfeed.it/index.php?page=post_details&id_post=14119	ransomfeed	ransom;play;	1	2024-04-04	男男性行为者服务
8493	Phishing-as-a-Service Platforms LabHost and Frappo Help Threat Actors Target Canadian Banks	https://blog.knowbe4.com/phishing-as-a-service-platforms-labhost-and-frappo-help-threat-actors-target-canadian-banks	knowbe4	news;Phishing;Security Awareness Training;Security Culture;	1	2024-03-19	Lab Host和Frappo帮助威胁行为者袭击加拿大银行
19474	Defining a holistic GRC strategy	https://www.helpnetsecurity.com/2024/04/09/holistic-grc-strategy-video/	helpnetsecurity	news;Don't miss;Hot stuff;Video;compliance;cybersecurity;LogicGate;risk management;strategy;video;	1	2024-04-09	确定一个综合性全球RC 战略
18466	Massive AT&T Data Leak, The Danger of Thread Hijacking	https://securityboulevard.com/2024/04/massive-att-data-leak-the-danger-of-thread-hijacking/	securityboulevard	news;Data Security;Security Bloggers Network;Social Engineering;Threats & Breaches;ATT;Cyber Security;Cybersecurity;Data breach;Data leak;Data Privacy;Digital Privacy;email;Episodes;Information Security;Infosec;Phishing;Podcast;Podcasts;Privacy;Scams;security;social engineering;Solar Eclipse;technology;Thread Hijacking;Weekly Edition;	1	2024-04-08	大规模AT&T数据泄漏,线索劫持的危险
16378	Inspection-Services	http://www.ransomfeed.it/index.php?page=post_details&id_post=14115	ransomfeed	ransom;akira;	1	2024-04-04	检查-服务
16370	Giex	http://www.ransomfeed.it/index.php?page=post_details&id_post=14105	ransomfeed	ransom;raworld;	1	2024-04-03	Giex 吉列
26200	华为知情人士回应与懂车帝停止合作 	https://s.weibo.com/weibo?q=%23华为知情人士回应与懂车帝停止合作 %23	sina.weibo	hotsearch;weibo	1	2024-01-03	华为知情人士回应与懂车帝停止合作
26201	华为耳夹耳机 	https://s.weibo.com/weibo?q=%23华为耳夹耳机 %23	sina.weibo	hotsearch;weibo	1	2023-12-26	华为耳夹耳机
9552	Unsaflok Vulnerability Lets Hackers Open 3M+ Hotel Doors in Seconds	https://gbhackers.com/unsaflok-vulnerability/	GBHacker	news;Cyber Attack;Cyber Security News;Vulnerability;	1	2024-03-22	让黑客打开 3M+ 酒店门以秒计
16371	Wacks-Law-Group	http://www.ransomfeed.it/index.php?page=post_details&id_post=14106	ransomfeed	ransom;qilin;	1	2024-04-03	Wacks-法律小组
16362	West-Idaho-Orthopedics	http://www.ransomfeed.it/index.php?page=post_details&id_post=14096	ransomfeed	ransom;incransom;	1	2024-04-03	西爱达荷 - 东正教
16374	Constelacion-Savings-and-Credit-Society	http://www.ransomfeed.it/index.php?page=post_details&id_post=14111	ransomfeed	ransom;ransomhub;	1	2024-04-04	康星-救生-救生-救生-救生-救生-救生-救世-救世-救世-救世-救世-救世-救世-社
26202	华为邀请4家合作车企共投合资公司 	https://s.weibo.com/weibo?q=%23华为邀请4家合作车企共投合资公司 %23	sina.weibo	hotsearch;weibo	1	2023-11-28	华为邀请4家合作车企共投合资公司
16372	mcalvaincom	http://www.ransomfeed.it/index.php?page=post_details&id_post=14109	ransomfeed	ransom;cactus;	1	2024-04-04	脑积分
26203	华为重夺中国手机市场销量第一宝座 	https://s.weibo.com/weibo?q=%23华为重夺中国手机市场销量第一宝座 %23	sina.weibo	hotsearch;weibo	1	2024-02-04	华为重夺中国手机市场销量第一宝座
26205	华为门店里有龙出没 	https://s.weibo.com/weibo?q=%23华为门店里有龙出没 %23	sina.weibo	hotsearch;weibo	1	2024-01-12	华为门店里有龙出没
26206	华为预计23年营收超7000亿元 	https://s.weibo.com/weibo?q=%23华为预计23年营收超7000亿元 %23	sina.weibo	hotsearch;weibo	1	2023-12-29	华为预计23年营收超7000亿元
29136	多家德国组织遭受网络攻击	https://buaq.net/go-234276.html	buaq	newscopy;	0	2024-04-15	多家德国组织遭受网络攻击
29151	受国家支持的黑客正积极利用Palo Alto Networks 防火墙零日漏洞	https://www.freebuf.com/news/397973.html	freebuf	news;资讯;	3	2024-04-15	受国家支持的黑客正积极利用Palo Alto Networks 防火墙零日漏洞
21684	Microsoft Fixes 149 Flaws in Huge April Patch Release, Zero-Days Included	https://thehackernews.com/2024/04/microsoft-fixes-149-flaws-in-huge-april.html	feedburner	news;	1	2024-04-10	Microsoft 修补巨型四月补丁释放中的149条法,包括零天
10184	Google fixes Chrome zero-days exploited at Pwn2Own 2024	https://www.bleepingcomputer.com/news/security/google-fixes-chrome-zero-days-exploited-at-pwn2own-2024/	bleepingcomputer	news;Security;Google;	1	2024-03-27	谷歌修复在Pwn2Own 2024开发的铬零日
10186	INC Ransom threatens to leak 3TB of NHS Scotland stolen data	https://www.bleepingcomputer.com/news/security/inc-ransom-threatens-to-leak-3tb-of-nhs-scotland-stolen-data/	bleepingcomputer	news;Security;Healthcare;	2	2024-03-27	INCRansom有可能泄漏苏格兰国家保健服务系统失窃数据的3TB
10187	New Darcula phishing service targets iPhone users via iMessage	https://www.bleepingcomputer.com/news/security/new-darcula-phishing-service-targets-iphone-users-via-imessage/	bleepingcomputer	news;Security;	2	2024-03-27	iMessage的iPhone用户
10188	Ransomware as a Service and the Strange Economics of the Dark Web	https://www.bleepingcomputer.com/news/security/ransomware-as-a-service-and-the-strange-economics-of-the-dark-web/	bleepingcomputer	news;Security;	2	2024-03-27	Ransomware作为暗网的服务和奇异经济学
10190	Patchless Apple M-Chip Vulnerability Allows Cryptography Bypass	https://www.darkreading.com/application-security/patchless-apple-m-chip-vulnerability-cryptography-bypass	darkreading	news;	1	2024-03-27	无孔不全的苹果 M-芯片脆弱性允许加密绕过
10191	'Tycoon' Malware Kit Bypasses Microsoft, Google MFA	https://www.darkreading.com/application-security/tycoon-malware-kit-bypasses-microsoft-google-mfa	darkreading	news;	1	2024-03-27	微软、谷歌MFA
10194	Checkmarx Announces Partnership With Wiz	https://www.darkreading.com/cloud-security/checkmarx-announces-partnership-with-wiz	darkreading	news;	1	2024-03-27	Checkmarx 宣布与 Wiz 的伙伴关系
10196	Australian Government Doubles Down On Cybersecurity in Wake of Major Attacks	https://www.darkreading.com/cyber-risk/australian-government-doubles-down-on-cybersecurity-in-wake-of-major-attacks	darkreading	news;	1	2024-03-27	澳大利亚政府在大规模袭击后双倍降低网络安全
10202	Flare Acquires Foretrace to Accelerate Threat Exposure Management Growth	https://www.darkreading.com/cyberattacks-data-breaches/flare-acquires-foretrace-to-accelerate-threat-exposure-management-growth	darkreading	news;	1	2024-03-27	加速威胁接触管理增长
10204	New Cyber Threats to Challenge Financial Services Sector in 2024	https://www.darkreading.com/cyberattacks-data-breaches/new-cyber-threats-to-challenge-financial-services-sector-in-2024	darkreading	news;	1	2024-03-27	2024年挑战金融服务部门的新网络威胁
10205	Threat Report: Examining the Use of AI in Attack Techniques	https://www.darkreading.com/cyberattacks-data-breaches/threat-report-examining-the-use-of-ai-in-attack-techniques	darkreading	news;	1	2024-03-27	威胁报告:审查在攻击技术中使用人工智能的情况
10168	ISO 42001	https://securityboulevard.com/2024/03/iso-42001/	securityboulevard	news;Governance, Risk & Compliance;Security Bloggers Network;Compliance;security;	1	2024-03-27	ISO 42001
10169	NIST CSF 2.0 – Top 10 Things You Should Know	https://securityboulevard.com/2024/03/nist-csf-2-0-top-10-things-you-should-know/	securityboulevard	news;Security Bloggers Network;assessment;Axio Insights;NISTCSF2.0;	1	2024-03-27	NIST SCF 2.0 - 10大事情你应该知道
10170	Randall Munroe’s XKCD ‘The Wreck of the Edmund Fitzgerald’	https://securityboulevard.com/2024/03/randall-munroes-xkcd-the-wreck-of-the-edmund-fitzgerald/	securityboulevard	news;Humor;Security Bloggers Network;Randall Munroe;Sarcasm;satire;XKCD;	1	2024-03-27	Randall Munroe的XKCD“埃德蒙·菲茨杰拉德的沉船”
10171	Ransomware in Context: 2024, A Year of Tumultuous Change	https://securityboulevard.com/2024/03/ransomware-in-context-2024-a-year-of-tumultuous-change/	securityboulevard	news;Security Bloggers Network;Blog;Dark Web Insider;	2	2024-03-27	2024年 " 巨变年 "
10172	SANS 2024 Threat Hunting Survey: Hunting for Normal Within Chaos	https://securityboulevard.com/2024/03/sans-2024-threat-hunting-survey-hunting-for-normal-within-chaos/	securityboulevard	news;Security Bloggers Network;library;White Paper;	1	2024-03-27	SANS 2024 威胁狩猎调查:为动乱中的正常进行狩猎
10173	The Cool Evolution: Liquid Cooling in Data Centers	https://securityboulevard.com/2024/03/the-cool-evolution-liquid-cooling-in-data-centers/	securityboulevard	news;Security Bloggers Network;Infrastructure;	1	2024-03-27	冷酷进化:数据中心的液体冷却
10175	Vulnerability Management Lifecycle in DevSecOps	https://securityboulevard.com/2024/03/vulnerability-management-lifecycle-in-devsecops/	securityboulevard	news;DevOps;Security Bloggers Network;Vulnerabilities;DevSecOps;Vulnerability Management;	1	2024-03-27	DevsecOps中的脆弱性管理生命周期
12	CISA Warns of Actively Exploited JetBrains TeamCity Vulnerability	https://thehackernews.com/2024/03/cisa-warns-of-actively-exploited.html	feedburner	news;	1	2024-03-08	CISA 主动被利用喷气排气团队的脆弱性
10178	Windows 11 22H2 Home and Pro get preview updates until June 26	https://www.bleepingcomputer.com/news/microsoft/windows-11-22h2-home-and-pro-get-preview-updates-until-june-26/	bleepingcomputer	news;Microsoft;	1	2024-03-27	Window 11 22H2 Home and Pro 获得预览更新,直到 6月26日
10009	It’s Official: Cyber Insurance is No Longer Seen as a 'Safety Net'	https://blog.knowbe4.com/cyber-insurance-no-longer-seen-safety-net	knowbe4	news;Security Culture;	1	2024-03-26	网络保险作为“安全网”并不长。
25917	余承东称华为智驾是现货不是期货 	https://s.weibo.com/weibo?q=%23余承东称华为智驾是现货不是期货 %23	sina.weibo	hotsearch;weibo	1	2024-04-11	余承东称华为智驾是现货不是期货
10176	KuCoin charged with AML violations that let cybercriminals launder billions	https://www.bleepingcomputer.com/news/cryptocurrency/kucoin-charged-with-aml-violations-that-let-cybercriminals-launder-billions/	bleepingcomputer	news;CryptoCurrency;Legal;	1	2024-03-27	Kucoin被控违反反洗钱法,让网络罪犯洗钱数十亿
25918	华为	https://s.weibo.com/weibo?q=%23华为%23	sina.weibo	hotsearch;weibo	1	2024-04-09	华为
25919	华为980克新款旗舰笔记本有多强 	https://s.weibo.com/weibo?q=%23华为980克新款旗舰笔记本有多强 %23	sina.weibo	hotsearch;weibo	1	2024-04-11	华为980克新款旗舰笔记本有多强
10342	The foundation for responsible analytics with Microsoft Purview	https://www.microsoft.com/en-us/security/blog/2024/03/26/the-foundation-for-responsible-analytics-with-microsoft-purview/	microsoft	news;	1	2024-03-26	与微软Purview进行负责任的分析基金会
10359	‘Malicious Activity’ Hits the University of Cambridge’s Medical School	https://www.wired.com/story/university-of-cambridge-medical-school-malicious-activity/	wired	news;Security;Security / Cyberattacks and Hacks;Security / Security News;	1	2024-03-27	剑桥大学医学院
21762	New SharePoint Technique Lets Hackers Bypass Security Measures	https://gbhackers.com/sharepoint-technique-bypas/	GBHacker	news;Cyber Security News;Vulnerability;computer security;cyber security;	1	2024-04-10	新的分享点技术让黑客绕过通道安全措施
21768	安全风险攻击面管理如何提升企业网络弹性？	https://www.freebuf.com/articles/397387.html	freebuf	news;	1	2024-04-10	安全风险攻击面管理如何提升企业网络弹性？
10361	Borrower beware: Common loan scams and how to avoid them	https://www.welivesecurity.com/en/scams/borrower-beware-common-loan-scams/	eset	news;	1	2024-03-26	借款人当心:常见的贷款骗债和如何避免
21771	网传桌面版telegram RCE 0day	https://www.freebuf.com/articles/system/397422.html	freebuf	news;系统安全;	1	2024-04-10	网传桌面版telegram RCE 0day
10362	Hack The Box: Nubilum-1 Sherlock Walkthrough – Medium Difficulty	https://threatninja.net/2024/03/hack-the-box-nubilum-1-sherlock-walkthrough-medium-difficulty/	threatninja	sectest;Sherlock Medium;Challenges;	1	2024-03-27	黑盒:Nubilum-1夏洛克漫步 — — 中度困难
10363	WordPress Bricks Builder Theme 1.9.6 Remote Code Execution	https://cxsecurity.com/issue/WLB-2024030064	cxsecurity	vuln;	1	2024-03-27	Wordpress Bricks 构建器主题 1.9.6 远程代码执行
10364	Sharepoint Dynamic Proxy Generator Remote Command Execution	https://cxsecurity.com/issue/WLB-2024030065	cxsecurity	vuln;	1	2024-03-27	共享点动态代理发电机远程指令执行
10371	Cisco Firepower Management Center <  6.6.7.1 Authenticated RCE	https://cxsecurity.com/issue/WLB-2024030066	cxsecurity	vuln;	1	2024-03-27	Cisco烟火管理中心 < 6.6.7.1 经认证的RCE
10379	Red Hat Security Advisory 2024-1456-03	https://packetstormsecurity.com/files/177785/RHSA-2024-1456-03.txt	packetstorm	vuln;;	1	2024-03-27	红色帽子安保咨询 2024-1456-03
10380	Red Hat Security Advisory 2024-1458-03	https://packetstormsecurity.com/files/177786/RHSA-2024-1458-03.txt	packetstorm	vuln;;	1	2024-03-27	红色帽子安保咨询 2024-1458-03
10381	Red Hat Security Advisory 2024-1461-03	https://packetstormsecurity.com/files/177787/RHSA-2024-1461-03.txt	packetstorm	vuln;;	1	2024-03-27	红色帽子安保咨询 2024-1461-03
10382	Red Hat Security Advisory 2024-1512-03	https://packetstormsecurity.com/files/177788/RHSA-2024-1512-03.txt	packetstorm	vuln;;	1	2024-03-27	红色帽子安保咨询2024-1512-03
10383	Red Hat Security Advisory 2024-1513-03	https://packetstormsecurity.com/files/177789/RHSA-2024-1513-03.txt	packetstorm	vuln;;	1	2024-03-27	红色帽子安保咨询2024-1513-03
10384	Red Hat Security Advisory 2024-1514-03	https://packetstormsecurity.com/files/177790/RHSA-2024-1514-03.txt	packetstorm	vuln;;	1	2024-03-27	红色帽子安保咨询2024-1514-03
10304	Boingo-Graphics	http://www.ransomfeed.it/index.php?page=post_details&id_post=14000	ransomfeed	ransom;play;	1	2024-03-27	博因戈语谱
10306	prodrivecom	http://www.ransomfeed.it/index.php?page=post_details&id_post=14003	ransomfeed	ransom;blackbasta;	1	2024-03-27	孔驱动器
10307	dgsecom	http://www.ransomfeed.it/index.php?page=post_details&id_post=14004	ransomfeed	ransom;blackbasta;	1	2024-03-27	dgsecom/ dgsecom
10323	CISA 和 FBI 敦促开发人员“全力消除” SQL 注入漏洞	https://www.freebuf.com/news/396035.html	freebuf	news;资讯;	3	2024-03-27	CISA 和 FBI 敦促开发人员“全力消除” SQL 注入漏洞
10324	Gartner 公布 2024 年八大网络安全预测	https://www.freebuf.com/news/396041.html	freebuf	news;资讯;	1	2024-03-27	Gartner 公布 2024 年八大网络安全预测
10326	FreeBuf 早报 | 数千家使用Ray的公司面临攻击威胁；攻击者利用人工智能生成虚假讣告	https://www.freebuf.com/news/396133.html	freebuf	news;资讯;	1	2024-03-27	FreeBuf 早报 | 数千家使用Ray的公司面临攻击威胁；攻击者利用人工智能生成虚假讣告
10328	Bedrock Security protects sensitive data within one unified platform	https://www.helpnetsecurity.com/2024/03/27/bedrock-security-data-platform/	helpnetsecurity	news;Industry news;Bedrock Security;	1	2024-03-27	安保安保在一个统一平台内保护敏感数据
10329	AI framework vulnerability is being used to compromise enterprise servers (CVE-2023-48022)	https://www.helpnetsecurity.com/2024/03/27/cve-2023-48022/	helpnetsecurity	news;Don't miss;Hot stuff;News;Anyscale;authentication;Bishop Fox;enterprise;machine learning;Oligo Security;vulnerability;	3	2024-03-27	正在利用大赦国际框架脆弱性框架脆弱性来损害企业服务器(CVE-2023-48022)
10330	CyberArk Secure Browser helps prevent breaches resulting from cookie theft	https://www.helpnetsecurity.com/2024/03/27/cyberark-secure-browser/	helpnetsecurity	news;Industry news;CyberArk;	1	2024-03-27	CyberArrk 安全浏览器有助于防止饼干盗窃造成的破坏
10331	Cybersecurity jobs available right now: March 27, 2024	https://www.helpnetsecurity.com/2024/03/27/cybersecurity-jobs-available-right-now-march-27-2024/	helpnetsecurity	news;Don't miss;Hot stuff;News;cybersecurity jobs;	1	2024-03-27	2024年3月27日 2024年3月27日
10334	Malwarebytes adds AI functionality to ThreatDown Security Advisor	https://www.helpnetsecurity.com/2024/03/27/malwarebytes-threatdown-security-advisor/	helpnetsecurity	news;Industry news;Malwarebytes;	1	2024-03-27	Malwarebytes将AI功能添加到威胁下安全顾问
10335	Essential elements of a strong data protection strategy	https://www.helpnetsecurity.com/2024/03/27/matt-waxman-veritas-technologies-data-protection-strategies/	helpnetsecurity	news;Don't miss;Features;Hot stuff;News;backup;cloud;cyber resilience;cybersecurity;data protection;opinion;strategy;Veritas Technologies;	1	2024-03-27	强有力的数据保护战略的基本要素
10336	Attackers leverage weaponized iMessages, new phishing-as-a-service platform	https://www.helpnetsecurity.com/2024/03/27/phishing-imessages-google-messages/	helpnetsecurity	news;Don't miss;Hot stuff;News;Android;iOS;macOS;Netcraft;phishing;	1	2024-03-27	攻击者利用武器化iMessages,新的网钓服务平台
10423	SANS 2024 Threat Hunting Survey: Hunting for Normal Within Chaos	https://buaq.net/go-230925.html	buaq	newscopy;	0	2024-03-28	SANS 2024 威胁狩猎调查:为动乱中的正常进行狩猎
10424	The Cool Evolution: Liquid Cooling in Data Centers	https://buaq.net/go-230926.html	buaq	newscopy;	0	2024-03-28	冷酷进化:数据中心的液体冷却
10426	Vulnerability Management Lifecycle in DevSecOps	https://buaq.net/go-230928.html	buaq	newscopy;	0	2024-03-28	DevsecOps中的脆弱性管理生命周期
10427	RozDll The Dynamic Hijacking Reverse Engineering Tool	https://buaq.net/go-230931.html	buaq	newscopy;	0	2024-03-28	RozDll 动态劫持反向工程工具
10428	Smashing Security podcast #365: Hacking hotels, Google’s AI goof, and cyberflashing	https://buaq.net/go-230932.html	buaq	newscopy;	0	2024-03-28	Smashing安全播客#365:黑客酒店、谷歌的AI高高楼和网络打击
10386	Red Hat Security Advisory 2024-1516-03	https://packetstormsecurity.com/files/177792/RHSA-2024-1516-03.txt	packetstorm	vuln;;	1	2024-03-27	红色帽子安保咨询2024-1516-03
21784	我参加了 OpenAI 红队的活动，并带来了一些笔记	https://www.freebuf.com/news/397407.html	freebuf	news;资讯;	1	2024-04-10	我参加了 OpenAI 红队的活动，并带来了一些笔记
10387	Red Hat Security Advisory 2024-1518-03	https://packetstormsecurity.com/files/177793/RHSA-2024-1518-03.txt	packetstorm	vuln;;	1	2024-03-27	2024-1518-03红色帽子安保咨询
10388	Red Hat Security Advisory 2024-1522-03	https://packetstormsecurity.com/files/177794/RHSA-2024-1522-03.txt	packetstorm	vuln;;	1	2024-03-27	红帽子安保咨询2024-1522-03
10390	Red Hat Security Advisory 2024-1532-03	https://packetstormsecurity.com/files/177796/RHSA-2024-1532-03.txt	packetstorm	vuln;;	1	2024-03-27	红色帽子安保咨询2024-1532-03
10391	Red Hat Security Advisory 2024-1533-03	https://packetstormsecurity.com/files/177797/RHSA-2024-1533-03.txt	packetstorm	vuln;;	1	2024-03-27	红色帽子安保咨询2024-1533-03
10392	DotNet-MetaData Analysis Tooling	https://packetstormsecurity.com/files/177798/DotNet-MetaData-main.zip	packetstorm	vuln;;	1	2024-03-27	DotNet-MetataData 分析工具
10393	Ubuntu Security Notice USN-6718-1	https://packetstormsecurity.com/files/177799/USN-6718-1.txt	packetstorm	vuln;;	1	2024-03-27	Ubuntu Ubuntu 安全通知 USN-6718-1
10394	Artica Proxy Unauthenticated PHP Deserialization	https://packetstormsecurity.com/files/177800/artica_proxy_unauth_rce_cve_2024_2054.rb.txt	packetstorm	vuln;;	1	2024-03-27	Artica 代理代理 未经认证 PHP
10396	Sharepoint Dynamic Proxy Generator Remote Command Execution	https://packetstormsecurity.com/files/177802/sharepoint_dynamic_proxy_generator_auth_bypass_rce.rb.txt	packetstorm	vuln;;	1	2024-03-27	共享点动态代理发电机远程指令执行
10397	CISA publishes 447-page draft of cyber incident reporting rule	https://therecord.media/cisa-publishes-circia-rule-cyber-incident-reporting	therecord	ransom;Government;Industry;News;	1	2024-03-27	CISA出版447页的网络事件报告规则草案
10401	Municipalities in Texas, Georgia see services disrupted following ransomware attacks	https://therecord.media/texas-georgia-municipalities-face-disruptions-from-ransomware	therecord	ransom;Cybercrime;Government;News;	2	2024-03-27	格鲁吉亚得克萨斯市的德克萨斯市看到因赎金软件袭击而中断的服务
10403	Noia - Simple Mobile Applications Sandbox File Browser Tool	http://www.kitploit.com/2024/03/noia-wip-simple-mobile-applications.html	kitploit	tool;Android Security;Android Tools;Hacking Tools;iOS Security;Ios Tools;Noia;Reverse Engineering;	1	2024-03-27	Noia - 简单移动应用程序沙箱文件浏览器工具
10408	Airbus to Acquire INFODAS to Strengthen its Cybersecurity Portfolio	https://gbhackers.com/airbus-acquire-infodas/	GBHacker	news;cyber security;Cyber security Course;Cyber Security News;	1	2024-03-27	向获得INFODAS以加强其网络安全组合的空中客客车
10409	Beware of Free Android VPN Apps that Turn Your Device into Proxies	https://gbhackers.com/beware-android-vpn-proxies/	GBHacker	news;Android;Cyber Security News;vpn;	2	2024-03-27	请注意将您的设备转换为近身的 免费和机器人 VPN 应用程序
10411	CISA Warns of Hackers Exploiting Microsoft SharePoint Server	https://gbhackers.com/cisa-warns-hackers-exploiting-2/	GBHacker	news;Cyber Security News;Microsoft;Cyber Attack;cyber security;	1	2024-03-27	CISA 利用微软 SharePoint 服务器的黑客战争
10412	Hackers Actively Exploiting Ray AI Framework Flaw to Hack Thousands of Servers	https://gbhackers.com/hackers-exploiting-ray-ai-framework/	GBHacker	news;Cyber AI;Cyber Security News;cyber security;	1	2024-03-27	黑客积极利用雷光 AI Frame Flaw 给黑客数千个服务器
10413	Metasploit Framework 6.4 Released: What’s New!	https://gbhackers.com/metasploit-framework-6-4/	GBHacker	news;Cyber Security News;what is New;Malware;	1	2024-03-27	假冒框架6.4 释放:什么是新的!
10414	Microsoft Expands Edge Bounty Program to Include WebView2!	https://gbhackers.com/microsoft-eedge-bounty-webview2/	GBHacker	news;Bug Bounty;Cyber Security News;Microsoft;cyber security;Vulnerability;	1	2024-03-27	微软 扩大边边博恩蒂程序以包含 WebView2 !
10417	ZENHAMMER – First Rowhammer Attack Impacting Zen-based AMD Platforms	https://gbhackers.com/zenhammer-first-rowhammer/	GBHacker	news;cyber security;Cyber Security News;Vulnerability;computer security;	1	2024-03-27	ZENHAMMER - 以Zen为基地的AMD平台首台冲击冲击Zen
10418	IREG	https://buaq.net/go-230917.html	buaq	newscopy;	0	2024-03-28	英 利 利 伊 利 利 伊 利 伊 利 伊
10419	Jailbreaking ChatGPT prompt injections examples	https://buaq.net/go-230918.html	buaq	newscopy;	0	2024-03-28	即时注射实例
10420	CISA publishes 447-page draft of cyber incident reporting rule	https://buaq.net/go-230919.html	buaq	newscopy;	0	2024-03-28	CISA出版447页的网络事件报告规则草案
10421	Windows 11 22H2 Home and Pro get preview updates until June 26	https://buaq.net/go-230920.html	buaq	newscopy;	0	2024-03-28	Window 11 22H2 Home and Pro 获得预览更新,直到 6月26日
25920	华为MateBook 	https://s.weibo.com/weibo?q=%23华为MateBook %23	sina.weibo	hotsearch;weibo	1	2024-04-11	华为MateBook
25921	华为P70 	https://s.weibo.com/weibo?q=%23华为P70 %23	sina.weibo	hotsearch;weibo	1	2024-04-11	华为P70
10433	Sharepoint Dynamic Proxy Generator Remote Command Execution	https://buaq.net/go-230937.html	buaq	newscopy;	0	2024-03-28	共享点动态代理发电机远程指令执行
10434	WordPress Bricks Builder Theme 1.9.6 Remote Code Execution	https://buaq.net/go-230938.html	buaq	newscopy;	0	2024-03-28	Wordpress Bricks 构建器主题 1.9.6 远程代码执行
10435	Why Investors Are Excited About The Metaverse In 2024	https://buaq.net/go-230939.html	buaq	newscopy;	0	2024-03-28	为何投资者对2024年的“假相”兴奋
10437	Motivation Doesn't Last: Here's Why	https://buaq.net/go-230941.html	buaq	newscopy;	0	2024-03-28	动机并不持久:这就是为什么
85	How to Ensure Open Source Packages Are Not Landmines	https://www.darkreading.com/application-security/how-to-ensure-open-source-pckages-are-not-landmines	darkreading	news;	1	2024-03-08	如何确保开放源软件包不是地雷
2990	【翻译】变脸BianLian用PowerShell重写了 BianLian GO后门	https://xz.aliyun.com/t/14081	阿里先知实验室	news;	1	2024-03-11	【翻译】变脸BianLian用PowerShell重写了 BianLian GO后门
375	Ubuntu Security Notice USN-6685-1	https://packetstormsecurity.com/files/177511/USN-6685-1.txt	packetstorm	vuln;;	1	2024-03-08	Ubuntu Ubuntu 安全通知 USN6685-1
9976	Spoutible Enhances Platform Security through Partnership with Wallarm	https://securityboulevard.com/2024/03/spoutible-enhances-platform-security-through-partnership-with-wallarm/	securityboulevard	news;Security Bloggers Network;API security;	1	2024-03-26	通过与瓦勒伙伴关系加强平台安全
414	WinFiHack - A Windows Wifi Brute Forcing Utility Which Is An Extremely Old Method But Still Works Without The Requirement Of External Dependencies	http://www.kitploit.com/2024/03/winfihack-windows-wifi-brute-forcing.html	kitploit	tool;Python;Scripts;Wifi;Windows;WinFiHack;	1	2024-03-07	WinFiHack - WinFiHack - Window Wifi Brute 一种 Window Wifi Brute 辅助功能,这种功能是极其老旧的方法,但是在没有外部依赖要求的情况下仍然有效
641	alanritcheycom	http://www.ransomfeed.it/index.php?page=post_details&id_post=13517	ransomfeed	ransom;blackbasta;	1	2024-02-29	anlanritcheycom 语
690	ipmaltamira	http://www.ransomfeed.it/index.php?page=post_details&id_post=13572	ransomfeed	ransom;alphv;	1	2024-03-03	Ip 玛玛塔米拉
10033	GitGuardian SCA automates vulnerability detection and prioritization for enhanced code health	https://www.helpnetsecurity.com/2024/03/26/gitguardian-software-composition-analysis-sca/	helpnetsecurity	news;Industry news;GitGuardian;	1	2024-03-26	GitGuardian SCA 将脆弱性检测自动化,并优先加强健康编码
2784	MSMS-PHP (by: oretnom23 - 2024) v1.0 Multiple-SQLi	https://buaq.net/go-227956.html	buaq	newscopy;	0	2024-03-14	MSMS-PHP (按: oretnom23 - 2024) v1.0 多SQLi
10039	Is That Delivery Text Real or Fake? How to Shop and Ship Safely this Season	https://www.mcafee.com/blogs/internet-security/is-that-delivery-text-real-or-fake-how-to-shop-and-ship-safely-this-season/	mcafee	news;	1	2024-03-27	送货文本是真实的还是假的?
3398	LockBit Ransomware Hacker Ordered to Pay $860,000 After Guilty Plea in Canada	https://thehackernews.com/2024/03/lockbit-ransomware-hacker-ordered-to.html	feedburner	news;	3	2024-03-14	Lock Bit Ransomware Hacker在加拿大认罪后下令支付86万美元
4916	Dark Web Market Admin Gets 42 Months Prison for Selling Login Passwords	https://gbhackers.com/dark-web-market-admin-arrested/	GBHacker	news;cyber security;Cyber Security News;computer security;	1	2024-03-17	黑网市场管理者因出售登录密码而被判处42个月的监禁
3467	TikTok Ban Raises Data Security, Control Questions	https://www.darkreading.com/cyber-risk/tiktok-ban-raises-data-security-control-questions	darkreading	news;	1	2024-03-14	TikTok Ban TikTok 提高数据安全、控制问题
9836	Vita-IT	http://www.ransomfeed.it/index.php?page=post_details&id_post=13925	ransomfeed	ransom;akira;	1	2024-03-25	维塔 -- -- IT
9837	European-Centre-for-Compensation	http://www.ransomfeed.it/index.php?page=post_details&id_post=13926	ransomfeed	ransom;akira;	1	2024-03-25	欧洲补偿中心
8439	From Deepfakes to Malware: AI's Expanding Role in Cyber Attacks	https://thehackernews.com/2024/03/from-deepfakes-to-malware-ais-expanding.html	feedburner	news;	1	2024-03-19	从深假到Malware:大赦国际在网络攻击中日益扩大的作用
8554	微软：87% 的英国企业极易受到网络攻击，AI或成破局“解药”	https://www.freebuf.com/news/395194.html	freebuf	news;资讯;	1	2024-03-19	微软：87% 的英国企业极易受到网络攻击，AI或成破局“解药”
8632	Novel Script-Based Attack That Leverages PowerShell And VBScript	https://gbhackers.com/power-vbscript-attack/	GBHacker	news;Cyber Attack;Cyber Security News;Malware;cyber security;Script-based Attacks;	1	2024-03-19	以新创脚本为基础的攻击, 利用电动 Shell 和 VBScript 和 VBScript 工具进行攻击
8633	How ANY.RUN Malware Sandbox Process IOCs for Threat Intelligence Lookup?	https://gbhackers.com/process-iocs-for-threat-intelligence-lookup/	GBHacker	news;Cyber Attack;Cyber Security News;What is;Malware;	1	2024-03-19	如何运行恶意沙箱 处理国际奥委会 威胁情报调查?
8635	WhiteSnake Stealer Checks for Mutex & VM Function Before Execution	https://gbhackers.com/whitesnake-stealer-checks/	GBHacker	news;Cyber Attack;Cyber Security News;Malware;	1	2024-03-19	执行前检查 Mutex & VM 函数的白蛇偷窃者检查
9876	Chinese Hackers Charged in Decade-Long Global Spying Rampage	https://www.wired.com/story/china-apt31-us-uk-hacking-espionage-charges-sanctions/	wired	news;Security;Security / Cyberattacks and Hacks;Security / National Security;Security / Security News;	4	2024-03-25	中国黑客在 " 十年之光 " 全球监视拉姆页上被指责
8636	Upcoming webinar: How a leading architecture firm approaches cybersecurity	https://buaq.net/go-229089.html	buaq	newscopy;	0	2024-03-20	即将举行的网络研讨会:主要建筑公司如何对待网络安全
25922	华为发布会 	https://s.weibo.com/weibo?q=%23华为发布会 %23	sina.weibo	hotsearch;weibo	1	2024-04-11	华为发布会
10430	New Darcula phishing service targets iPhone users via iMessage	https://buaq.net/go-230934.html	buaq	newscopy;	0	2024-03-28	iMessage的iPhone用户
25923	华为发布会没提P70 	https://s.weibo.com/weibo?q=%23华为发布会没提P70 %23	sina.weibo	hotsearch;weibo	1	2024-04-11	华为发布会没提P70
25924	华为口红耳机2 	https://s.weibo.com/weibo?q=%23华为口红耳机2 %23	sina.weibo	hotsearch;weibo	1	2024-04-10	华为口红耳机2
8654	俄罗斯人将无法再访问微软云服务和其他商业智能工具	https://buaq.net/go-229123.html	buaq	newscopy;	0	2024-03-20	俄罗斯人将无法再访问微软云服务和其他商业智能工具
9903	Red Hat Security Advisory 2024-1387-03	https://packetstormsecurity.com/files/177745/RHSA-2024-1387-03.txt	packetstorm	vuln;;	1	2024-03-25	2024-1387-03红色帽子安保咨询
9904	Red Hat Security Advisory 2024-1415-03	https://packetstormsecurity.com/files/177746/RHSA-2024-1415-03.txt	packetstorm	vuln;;	1	2024-03-25	红色帽子安保咨询 2024-1415-03
8651	Navigating New RWA Horizons: Rick Schmitz on Bridging Blockchain and Traditional Finance	https://buaq.net/go-229113.html	buaq	newscopy;	0	2024-03-20	RWA新地平线导航:Rick Schmitz关于 " 连锁链与传统融资的连接 "
8653	Pwn2Own Vancouver 2024 - The Full Schedule	https://buaq.net/go-229122.html	buaq	newscopy;	0	2024-03-20	Pwn2Own温哥华 2024 - 完整时间表
8655	供应链投毒预警 | 开源供应链投毒202402月报发布啦	https://buaq.net/go-229125.html	buaq	newscopy;	0	2024-03-20	供应链投毒预警 | 开源供应链投毒202402月报发布啦
10322	FreeBuf 早报 | 超大型养老院因网络攻击申请破产；欧美100多家组织遭恶意软件攻击	https://www.freebuf.com/news/395990.html	freebuf	news;资讯;	2	2024-03-26	FreeBuf 早报 | 超大型养老院因网络攻击申请破产；欧美100多家组织遭恶意软件攻击
8479	5 Ways CISOs Can Navigate Their New Business Role	https://www.darkreading.com/cybersecurity-operations/5-ways-cisos-can-navigate-new-business-role	darkreading	news;	1	2024-03-19	5 CISOs 能够发挥新商业作用的方式
8641	FTC warns scammers are impersonating its employees to steal money	https://buaq.net/go-229095.html	buaq	newscopy;	0	2024-03-20	公平贸易委员会警告诈骗者冒冒冒名顶替其雇员偷钱
8822	TYPO3 11.5.24 Path Traversal (Authenticated)	https://cxsecurity.com/issue/WLB-2024030040	cxsecurity	vuln;	1	2024-03-20	11.5.24 转轨路径(经批准)
8597	Red Hat Security Advisory 2024-1318-03	https://packetstormsecurity.com/files/177649/RHSA-2024-1318-03.txt	packetstorm	vuln;;	1	2024-03-19	2024-1318-03红色帽子安保咨询
8598	Red Hat Security Advisory 2024-1319-03	https://packetstormsecurity.com/files/177650/RHSA-2024-1319-03.txt	packetstorm	vuln;;	1	2024-03-19	2024-1319-03红色帽子安保咨询
8599	Red Hat Security Advisory 2024-1324-03	https://packetstormsecurity.com/files/177651/RHSA-2024-1324-03.txt	packetstorm	vuln;;	1	2024-03-19	2024-1324-03红色帽子安保咨询
8600	Red Hat Security Advisory 2024-1325-03	https://packetstormsecurity.com/files/177652/RHSA-2024-1325-03.txt	packetstorm	vuln;;	1	2024-03-19	2024-1325-03红色帽子安保咨询
8601	Red Hat Security Advisory 2024-1353-03	https://packetstormsecurity.com/files/177653/RHSA-2024-1353-03.txt	packetstorm	vuln;;	1	2024-03-19	2024-1353(2001)年红色帽子安保咨询
8602	Red Hat Security Advisory 2024-1354-03	https://packetstormsecurity.com/files/177654/RHSA-2024-1354-03.txt	packetstorm	vuln;;	1	2024-03-19	2024-1354-03红色帽子安保咨询
8604	Red Hat Security Advisory 2024-1368-03	https://packetstormsecurity.com/files/177656/RHSA-2024-1368-03.txt	packetstorm	vuln;;	1	2024-03-19	2024-1368-03红色帽子安保咨询
8605	Quick.CMS 6.7 SQL Injection	https://packetstormsecurity.com/files/177657/quickcms67-sql.txt	packetstorm	vuln;;	1	2024-03-19	快速 CMS 6.7 SQL 注射
8606	SurveyJS Survey Creator 1.9.132 Cross Site Scripting	https://packetstormsecurity.com/files/177658/surveyjssurveycreator19132-xss.txt	packetstorm	vuln;;	1	2024-03-19	1.9.132 跨地点文件
8607	GNUnet P2P Framework 0.21.1	https://packetstormsecurity.com/files/177659/gnunet-0.21.1.tar.gz	packetstorm	vuln;;	1	2024-03-19	GNUnet P2PP框架0.21.1
8608	Tramyardg Autoexpress 1.3.0 SQL Injection	https://packetstormsecurity.com/files/177660/autoexpress130-sql.txt	packetstorm	vuln;;	1	2024-03-19	Trampyardg 自动表达式 1.3.0 SQL 喷射
8609	Tramyardg Autoexpress 1.3.0 Authentication Bypass	https://packetstormsecurity.com/files/177661/autoexpress130-bypass.txt	packetstorm	vuln;;	1	2024-03-19	Trampyardg 自动表达式 1.3.0 认证快取
8610	Tramyardg Autoexpress 1.3.0 Cross Site Scripting	https://packetstormsecurity.com/files/177662/autoexpress130-xss.txt	packetstorm	vuln;;	1	2024-03-19	Tramiardg 自动表达式 1.3.0 跨站点脚本
8611	Ubuntu Security Notice USN-6701-1	https://packetstormsecurity.com/files/177663/USN-6701-1.txt	packetstorm	vuln;;	1	2024-03-19	Ubuntu Untuntu 安全通知 USN-6701-1
8617	White House cyber official urges UnitedHealth to provide third-party certification of network safety	https://therecord.media/white-house-official-united-health-certification-assessment	therecord	ransom;News;Government;Industry;	1	2024-03-19	白宫网络官员敦促联合卫生组织为网络安全提供第三方认证
8626	Researchers Hacked AI Assistants Using ASCII Art	https://gbhackers.com/ascii-art-ai-assistant-hack/	GBHacker	news;Artificial Intelligence;cyber security;Vulnerability;AI Security;ASCII Art;Jailbreak Attacks;	1	2024-03-19	研究人员利用ASCII艺术,利用ASCII艺术,利用AI助理
8628	CryptoWire Ransomware Attacking Abuses Schedule Task To maintain Persistence	https://gbhackers.com/cryptowire-ransomware-persistence-schedule-task-buse/	GBHacker	news;cyber security;Malware;Ransomware;Persistence;ransomware;	2	2024-03-19	加密光电序列软件攻击滥用 任务调度 以保持持久性
8629	E-Root Admin Sentenced to 42 Months in Prison for Selling 350,000 Credentials	https://gbhackers.com/e-root-admin-sentenced-to-42-months-in-prison/	GBHacker	news;Cyber Crime;cyber security;Cyber Security News;computer security;	1	2024-03-19	因出售350 000份全权证书而被判处42个月监禁
8627	BunnyLoader 3.0 Detected With Advanced Keylogging Capabilities	https://gbhackers.com/bunnyloader-3-0-advanced-keylogging-detected/	GBHacker	news;Cyber Security News;Malware;Vulnerability Analysis;cyber security;keylogging;Malware analysis;	1	2024-03-19	Bunny Loader 3. 0 以高级键盘记录能力检测到
25925	华为官宣春季沟通会时间 	https://s.weibo.com/weibo?q=%23华为官宣春季沟通会时间 %23	sina.weibo	hotsearch;weibo	1	2024-04-09	华为官宣春季沟通会时间
25926	华为智界S7价格权益真香 	https://s.weibo.com/weibo?q=%23华为智界S7价格权益真香 %23	sina.weibo	hotsearch;weibo	1	2024-04-11	华为智界S7价格权益真香
8630	Hackers Exploiting Microsoft Office Templates to Execute Malicious Code	https://gbhackers.com/hackers-exploiting-microsoft/	GBHacker	news;cyber security;Cyber Security News;Microsoft;Cyber Attack;	1	2024-03-19	利用微软办公室模板执行恶意守则
29904	2024阿里云ctf-web-chain17学习	https://xz.aliyun.com/t/14298	阿里先知实验室	news;	1	2024-04-15	2024阿里云ctf-web-chain17学习
8640	CISA shares critical infrastructure defense tips against Chinese hackers	https://buaq.net/go-229094.html	buaq	newscopy;	0	2024-03-20	CISA分享了针对中国黑客的重要基础设施防御小费
8642	‘Lifelock’ hacker pleads guilty to extorting medical clinics	https://buaq.net/go-229096.html	buaq	newscopy;	0	2024-03-20	“Lifellock”黑客承认勒索医疗诊所是有罪的。
8645	Misconfigured Firebase instances leaked 19 million plaintext passwords	https://buaq.net/go-229107.html	buaq	newscopy;	0	2024-03-20	错误配置的Firebase 事件泄漏了1 900万简文本密码
105	JetBrains TeamCity Mass Exploitation Underway, Rogue Accounts Thrive	https://www.darkreading.com/cyberattacks-data-breaches/jetbrains-teamcity-mass-exploitation-underway-rogue-accounts-thrive	darkreading	news;	1	2024-03-07	城市大规模开采地下,
8647	White House and EPA warn of hackers breaching water systems	https://buaq.net/go-229109.html	buaq	newscopy;	0	2024-03-20	白宫和环保局警告黑客破坏供水系统
8465	Misconfigured Firebase instances leaked 19 million plaintext passwords	https://www.bleepingcomputer.com/news/security/misconfigured-firebase-instances-leaked-19-million-plaintext-passwords/	bleepingcomputer	news;Security;	1	2024-03-19	错误配置的Firebase 事件泄漏了1 900万简文本密码
9915	US penalizes Russian fintech firms that helped others evade sanctions	https://therecord.media/us-sanctions-russian-fintech-firms-evasions-cryptocurrency	therecord	ransom;Cybercrime;Government;News;News Briefs;	3	2024-03-25	美国惩罚俄罗斯的烟工公司,它们帮助他人逃避制裁。
8559	Appdome launches Social Engineering Prevention service to safeguard mobile users	https://www.helpnetsecurity.com/2024/03/19/appdome-social-engineering-prevention/	helpnetsecurity	news;Industry news;Appdome;	1	2024-03-19	保护移动用户的社会工程预防服务
8664	Generative AI Security - Secure Your Business in a World Powered by LLMs	https://thehackernews.com/2024/03/generative-ai-security-secure-your.html	feedburner	news;	1	2024-03-20	A. 产生AI 安全 -- -- 在由LLM女士统治的世界中确保业务安全
8613	EPA looking to create water sector cyber task force to reduce risks from Iran, China	https://therecord.media/epa-water-sector-cyber-task-force-china-iran	therecord	ransom;Government;Industry;News;	6	2024-03-19	EPA 寻求建立水部门网络工作队,以减少伊朗、中国的风险
8634	900+ websites Exposing 10M+ Passwords: Most in Plaintext	https://gbhackers.com/websites-exposing-10m-passwords/	GBHacker	news;Cyber Crime;cyber security;Cyber Security News;Cyber Attack;	1	2024-03-19	900+网站 揭露10M+密码:大多数为普通文本
8614	‘Lifelock’ hacker pleads guilty to extorting medical clinics	https://therecord.media/lifelock-hacker-pleads-guilty-to-attacks-on-medical-clinics	therecord	ransom;Cybercrime;News;News Briefs;	1	2024-03-19	“Lifellock”黑客承认勒索医疗诊所是有罪的。
8673	Ukraine Arrests Trio for Hijacking Over 100 Million Email and Instagram Accounts	https://thehackernews.com/2024/03/ukraine-arrests-trio-for-hijacking-over.html	feedburner	news;	1	2024-03-20	乌克兰因劫持1亿多封电子邮件和Instagram账户而逮捕三驾马车
8672	TeamCity Flaw Leads to Surge in Ransomware, Cryptomining, and RAT Attacks	https://thehackernews.com/2024/03/teamcity-flaw-leads-to-surge-in.html	feedburner	news;	2	2024-03-20	团队Flaw 导致Ransomware、加密和RAT袭击的暴增
8674	U.S. EPA Forms Task Force to Protect Water Systems from Cyberattacks	https://thehackernews.com/2024/03/us-epa-forms-task-force-to-protect.html	feedburner	news;	1	2024-03-20	美国环保署保护水系统免受网络攻击形式工作队
8676	JA 指纹识别全系讲解	https://paper.seebug.org/3132/	seebug	news;经验心得;	1	2024-03-20	JA 指纹识别全系讲解
9905	Debian Security Advisory 5645-1	https://packetstormsecurity.com/files/177747/dsa-5645-1.txt	packetstorm	vuln;;	1	2024-03-25	Debian安全咨询 5645-1
9906	Debian Security Advisory 5646-1	https://packetstormsecurity.com/files/177748/dsa-5646-1.txt	packetstorm	vuln;;	1	2024-03-25	Debian安全咨询 5646-1
9907	Debian Security Advisory 5647-1	https://packetstormsecurity.com/files/177749/dsa-5647-1.txt	packetstorm	vuln;;	1	2024-03-25	Debian安全咨询 5647-1
8683	New Sysrv Botnet Variant Makes Use of Google Subdomain to Spread XMRig Miner	https://securityboulevard.com/2024/03/new-sysrv-botnet-variant-makes-use-of-google-subdomain-to-spread-xmrig-miner/	securityboulevard	news;Security Bloggers Network;google;imperva;Imperva Threat Research;Threat Research;	1	2024-03-20	新Sysrv Botnet 变异工具利用 Google 子域传播 XMRIG 矿工
8530	Hallesche-Kraftverkehrs--Speditions-GmbH	http://www.ransomfeed.it/index.php?page=post_details&id_post=13786	ransomfeed	ransom;hunters;	1	2024-03-19	Hallesche- Kraftverkehrs- Speditions- GmbH - 哈列舍- 克拉夫特维尔克尔斯- 斯佩迪特- 格林布
8538	Mayer-Antonellis-Jachowicz--Haranas-LLP	http://www.ransomfeed.it/index.php?page=post_details&id_post=13835	ransomfeed	ransom;bianlian;	1	2024-03-19	Mayer-Antonellis-Jachowicz-哈拉纳斯-LLP
8547	红队实战小课，大考前充电｜实战攻防思路之企业纵深防御体系突破	https://www.freebuf.com/consult/395296.html	freebuf	news;咨询;	1	2024-03-19	红队实战小课，大考前充电｜实战攻防思路之企业纵深防御体系突破
8560	CalypsoAI Platform provides real-time LLM cybersecurity insights	https://www.helpnetsecurity.com/2024/03/19/calypsoai-platform-provides-real-time-llm-cybersecurity-insights/	helpnetsecurity	news;Industry news;CalypsoAI;	1	2024-03-19	CalypsoAI 平台提供实时LLM网络安全洞见
8556	FreeBuf早报 | 英国87%的组织易受网络攻击；法国政府泄露4300万公民个人数据	https://www.freebuf.com/news/395244.html	freebuf	news;资讯;	1	2024-03-19	FreeBuf早报 | 英国87%的组织易受网络攻击；法国政府泄露4300万公民个人数据
8596	Red Hat Security Advisory 2024-1317-03	https://packetstormsecurity.com/files/177648/RHSA-2024-1317-03.txt	packetstorm	vuln;;	1	2024-03-19	2024-1317-03红色帽子安保咨询
8603	Red Hat Security Advisory 2024-1367-03	https://packetstormsecurity.com/files/177655/RHSA-2024-1367-03.txt	packetstorm	vuln;;	1	2024-03-19	2024-1367-03红色帽子安保咨询
8612	OpenSCAP Libraries 1.3.10	https://packetstormsecurity.com/files/177665/openscap-1.3.10.tar.gz	packetstorm	vuln;;	1	2024-03-19	OpenSCAP 图书馆 1.3.10
8713	India's Android Users Hit by Malware-as-a-Service Campaign	https://www.darkreading.com/cyberattacks-data-breaches/hackers-target-android-users-in-india-through-maas-campaign	darkreading	news;	2	2024-03-20	印度的机器人用户被Malware-as-A-Service运动击中
8695	Ivanti fixes critical Standalone Sentry bug reported by NATO	https://www.bleepingcomputer.com/news/security/ivanti-fixes-critical-standalone-sentry-bug-reported-by-nato/	bleepingcomputer	news;Security;	1	2024-03-20	Ivanti修复北约报告的关键独立哨兵虫
8704	Detecting Cloud Threats With CloudGrappler	https://www.darkreading.com/cloud-security/detecting-cloud-threats-with-cloudgrappler	darkreading	news;	1	2024-03-19	用云杯探测云层威胁
8646	American Renal Associates, nearly 20,000 patients are affected by the data breach	https://buaq.net/go-229108.html	buaq	newscopy;	0	2024-03-20	美国Renal American Renal Associates, 近20,000名病人 受到数据泄漏的影响
8681	Linux Supply Chain Validation Cheat Sheet	https://securityboulevard.com/2024/03/linux-supply-chain-validation-cheat-sheet/	securityboulevard	news;Security Bloggers Network;Blog;	1	2024-03-20	Linux 供应链验证热纸
8693	GitHub’s new AI-powered tool auto-fixes vulnerabilities in your code	https://www.bleepingcomputer.com/news/security/githubs-new-ai-powered-tool-auto-fixes-vulnerabilities-in-your-code/	bleepingcomputer	news;Security;Software;	1	2024-03-20	GitHub 新的 AI 动力工具自动修正代码中的脆弱性
8701	UK bakery Greggs is latest victim of recent POS system outages	https://www.bleepingcomputer.com/news/technology/uk-bakery-greggs-is-latest-victim-of-recent-pos-system-outages/	bleepingcomputer	news;Technology;Business;	1	2024-03-20	联合王国面包店Greggs是最近POS系统故障的最新受害者
8702	Akamai Research Finds 29% of Web Attacks Target APIs	https://www.darkreading.com/application-security/akamai-research-finds-29-of-web-attacks-target-apis	darkreading	news;	1	2024-03-20	Akamai研究发现29%的网络攻击目标API
9917	Radamsa - A General-Purpose Fuzzer	http://www.kitploit.com/2024/03/radamsa-general-purpose-fuzzer.html	kitploit	tool;Protocols;Radamsa;Troubleshooting;Windows;Wireshark;	1	2024-03-25	Radamsa - 通用模糊器
9920	Atlassian Confluence路径遍历漏洞(CVE-2024-21677)通告	https://blog.nsfocus.net/atlassian-confluencecve-2024-21677/	绿盟	news;威胁通告;安全漏洞;漏洞防护;	5	2024-03-25	Atlassian Confluence路径遍历漏洞(CVE-2024-21677)通告
8697	New ‘Loop DoS’ attack may impact up to 300,000 online systems	https://www.bleepingcomputer.com/news/security/new-loop-dos-attack-may-impact-up-to-300-000-online-systems/	bleepingcomputer	news;Security;	1	2024-03-20	新的“Looop doS”攻击可能撞击多达300 000个在线系统
8698	Spa Grand Prix email account hacked to phish banking info from fans	https://www.bleepingcomputer.com/news/security/spa-grand-prix-email-account-hacked-to-phish-banking-info-from-fans/	bleepingcomputer	news;Security;	1	2024-03-20	Spa Grand Prix 电子邮件账户黑入粉丝的菲什银行信息
9922	绿盟科技威胁周报（2024.03.18-2024.03.24）	https://blog.nsfocus.net/weeklyreport202412/	绿盟	news;威胁通告;周报;威胁防护;	1	2024-03-25	绿盟科技威胁周报（2024.03.18-2024.03.24）
9923	170K+ Python Developers GitHub Accounts Hacked in Supply Chain Attack	https://gbhackers.com/170k-user-accounts-hacked/	GBHacker	news;cyber security;Cyber Security News;Python;Cyber Attack;	1	2024-03-25	170K+ Python 开发者
8667	New BunnyLoader Malware Variant Surfaces with Modular Attack Features	https://thehackernews.com/2024/03/new-bunnyloader-malware-variant.html	feedburner	news;	1	2024-03-20	带有模块攻击特性的新兔子拖放器 Malware 变异表面
8619	GAP-Burp-Extension - Burp Extension To Find Potential Endpoints, Parameters, And Generate A Custom Target Wordlist	http://www.kitploit.com/2024/03/gap-burp-extension-burp-extension-to.html	kitploit	tool;GAP-Burp-Extension;Performance;Python;Wordlist;	1	2024-03-19	GAP-brp-Extention - 寻找潜在终点、参数和生成自定义目标单词列表的包包扩展
9908	Ubuntu Security Notice USN-6710-1	https://packetstormsecurity.com/files/177750/USN-6710-1.txt	packetstorm	vuln;;	1	2024-03-25	Ubuntu Ubuntu 安全通知 USN-6710-1
9909	Ubuntu Security Notice USN-6712-1	https://packetstormsecurity.com/files/177751/USN-6712-1.txt	packetstorm	vuln;;	1	2024-03-25	Ubuntu Ubuntu 安全通知 USN-6712-1
9910	Ubuntu Security Notice USN-6713-1	https://packetstormsecurity.com/files/177752/USN-6713-1.txt	packetstorm	vuln;;	1	2024-03-25	Ubuntu Ubuntu 安全通知 USN-6713-1
9911	‘Far-reaching’ hack stole information from Python developers	https://therecord.media/far-reaching-hack-stole-information-from-python-developers	therecord	ransom;Cybercrime;Malware;News;News Briefs;	1	2024-03-25	盗用Python开发商的信息。
9912	Senator demands answers from HHS about $7.5 million cyber theft in 2023	https://therecord.media/hhs-reported-grant-payment-scam-sen-bill-cassidy-letter	therecord	ransom;Government;Cybercrime;News;	1	2024-03-25	参议员要求HHHS回答2023年大约750万美元的网络盗窃案
9913	St. Cloud most recent in string of Florida cities hit with ransomware	https://therecord.media/st-cloud-hit-with-ransomware-florida-string	therecord	ransom;News;Government;Cybercrime;	2	2024-03-25	佛罗里达连连串城市中最新的圣克劳德市
10142	10 Rookie Product Design Mistakes (And How to Sidestep Them)	https://buaq.net/go-230693.html	buaq	newscopy;	0	2024-03-27	10 Rookie 产品设计错误(和如何绕过这些错误)
8689	New Windows Server updates cause domain controller crashes, reboots	https://www.bleepingcomputer.com/news/microsoft/new-windows-server-updates-cause-domain-controller-crashes-reboots/	bleepingcomputer	news;Microsoft;	1	2024-03-20	新 Windows 服务器更新导致域控制器崩溃, 重新启动
8710	Don't Answer the Phone: Inside a Real-Life Vishing Attack	https://www.darkreading.com/cyberattacks-data-breaches/dont-answer-phone-inside-real-life-vishing-attack	darkreading	news;	1	2024-03-20	不要接电话:在现实生活中的 钓鱼攻击中
8684	Pwned by the Mail Carrier	https://securityboulevard.com/2024/03/pwned-by-the-mail-carrier/	securityboulevard	news;Security Bloggers Network;Active Directory;BloodHound;Microsoft Exchange;research;security-boundaries;	1	2024-03-20	被邮递员勾引
8709	Pathlock Introduces Continuous Controls Monitoring to Reduce Time and Costs	https://www.darkreading.com/cyber-risk/pathlock-introduces-continuous-controls-monitoring-to-reduce-time-and-costs	darkreading	news;	1	2024-03-20	" 路径锁定 " 引入持续控制监测,以缩短时间和成本
8793	网络威胁攻击者”盯上了“API	https://www.freebuf.com/news/395332.html	freebuf	news;资讯;	1	2024-03-20	网络威胁攻击者”盯上了“API
8794	敲击键盘也可能泄露敏感信息？	https://www.freebuf.com/news/395358.html	freebuf	news;资讯;	1	2024-03-20	敲击键盘也可能泄露敏感信息？
8805	Semgrep Assistant boosts AppSec team productivity using AI	https://www.helpnetsecurity.com/2024/03/20/semgrep-assistant/	helpnetsecurity	news;Industry news;Semgrep;	1	2024-03-20	Semgrep Semgrep助理利用AI提高AppSec团队生产率
8796	革新行业的“杀手级”产品，360安全大模型3.0发布	https://www.freebuf.com/news/395436.html	freebuf	news;资讯;	1	2024-03-20	革新行业的“杀手级”产品，360安全大模型3.0发布
8798	Apiiro and Secure Code Warrior join forces for developer training integration	https://www.helpnetsecurity.com/2024/03/20/apiiro-secure-code-warrior-developer-training/	helpnetsecurity	news;Industry news;Apiiro;Secure Code Warrior;	1	2024-03-20	Apiiro和安全守则
8677	Android malware, Android malware and more Android malware	https://securelist.com/crimeware-report-android-malware/112121/	securelist	news;Malware reports;Google Android;Malware;RAT Trojan;Spyware;Trojan;Mobile threats;	2	2024-03-20	还有机器人的恶意软件 机器人的恶意软件 还有更多的机器人的恶意软件
8801	CyberSaint raises $21 million to accelerate market expansion	https://www.helpnetsecurity.com/2024/03/20/cybersaint-funding-21-million/	helpnetsecurity	news;Industry news;CyberSaint;	1	2024-03-20	网络圣卢西亚筹集2 100万美元,以加速市场扩张
8691	Flipper Zero makers respond to Canada’s ‘harmful’ ban proposal	https://www.bleepingcomputer.com/news/security/flipper-zero-makers-respond-to-canadas-harmful-ban-proposal/	bleepingcomputer	news;Security;Hardware;	1	2024-03-20	Flipper Zero 制造商响应加拿大的 " 有害 " 禁令提案
8803	Portnox Conditional Access for Applications improves data security for organizations	https://www.helpnetsecurity.com/2024/03/20/portnox-conditional-access-for-applications/	helpnetsecurity	news;Industry news;Portnox;	1	2024-03-20	Portnox 有条件的应用程序访问提高了组织的数据安全性
10138	Windows 11 KB5035942 update enables Moment 5 features for everyone	https://buaq.net/go-230689.html	buaq	newscopy;	0	2024-03-27	Windows 11 KB5035942 更新 Windows 11 KB5035942 启用每个人的5分钟功能
10139	Facebook snooped on users’ Snapchat traffic in secret project, documents reveal	https://buaq.net/go-230690.html	buaq	newscopy;	0	2024-03-27	Facebook浏览用户的Snapcatch通讯秘密项目,
8725	Federal Warning Highlights Cyber Vulnerability of US Water Systems	https://www.darkreading.com/ics-ot-security/new-us-warning-highlights-vulnerability-of-us-water-systems-to-cyberattacks	darkreading	news;	1	2024-03-20	联邦警报突出显示美国供水系统的网络脆弱性
10143	Taking the Azure Open AI Challenge - Day 1	https://buaq.net/go-230694.html	buaq	newscopy;	0	2024-03-27	接受Azure 公开AI挑战 - 第1天
10144	AI In Web3 User Acquisition: Exploring Bonus Block And DIA	https://buaq.net/go-230695.html	buaq	newscopy;	0	2024-03-27	AI 在Web3 用户获取:探索Bonus区块和DIA
10145	Are We Ignoring the Cybersecurity Risks of Undersea Internet Cables?	https://buaq.net/go-230696.html	buaq	newscopy;	0	2024-03-27	我们是否忽视海底互联网电缆的网络安全风险?
8728	'Fluffy Wolf' Spreads Meta Stealer in Corporate Phishing Campaign	https://www.darkreading.com/threat-intelligence/fluffy-wolf-spreads-meta-stealer-in-corporate-phishing-campaign	darkreading	news;	1	2024-03-20	“Fluffy Wolf”在公司钓鱼运动中传播的假冒偷窃者
9925	Hackers Claiming Unauthorized Access to the Fortinet Devices of Many Companies	https://gbhackers.com/hackers-claiming-unauthorized-access/	GBHacker	news;cyber security;Cyber Security News;	1	2024-03-25	声称未经许可进入许多公司Fortnet装置的黑客
8731	Tax Hackers Blitz Small Business With Phishing Emails	https://www.darkreading.com/threat-intelligence/tax-cons-targeting-small-business-with-phishing-emails	darkreading	news;	1	2024-03-20	税务黑客黑客闪电小商业及幻灯邮件
8738	[Heads Up] Reinforce Your Defenses Against Rising Supply-Chain Cyber Threats	https://blog.knowbe4.com/heads-up-reinforce-your-defenses-against-rising-supply-chain-cyber-threats	knowbe4	news;Social Engineering;Ransomware;	1	2024-03-20	强化防御力量 防止供应增加 查因网络威胁
8768	South-Star-Electronics	http://www.ransomfeed.it/index.php?page=post_details&id_post=13839	ransomfeed	ransom;trigona;	1	2024-03-20	南南星电子
8769	Filexis-AG-Treuhand-und-Immobilien	http://www.ransomfeed.it/index.php?page=post_details&id_post=13841	ransomfeed	ransom;8base;	1	2024-03-20	Filexis- AG- Treuhand- und- Immobilien 档案文件( AG- Treuhand- und- Immobilien )
8770	Springfield-Sign	http://www.ransomfeed.it/index.php?page=post_details&id_post=13842	ransomfeed	ransom;8base;	1	2024-03-20	斯普林菲尔德签署
8771	STENSSONS-LIVS-AB	http://www.ransomfeed.it/index.php?page=post_details&id_post=13843	ransomfeed	ransom;8base;	1	2024-03-20	小学学生 -- -- 小学
8773	Kolbe-Striping	http://www.ransomfeed.it/index.php?page=post_details&id_post=13845	ransomfeed	ransom;rhysida;	1	2024-03-20	Kolbe- 粉刷
8774	oceaneeringcom	http://www.ransomfeed.it/index.php?page=post_details&id_post=13846	ransomfeed	ransom;blackbasta;	1	2024-03-20	海洋海洋
8775	logistasolutionscom	http://www.ransomfeed.it/index.php?page=post_details&id_post=13847	ransomfeed	ransom;blackbasta;	1	2024-03-20	logista Solutionscom log 逻辑解算器
8776	igf-inccom	http://www.ransomfeed.it/index.php?page=post_details&id_post=13848	ransomfeed	ransom;blackbasta;	1	2024-03-20	igf- inccom 数字
8779	因系统故障，这家银行的ATM可以“无限”取钱	https://www.freebuf.com/articles/395363.html	freebuf	news;	1	2024-03-20	因系统故障，这家银行的ATM可以“无限”取钱
8791	从深度伪造到恶意软件：网络安全迎来AI新挑战	https://www.freebuf.com/news/395324.html	freebuf	news;资讯;	2	2024-03-20	从深度伪造到恶意软件：网络安全迎来AI新挑战
8792	涉及1亿被盗账户，乌克兰警方逮捕3名黑客	https://www.freebuf.com/news/395328.html	freebuf	news;资讯;	1	2024-03-20	涉及1亿被盗账户，乌克兰警方逮捕3名黑客
9051	politiaromanaro	http://www.ransomfeed.it/index.php?page=post_details&id_post=13893	ransomfeed	ransom;killsec;	1	2024-03-21	政治政治
8823	CSZCMS v1.3.0 SQL Injection (Authenticated)	https://cxsecurity.com/issue/WLB-2024030041	cxsecurity	vuln;	1	2024-03-20	CSZCMS v1.3.0 SQL 注射(核准)
8850	Red Hat Security Advisory 2024-1437-03	https://packetstormsecurity.com/files/177705/RHSA-2024-1437-03.txt	packetstorm	vuln;;	1	2024-03-20	红色帽子安保咨询 2024-1437-03
8851	GNU Transport Layer Security Library 3.8.4	https://packetstormsecurity.com/files/177706/gnutls-3.8.4.tar.xz	packetstorm	vuln;;	1	2024-03-20	GNU 运输层安全图书馆 3.8.4
8860	International freight tech firm isolates Canada operations after cyberattack	https://therecord.media/radiant-logistics-cyberattack-canada-operations	therecord	ransom;Cybercrime;Industry;News;News Briefs;	1	2024-03-20	国际货运技术公司在网络攻击后孤立加拿大的业务
8814	Microsoft Outlook Remote Code Execution Vulnerability - CVE-2024-21413	https://www.nu11secur1ty.com/2024/03/microsoft-outlook-remote-code-execution.html	nu11security	vuln;	3	2024-03-20	微软 Outlook 远程代码执行脆弱性 -- -- CVE-2024-21413
8799	ControlUp Secure DX reduces endpoint management complexity	https://www.helpnetsecurity.com/2024/03/20/controlup-secure-dx/	helpnetsecurity	news;Industry news;ControlUp;	1	2024-03-20	降低端点管理复杂性
8816	Some of the Most Popular Websites Share Your Data With Over 1,500 Companies	https://www.wired.com/story/cookie-pop-up-ad-tech-partner-top-websites/	wired	news;Security;Security / Privacy;	1	2024-03-20	与1 500多家公司共享数据的一些最受欢迎的网站
16382	Commerce-Dental-Group	http://www.ransomfeed.it/index.php?page=post_details&id_post=14121	ransomfeed	ransom;ciphbit;	1	2024-04-05	商业集团
8826	ZoneMinder Snapshots Remote Code Execution	https://cxsecurity.com/issue/WLB-2024030044	cxsecurity	vuln;	1	2024-03-20	ZoneMinder 区抓图远程代码执行
16383	Agencia-Host-	http://www.ransomfeed.it/index.php?page=post_details&id_post=14123	ransomfeed	ransom;ransomhub;	1	2024-04-05	主管... 主管...
8682	Misconfigurations in Google Firebase lead to over 19.8 million leaked secrets	https://securityboulevard.com/2024/03/misconfigurations-in-google-firebase-lead-to-over-19-8-million-leaked-secrets/	securityboulevard	news;Security Bloggers Network;Breach explained;	1	2024-03-20	Google Firebase的错误配置导致1 980多万个泄露秘密
8828	Atlassian Confluence 8.5.3 Remote Code Execution	https://cxsecurity.com/issue/WLB-2024030046	cxsecurity	vuln;	1	2024-03-20	8.5.3 远程代码执行
8830	Backdoor.Win32.Emegrab.b / Remote Stack Buffer Overflow (SEH)	https://cxsecurity.com/issue/WLB-2024030049	cxsecurity	vuln;	1	2024-03-20	Win32.Emegrab.b/遥控斯塔克缓冲溢流(SEH)
8829	Backdrop CMS 1.23.0 Cross Site Scripting	https://cxsecurity.com/issue/WLB-2024030047	cxsecurity	vuln;	1	2024-03-20	返回 CMS 1.23.0 跨站点脚本
18815	Notepad++ wants your help in 'parasite website' shutdown	https://www.bleepingcomputer.com/news/security/notepad-plus-plus-wants-your-help-in-parasite-website-shutdown/	bleepingcomputer	news;Security;	1	2024-04-08	Notpad+++ 想要您在“ 平行网站” 关闭时帮助您 。
8831	SARMANSOFT SQL - NO-REDİRECT PoC	https://cxsecurity.com/issue/WLB-2024030050	cxsecurity	vuln;	1	2024-03-20	沙特SQL -- -- 无REDRECT Poc
8834	Red Hat Security Advisory 2024-1411-03	https://packetstormsecurity.com/files/177689/RHSA-2024-1411-03.txt	packetstorm	vuln;;	1	2024-03-20	红色帽子安保咨询 2024-1411-03
8838	Red Hat Security Advisory 2024-1423-03	https://packetstormsecurity.com/files/177693/RHSA-2024-1423-03.txt	packetstorm	vuln;;	1	2024-03-20	红帽子安保咨询 2024-1423-03
8832	Red Hat Security Advisory 2024-1408-03	https://packetstormsecurity.com/files/177687/RHSA-2024-1408-03.txt	packetstorm	vuln;;	1	2024-03-20	红色帽子安保咨询 2024-1408-03
8833	Red Hat Security Advisory 2024-1409-03	https://packetstormsecurity.com/files/177688/RHSA-2024-1409-03.txt	packetstorm	vuln;;	1	2024-03-20	红色帽子安保咨询 2024-1409-03
8841	Red Hat Security Advisory 2024-1426-03	https://packetstormsecurity.com/files/177696/RHSA-2024-1426-03.txt	packetstorm	vuln;;	1	2024-03-20	红帽子安保咨询 2024-1426-03
8835	Red Hat Security Advisory 2024-1412-03	https://packetstormsecurity.com/files/177690/RHSA-2024-1412-03.txt	packetstorm	vuln;;	1	2024-03-20	红色帽子安保咨询 2024-1412-03
8836	Red Hat Security Advisory 2024-1417-03	https://packetstormsecurity.com/files/177691/RHSA-2024-1417-03.txt	packetstorm	vuln;;	1	2024-03-20	红色帽子安保咨询 2024-1417-03
8844	Red Hat Security Advisory 2024-1429-03	https://packetstormsecurity.com/files/177699/RHSA-2024-1429-03.txt	packetstorm	vuln;;	1	2024-03-20	红色帽子安保咨询 2024-1429-03
8840	Red Hat Security Advisory 2024-1425-03	https://packetstormsecurity.com/files/177695/RHSA-2024-1425-03.txt	packetstorm	vuln;;	1	2024-03-20	红帽子安保咨询 2024-1425-03
8852	Ubuntu Security Notice USN-6702-1	https://packetstormsecurity.com/files/177707/USN-6702-1.txt	packetstorm	vuln;;	1	2024-03-20	Ubuntu Ubuntu 安全通知 USN-6702-1
8848	Red Hat Security Advisory 2024-1435-03	https://packetstormsecurity.com/files/177703/RHSA-2024-1435-03.txt	packetstorm	vuln;;	1	2024-03-20	红色帽子安保咨询 2024-1435-03
8842	Red Hat Security Advisory 2024-1427-03	https://packetstormsecurity.com/files/177697/RHSA-2024-1427-03.txt	packetstorm	vuln;;	1	2024-03-20	红色帽子安保咨询 2024-1427-03
8843	Red Hat Security Advisory 2024-1428-03	https://packetstormsecurity.com/files/177698/RHSA-2024-1428-03.txt	packetstorm	vuln;;	1	2024-03-20	红帽子安保咨询 2024-1428-03
9052	rabitbdcom	http://www.ransomfeed.it/index.php?page=post_details&id_post=13894	ransomfeed	ransom;killsec;	1	2024-03-21	拉比卜德康
8845	Red Hat Security Advisory 2024-1431-03	https://packetstormsecurity.com/files/177700/RHSA-2024-1431-03.txt	packetstorm	vuln;;	1	2024-03-20	红色帽子安保咨询 2024-1431-03
8847	Red Hat Security Advisory 2024-1434-03	https://packetstormsecurity.com/files/177702/RHSA-2024-1434-03.txt	packetstorm	vuln;;	1	2024-03-20	红色帽子安保咨询 2024-1434-03
8825	Lektor 3.3.10 Arbitrary File upload	https://cxsecurity.com/issue/WLB-2024030043	cxsecurity	vuln;	1	2024-03-20	Lektor 3.3.10 任意文件上传
8849	Red Hat Security Advisory 2024-1436-03	https://packetstormsecurity.com/files/177704/RHSA-2024-1436-03.txt	packetstorm	vuln;;	1	2024-03-20	红色帽子安保咨询 2024-1436-03
9175	SBF lengthy Jail Time to Serve as Financial Crime Deterrent	https://buaq.net/go-229787.html	buaq	newscopy;	0	2024-03-22	SBF SBF 长时间的监狱服刑时间,以起到金融犯罪威慑作用
8893	252 - Bypassing KASLR and a FortiGate RCE	https://buaq.net/go-229501.html	buaq	newscopy;	0	2024-03-21	252 - 绕过KASLR和堡垒RCE
8874	Hackers Attacking Critical US Water Systems, White House Warns	https://gbhackers.com/hackers-attacking-us-water-systems/	GBHacker	news;Cyber Attack;Cyber Security News;	1	2024-03-20	黑客攻击美国关键水系统,白宫警告
19913	Google Rolls Out “Find My Device” Network for Android Users	https://gbhackers.com/google-find-my-device-network/	GBHacker	news;Android;cyber security;Cyber Security News;	2	2024-04-09	Google为Android用户推出“找到我的设备”网络
8896	微软推出Windows 11 开发版/金丝雀 Build 26085版 修复鼠标消失/蓝屏等问题	https://buaq.net/go-229505.html	buaq	newscopy;	0	2024-03-21	微软推出Windows 11 开发版/金丝雀 Build 26085版 修复鼠标消失/蓝屏等问题
22388	Beware: GitHub's Fake Popularity Scam Tricking Developers into Downloading Malware	https://thehackernews.com/2024/04/beware-githubs-fake-popularity-scam.html	feedburner	news;	1	2024-04-10	当心: GitHub 假冒的流行片将开发者骗入下载 Maware
8881	Two Russians sanctioned by US for alleged disinformation campaign	https://buaq.net/go-229464.html	buaq	newscopy;	0	2024-03-21	两名俄罗斯人被美国制裁 罪名是进行假情报活动
8889	Crypto Taxes: Ignorance Is Never Bliss!	https://buaq.net/go-229484.html	buaq	newscopy;	0	2024-03-21	无知永远不会是丑闻!
303	The Mysterious Case of the Missing Trump Trial Ransomware Leak	https://www.wired.com/story/lockbit-fulton-county-georgia-trump-ransomware-leak/	wired	news;Security;Security / Cyberattacks and Hacks;Security / Security News;Politics / Global Elections;Politics / Politics News;	2	2024-02-29	失踪特朗普审判案的神秘案件
21967	Complete Guide to ISA/IEC 62443-3-2: Risk Assessments for Industrial Automation and Control Systems	https://securityboulevard.com/2024/04/complete-guide-to-isa-iec-62443-3-2-risk-assessments-for-industrial-automation-and-control-systems/	securityboulevard	news;Governance, Risk & Compliance;Security Bloggers Network;Compliance;FEATURED;OT;	1	2024-04-10	ISA/IEC 62443-3-2完整指南:工业自动化和控制系统的风险评估
8887	Personalized Soups: LLM Alignment Via Parameter Merging - Conclusion & References	https://buaq.net/go-229482.html	buaq	newscopy;	0	2024-03-21	个性化投影: LLM 对齐Via参数合并 - 结论和参考
8858	Hackers claim to have breached Israeli nuclear facility’s computer network	https://therecord.media/hackers-claim-attack-on-israeli-nuclear-research-facility	therecord	ransom;Cybercrime;Government;News;Technology;	1	2024-03-20	Hackers声称违反了以色列核设施的计算机网络
25927	华为盘古大模型首次应用于笔记本 	https://s.weibo.com/weibo?q=%23华为盘古大模型首次应用于笔记本 %23	sina.weibo	hotsearch;weibo	1	2024-04-10	华为盘古大模型首次应用于笔记本
9928	Linux Admins Beware! Fake PuTTY Client that Installs Rhadamanthys stealer	https://gbhackers.com/linux-admins-beware/	GBHacker	news;Cyber Security News;Linux;Linux malware;Malware;	1	2024-03-25	安装Rhadamanthys 偷盗者的假 PUTTY 客户端
22381	22 ‘hunt forward’ missions deployed overseas in 2023, Cyber Command leader says	https://therecord.media/cyber-command-hunt-forward-missions-2023-haugh-senate	therecord	ransom;Government;Elections;Nation-state;News;	1	2024-04-10	2023年在海外部署的22个`追捕前方 ' 任务,
8871	Androxgh0st Exploits SMTP Services To Extract Critical Data	https://gbhackers.com/androxgh0st-smtp-exploits-critical-data/	GBHacker	news;Cyber Security News;Email Security;Malware;computer security;SMTP Exploitation;	1	2024-03-20	解析关键数据的 SMTP 服务
8884	La minaccia informatica di AndroxGh0st: una sfida per la sicurezza digitale	https://buaq.net/go-229476.html	buaq	newscopy;	0	2024-03-21	信息学信息学和AndroxGh0st: 数字数字: 千千兆瓦
25928	华为门店回应P70先锋计划 	https://s.weibo.com/weibo?q=%23华为门店回应P70先锋计划 %23	sina.weibo	hotsearch;weibo	1	2024-04-09	华为门店回应P70先锋计划
25929	华为首款柔性OLED笔记本发布 	https://s.weibo.com/weibo?q=%23华为首款柔性OLED笔记本发布 %23	sina.weibo	hotsearch;weibo	1	2024-04-11	华为首款柔性OLED笔记本发布
8878	WordPress Plugin Flaw Exposes 40,000+ Websites to Cyber Attack	https://gbhackers.com/wordpress-plugin-flaw-2/	GBHacker	news;Cyber Attack;Cyber Security News;	1	2024-03-20	WordPress Plugin Flaw 展览40 000+网络攻击网站
25933	小米SU7后视镜雨天可开启加热功能 	https://s.weibo.com/weibo?q=%23小米SU7后视镜雨天可开启加热功能 %23	sina.weibo	hotsearch;weibo	1	2024-04-09	小米SU7后视镜雨天可开启加热功能
25930	字节2023年利润涨约60% 	https://s.weibo.com/weibo?q=%23字节2023年利润涨约60% %23	sina.weibo	hotsearch;weibo	1	2024-04-10	字节2023年利润涨约60%
25931	官方将处理无资质小米SU7跑网约车平台 	https://s.weibo.com/weibo?q=%23官方将处理无资质小米SU7跑网约车平台 %23	sina.weibo	hotsearch;weibo	1	2024-04-12	官方将处理无资质小米SU7跑网约车平台
8877	Tor Unveils WebTunnel – Let Users Bypass Censorship	https://gbhackers.com/tor-unveils-webtunnel/	GBHacker	news;cyber security;Cyber Security News;	1	2024-03-20	Torveils Unveils WebTunnel - 让用户绕过检查
25932	小米SU7Pro版不能加尾翼调节实体键 	https://s.weibo.com/weibo?q=%23小米SU7Pro版不能加尾翼调节实体键 %23	sina.weibo	hotsearch;weibo	1	2024-04-10	小米SU7Pro版不能加尾翼调节实体键
25934	小米SU7断电后冰箱最长工作24小时 	https://s.weibo.com/weibo?q=%23小米SU7断电后冰箱最长工作24小时 %23	sina.weibo	hotsearch;weibo	1	2024-04-12	小米SU7断电后冰箱最长工作24小时
25935	小米SU7跑滴滴 	https://s.weibo.com/weibo?q=%23小米SU7跑滴滴 %23	sina.weibo	hotsearch;weibo	1	2024-04-11	小米SU7跑滴滴
20753	LG Smart TVs at Risk of Attacks, Thanks to 4 OS Vulnerabilities	https://www.darkreading.com/vulnerabilities-threats/researchers-discover-thousands-of-lg-smart-tvs-at-risk-of-attacks	darkreading	news;	1	2024-04-09	LG 面临袭击风险的智能电视,由于4个OS脆弱性
23623	100 预算，你会怎么开展网络安全？	https://www.freebuf.com/news/397622.html	freebuf	news;资讯;	1	2024-04-11	100 预算，你会怎么开展网络安全？
24159	Backdoor in XZ Utils That Almost Happened	https://securityboulevard.com/2024/04/backdoor-in-xz-utils-that-almost-happened/	securityboulevard	news;Application Security;DevOps;Malware;Security Bloggers Network;Social Engineering;backdoors;Cybersecurity;economics of security;Hacking;Linux;open source;social engineering;SSH;Uncategorized;	1	2024-04-11	XZ 几乎发生时的后门工具
22828	Spectre漏洞 v2 版本再现，影响英特尔 CPU + Linux 组合设备	https://www.freebuf.com/news/397580.html	freebuf	news;资讯;	3	2024-04-11	Spectre漏洞 v2 版本再现，影响英特尔 CPU + Linux 组合设备
22829	黑客疑似利用AI生成的恶意代码攻击德国企业	https://www.freebuf.com/news/397597.html	freebuf	news;资讯;	1	2024-04-11	黑客疑似利用AI生成的恶意代码攻击德国企业
3707	7 Tips to Protect Your Smartphone from Getting Hacked	https://www.mcafee.com/blogs/mobile-security/7-tips-to-protect-your-smartphone-from-getting-hacked/	mcafee	news;Tips & Tricks;Mobile Security;mobile security;smart phone security;smartphone security;smartphone vulnerabilities;	1	2024-03-14	7 保护您的智能手机不被黑入的提示
24214	APKDeepLens - Android Security Insights In Full Spectrum	http://www.kitploit.com/2024/04/apkdeeplens-android-security-insights.html	kitploit	tool;Android Security;APKDeepLens;Mobile Security;vulnerabilities;Windows;	2	2024-04-11	APKDIepLens - 完整光谱中机器人安全透视
22838	Graylog: Open-source log management	https://www.helpnetsecurity.com/2024/04/11/graylog-log-management/	helpnetsecurity	news;Don't miss;Hot stuff;News;GitHub;log management;open source;software;	1	2024-04-11	灰色: 开源日志管理
9941	St. Cloud most recent in string of Florida cities hit with ransomware	https://buaq.net/go-230428.html	buaq	newscopy;	0	2024-03-26	佛罗里达连连串城市中最新的圣克劳德市
24232	Malvertising Campaigns Surged in 2023	https://blog.knowbe4.com/malvertising-campaigns-surged-in-2023	knowbe4	news;Phishing;	1	2024-04-11	2023年爆发的扭曲运动
8391	Fujitsu says it discovered malware on ‘multiple work computers’ that may expose customer data	https://therecord.media/fujitsu-malware-statement-customer-data	therecord	ransom;Cybercrime;Industry;News;News Briefs;Technology;	1	2024-03-18	Fujitsu说,它在 " 多种工作计算机 " 上发现了可能暴露客户数据的恶意软件。
20752	Microsoft Patch Tuesday Tsunami: No Zero-Days, but an Asterisk	https://www.darkreading.com/vulnerabilities-threats/microsoft-patch-tuesday-no-zero-days-but-one-under-active-exploit	darkreading	news;	1	2024-04-09	微软帕奇 星期二海啸:无零日,但有星号
24173	DuckDuckGo launches a premium Privacy Pro VPN service	https://www.bleepingcomputer.com/news/security/duckduckgo-launches-a-premium-privacy-pro-vpn-service/	bleepingcomputer	news;Security;Software;	1	2024-04-11	DuckDuckDuckGo 推出保值隐私 Pro VPN 服务
24237	Top Tax Scams of 2024 Your Organization Should Watch Out For	https://blog.knowbe4.com/top-tax-scams-2024	knowbe4	news;Phishing;Security Awareness Training;Artificial Intelligence;	1	2024-04-11	2024年最顶尖的税收薄膜 贵组织应该注意
24204	Zambia Busts 77 People in China-Backed Cybercrime Operation	https://www.darkreading.com/endpoint-security/zambia-busts-77-in-china-backed-cybercrime-operation	darkreading	news;	4	2024-04-11	赞比亚在中国打击网络犯罪行动中打击77人
24238	Water Facilities Compromised By Iranian Threat Actors	https://blog.knowbe4.com/water-facilities-compromised-iranian-threat-actors	knowbe4	news;Cybersecurity;Security Culture;	3	2024-04-11	伊朗威胁行为体破坏的供水设施
12218	Indian Government Rescues 250 Citizens Forced into Cybercrime in Cambodia	https://thehackernews.com/2024/04/indian-government-rescues-250-citizens.html	feedburner	news;	1	2024-04-01	印度政府援救250名柬埔寨公民,
22037	RUBYCARP the SSH Brute Botnet Resurfaces With New Tools	https://gbhackers.com/rubycarp-ssh-brute-botnet/	GBHacker	news;Botnet;cyber security;Cyber Security News;	1	2024-04-10	RUBYCARP SSH 布鲁特 Butte Botnet 使用新工具的 SSH 布鲁特 Botnet 重新表层
22038	New Critical Rust Vulnerability Allows Attackers to Inject Commands on Windows Systems	https://gbhackers.com/rust-flaw-let-attackers-inject-commands/	GBHacker	news;cyber security;Vulnerability;Windows;Command Injection;Rust Vulnerability;	1	2024-04-10	允许攻击者在 Windows 系统上输入命令
10986	X Files Lawsuit Against Center for Countering Digital Hate, Alleging Speech Suppression Tactics	https://buaq.net/go-231433.html	buaq	newscopy;	0	2024-03-30	X 文件 反对反对数字仇恨、煽动言论压制策略中心的法律诉讼
23335	Apple Expands Spyware Alert System to Warn Users of Mercenary Attacks	https://thehackernews.com/2024/04/apple-expands-spyware-alert-system-to.html	feedburner	news;	1	2024-04-11	Apples 向雇佣军袭击的警告用户推广间谍警报系统
23343	Fortinet Rolls Out Critical Security Patches for FortiClientLinux Vulnerability	https://thehackernews.com/2024/04/fortinet-has-released-patches-to.html	feedburner	news;	1	2024-04-11	Fortinet 为FortClientLinux脆弱性推出关键安全补丁
25936	小米公司深夜连发三文 	https://s.weibo.com/weibo?q=%23小米公司深夜连发三文 %23	sina.weibo	hotsearch;weibo	1	2024-04-09	小米公司深夜连发三文
25937	小米提醒不可魔改升级SU7车机硬件 	https://s.weibo.com/weibo?q=%23小米提醒不可魔改升级SU7车机硬件 %23	sina.weibo	hotsearch;weibo	1	2024-04-10	小米提醒不可魔改升级SU7车机硬件
25938	小米汽车听劝加按键 	https://s.weibo.com/weibo?q=%23小米汽车听劝加按键 %23	sina.weibo	hotsearch;weibo	1	2024-04-11	小米汽车听劝加按键
25939	小米汽车回应车内摄像头 	https://s.weibo.com/weibo?q=%23小米汽车回应车内摄像头 %23	sina.weibo	hotsearch;weibo	1	2024-04-11	小米汽车回应车内摄像头
25940	张颂文说还没去提小米SU7 	https://s.weibo.com/weibo?q=%23张颂文说还没去提小米SU7 %23	sina.weibo	hotsearch;weibo	1	2024-04-11	张颂文说还没去提小米SU7
24279	Simbian raises $10 million to automate security operations with GenAI	https://www.helpnetsecurity.com/2024/04/11/simbian-funding-10-million/	helpnetsecurity	news;Industry news;Simbian;	1	2024-04-11	Simbian筹募1 000万美元,与GenAI公司实现安全行动自动化
10691	TheMoon Botnet Resurfaces, Exploiting EoL Devices to Power Criminal Proxy	https://thehackernews.com/2024/03/themoon-botnet-resurfaces-exploiting.html	feedburner	news;	1	2024-03-29	Moon Botnet 重新表层, 利用EL 设备来增强罪犯代理权
10703	Implications of AI for Corporate Security	https://securityboulevard.com/2024/03/implications-of-ai-for-corporate-security/	securityboulevard	news;Security Bloggers Network;article;	1	2024-03-29	大赦国际对公司安全的影响
422	Mastering Nmap: A Comprehensive Guide for Network Discovery and Security Auditing	https://infosecwriteups.com/mastering-nmap-a-comprehensive-guide-for-network-discovery-and-security-auditing-29fa0c669ef7?source=rss----7b722bfd1b8d---4	infosecwriteups	tech;cybersecurity;penetration-testing;bug-bounty;networking;nmap;	1	2024-03-04	《掌握Nmap:网络发现和安全审计综合指南》
22068	Alethea raises $20 million to combat disinformation campaigns	https://www.helpnetsecurity.com/2024/04/10/alethea-funding-20-million/	helpnetsecurity	news;Industry news;Alethea;	1	2024-04-10	阿莱西娅募募2 000万美元,以打击假情报活动
697	Chris-Argiropoulos-Professional	http://www.ransomfeed.it/index.php?page=post_details&id_post=13579	ransomfeed	ransom;medusa;	1	2024-03-03	克里斯·阿吉罗普洛斯-专业
23	Hacked WordPress Sites Abusing Visitors' Browsers for Distributed Brute-Force Attacks	https://thehackernews.com/2024/03/hacked-wordpress-sites-abusing-visitors.html	feedburner	news;	1	2024-03-07	滥用游客浏览器对散布的布鲁特-部队袭击进行虐待的黑包文字新闻网站
26208	华为首款开放式耳机 	https://s.weibo.com/weibo?q=%23华为首款开放式耳机 %23	sina.weibo	hotsearch;weibo	1	2023-12-13	华为首款开放式耳机
25941	支付宝崩了 	https://s.weibo.com/weibo?q=%23支付宝崩了 %23	sina.weibo	hotsearch;weibo	1	2024-04-09	支付宝崩了
25942	智己小米事件始末 	https://s.weibo.com/weibo?q=%23智己小米事件始末 %23	sina.weibo	hotsearch;weibo	1	2024-04-09	智己小米事件始末
25943	智己汽车再次向小米道歉 	https://s.weibo.com/weibo?q=%23智己汽车再次向小米道歉 %23	sina.weibo	hotsearch;weibo	1	2024-04-09	智己汽车再次向小米道歉
25944	智己错误标注小米SU7参数 	https://s.weibo.com/weibo?q=%23智己错误标注小米SU7参数 %23	sina.weibo	hotsearch;weibo	1	2024-04-09	智己错误标注小米SU7参数
25945	特斯拉市值一夜涨超1800亿 	https://s.weibo.com/weibo?q=%23特斯拉市值一夜涨超1800亿 %23	sina.weibo	hotsearch;weibo	1	2024-04-09	特斯拉市值一夜涨超1800亿
25946	王者荣耀	https://s.weibo.com/weibo?q=%23王者荣耀%23	sina.weibo	hotsearch;weibo	1	2024-04-09	王者荣耀
25947	王者荣耀唱片 	https://s.weibo.com/weibo?q=%23王者荣耀唱片 %23	sina.weibo	hotsearch;weibo	1	2024-04-11	王者荣耀唱片
26210	华为首款轿车智界S7首批到店 	https://s.weibo.com/weibo?q=%23华为首款轿车智界S7首批到店 %23	sina.weibo	hotsearch;weibo	1	2023-12-13	华为首款轿车智界S7首批到店
26211	华为高颜值HR回应 	https://s.weibo.com/weibo?q=%23华为高颜值HR回应 %23	sina.weibo	hotsearch;weibo	1	2023-12-08	华为高颜值HR回应
26212	华为鸿蒙发布会 	https://s.weibo.com/weibo?q=%23华为鸿蒙发布会 %23	sina.weibo	hotsearch;weibo	1	2024-01-18	华为鸿蒙发布会
26213	华为龙年手机壳上架官网 	https://s.weibo.com/weibo?q=%23华为龙年手机壳上架官网 %23	sina.weibo	hotsearch;weibo	1	2024-01-30	华为龙年手机壳上架官网
26214	卢伟冰称将形成苹果三星小米三足鼎立格局 	https://s.weibo.com/weibo?q=%23卢伟冰称将形成苹果三星小米三足鼎立格局 %23	sina.weibo	hotsearch;weibo	1	2024-01-16	卢伟冰称将形成苹果三星小米三足鼎立格局
26215	原生鸿蒙操作系统星河版曝光 	https://s.weibo.com/weibo?q=%23原生鸿蒙操作系统星河版曝光 %23	sina.weibo	hotsearch;weibo	1	2024-01-19	原生鸿蒙操作系统星河版曝光
26216	原神小米联名 	https://s.weibo.com/weibo?q=%23原神小米联名 %23	sina.weibo	hotsearch;weibo	1	2023-12-08	原神小米联名
25948	王者荣耀酷洛米 	https://s.weibo.com/weibo?q=%23王者荣耀酷洛米 %23	sina.weibo	hotsearch;weibo	1	2024-04-12	王者荣耀酷洛米
25949	荣耀回应小米道歉 	https://s.weibo.com/weibo?q=%23荣耀回应小米道歉 %23	sina.weibo	hotsearch;weibo	1	2024-04-11	荣耀回应小米道歉
25950	警方回应聊城一特斯拉撞断大桥护栏 	https://s.weibo.com/weibo?q=%23警方回应聊城一特斯拉撞断大桥护栏 %23	sina.weibo	hotsearch;weibo	1	2024-04-10	警方回应聊城一特斯拉撞断大桥护栏
25951	雷军说余承东调侃小米手机支架没事 	https://s.weibo.com/weibo?q=%23雷军说余承东调侃小米手机支架没事 %23	sina.weibo	hotsearch;weibo	1	2024-04-12	雷军说余承东调侃小米手机支架没事
25952	马云内部发帖肯定阿里一年改革 	https://s.weibo.com/weibo?q=%23马云内部发帖肯定阿里一年改革 %23	sina.weibo	hotsearch;weibo	1	2024-04-10	马云内部发帖肯定阿里一年改革
25953	鸿蒙智行回应雷军 	https://s.weibo.com/weibo?q=%23鸿蒙智行回应雷军 %23	sina.weibo	hotsearch;weibo	1	2024-04-09	鸿蒙智行回应雷军
26217	吉利高管到小米线下门店看SU7 	https://s.weibo.com/weibo?q=%23吉利高管到小米线下门店看SU7 %23	sina.weibo	hotsearch;weibo	1	2024-04-01	吉利高管到小米线下门店看SU7
26218	吉利高管回应未被小米汽车致敬 	https://s.weibo.com/weibo?q=%23吉利高管回应未被小米汽车致敬 %23	sina.weibo	hotsearch;weibo	1	2023-12-27	吉利高管回应未被小米汽车致敬
26220	向日葵崩了 	https://s.weibo.com/weibo?q=%23向日葵崩了 %23	sina.weibo	hotsearch;weibo	1	2024-01-26	向日葵崩了
26221	周鸿祎称要坚定支持华为 	https://s.weibo.com/weibo?q=%23周鸿祎称要坚定支持华为 %23	sina.weibo	hotsearch;weibo	1	2024-01-18	周鸿祎称要坚定支持华为
26222	周鸿祎谈滴滴崩了会发生什么 	https://s.weibo.com/weibo?q=%23周鸿祎谈滴滴崩了会发生什么 %23	sina.weibo	hotsearch;weibo	1	2023-11-28	周鸿祎谈滴滴崩了会发生什么
26223	喜马拉雅崩了 	https://s.weibo.com/weibo?q=%23喜马拉雅崩了 %23	sina.weibo	hotsearch;weibo	1	2023-12-19	喜马拉雅崩了
20774	Critical Improvements To The Seven Most Common Pieces of Cybersecurity Advice	https://blog.knowbe4.com/seven-critical-adjustments-needed-improve-cybersecurity-advice	knowbe4	news;Social Engineering;Phishing;Spear Phishing;MFA;	1	2024-04-09	关键改进网络安全咨询的七大最常见的网络安全建议
20780	How to Use Cyber Threat Intelligence ? 4 TI Categories to Learn SOC/DFIR Team	https://gbhackers.com/cyber-threat-intelligence/	GBHacker	news;Cyber Attack;cyber security;Cyber Security News;	1	2024-04-09	如何使用网络威胁情报? 4 TI类学习SOC/DFIR小组
20786	Hackers Using ScrubCrypt ‘AV Evasion Tool’ To Exploit Oracle WebLogic Servers	https://gbhackers.com/scrubcrypt-weblogic-exploit/	GBHacker	news;cyber security;Exploit;Malware;Malware analysis;Oracle Weblogic;	1	2024-04-09	利用ScrubCrypt `AV Evasion 工具 ' 来利用Oracle Oracle WebLogic 服务器的黑客
20811	Microsoft patches two actively exploited zero-days (CVE-2024-29988, CVE-2024-26234)	https://www.helpnetsecurity.com/2024/04/09/april-2024-patch-tuesday-cve-2024-29988/	helpnetsecurity	news;Don't miss;Hot stuff;News;0-day;CISA;CVE;Microsoft;Patch Tuesday;security update;SonicWall;Sophos;Tenable;Trend Micro;vulnerability;vulnerability management;	3	2024-04-09	微软补丁两个积极开发的零日(CVE-2024-29988,CVE-2024-26234)
20813	ESET Small Business Security offers protection against online fraud, data theft and human error	https://www.helpnetsecurity.com/2024/04/09/eset-small-business-security/	helpnetsecurity	news;Industry news;ESET;	1	2024-04-09	小企业安全提供防止网上欺诈、数据盗窃和人为错误的保护
20814	New Google Workspace feature prevents sensitive security changes if two admins don’t approve them	https://www.helpnetsecurity.com/2024/04/09/google-workspace-multi-party-approvals/	helpnetsecurity	news;Don't miss;Hot stuff;News;	1	2024-04-09	新的谷歌工作空间功能防止敏感安全变化,
10763	Russian Federation-backed threat group APT29 Now Targeting German Political Parties	https://blog.knowbe4.com/russian-backed-group-apt29-targeting-german-political-parties	knowbe4	news;Phishing;Security Culture;	4	2024-03-29	俄罗斯联邦支持的威胁团体APT29 立即针对德国政党
20773	New Phishing-as-a-Service (PhaaS) platform, 'Tycoon 2FA', Targets Microsoft 365 and Gmail Accounts	https://blog.knowbe4.com/new-phishing-as-a-service-phaas-platform-tycoon-2fa-targets-microsoft-gmail-accounts	knowbe4	news;Phishing;Security Culture;MFA;	1	2024-04-09	新钓钓鱼服务平台、“Tycoon 2FA”、目标Microsoft 365和Gmail账户
22998	How Google’s 90-day TLS certificate validity proposal will affect enterprises	https://www.helpnetsecurity.com/2024/04/11/tls-certificate-renewal-proposal/	helpnetsecurity	news;Don't miss;Expert analysis;Expert corner;Hot stuff;News;AppViewX;automation;certificates;cybersecurity;DevOps;encryption;Google;opinion;policy;risk assessment;	1	2024-04-11	Google90天的TLS证书认证建议将如何影响企业
20848	Hackers Targeting Human Rights Activists in Morocco and Western Sahara	https://thehackernews.com/2024/04/hackers-targeting-human-rights.html	feedburner	news;	1	2024-04-09	摩洛哥和西撒哈拉针对人权积极分子的黑客组织
20853	Daniel Stori’s ‘Minimum Viable Elevator’	https://securityboulevard.com/2024/04/daniel-storis-minimum-viable-elevator/	securityboulevard	news;Humor;Security Bloggers Network;Daniel Stori;Sarcasm;satire;turnoff.us;	1	2024-04-09	Daniel Stori的 " 最起码可行的电梯 "
23356	NIST CSF: A “Fellowship” for Your Cybersecurity Journey to 2.0 	https://securityboulevard.com/2024/04/nist-csf-a-fellowship-for-your-cybersecurity-journey-to-2-0/	securityboulevard	news;Security Bloggers Network;Blog Posts;	1	2024-04-11	NIST CSF: 网络安全路线“Fellowship”至2.0。
20838	Ukrainian security service’s cyber chief suspended following media investigation	https://therecord.media/ukraine-cybersecurity-sbu-illia-vitiuk-suspended	therecord	ransom;Government;News;People;Leadership;	1	2024-04-09	乌克兰安全局网络主管在媒体调查后被停职
22221	金眼狗黑产组织最新攻击样本详细分析与关联分析	https://xz.aliyun.com/t/14272	阿里先知实验室	news;	1	2024-04-10	金眼狗黑产组织最新攻击样本详细分析与关联分析
20852	Breaking APIs with Naughty Strings	https://securityboulevard.com/2024/04/breaking-apis-with-naughty-strings/	securityboulevard	news;Security Bloggers Network;API Hacking Fundamentals;	1	2024-04-09	与下调字符串断开 APP
22222	勒索软件漏洞？在不支付赎金的情况下解密文件	https://xz.aliyun.com/t/14273	阿里先知实验室	news;	3	2024-04-10	勒索软件漏洞？在不支付赎金的情况下解密文件
23757	Fortra For Windows Vulnerability Let Attackers Escalate Privilege	https://gbhackers.com/fortra-windows-vulnerability-escalation/	GBHacker	news;CVE/vulnerability;Cyber Security News;Exploit;CVE-2024-0259;Fortra Security Update;Privilege Escalation;	1	2024-04-11	Fortra for Windows 脆弱程度
20835	LG releases updates for vulnerabilities that could allow hackers to gain access to TVs	https://therecord.media/lg-patches-vulnerabilities-tv	therecord	ransom;Cybercrime;News;Technology;	1	2024-04-09	LG发布最新的脆弱性更新信息,使黑客能够利用电视
23758	Hackers Manipulate GitHub Search To Deliver Clipboard-Hijacking Malware	https://gbhackers.com/manipulate-github-search-to-deliver-malware/	GBHacker	news;cyber security;Malware;Cyber Security News;	1	2024-04-11	黑客操纵 GitHub 搜索以交付剪贴板抓劫错误
23771	碰撞AI安全的火花，探索企业安全建设新路径	https://www.freebuf.com/fevents/397485.html	freebuf	news;活动;	1	2024-04-10	碰撞AI安全的火花，探索企业安全建设新路径
23787	AppViewX CERT+ helps organizations identify and renew certificates before they expire	https://www.helpnetsecurity.com/2024/04/11/appviewx-cert/	helpnetsecurity	news;Industry news;AppViewX;	1	2024-04-11	AppViVX CERT+ 帮助各组织在证书到期前确定并更新证书
19168	Targus discloses cyberattack after hackers detected on file servers	https://www.bleepingcomputer.com/news/security/targus-discloses-cyberattack-after-hackers-detected-on-file-servers/	bleepingcomputer	news;Security;	1	2024-04-08	Targus在文件服务器上发现黑客后披露了网络攻击
20840	10-Year-Old 'RUBYCARP' Romanian Hacker Group Surfaces with Botnet	https://thehackernews.com/2024/04/10-year-old-rubycarp-romanian-hacker.html	feedburner	news;	1	2024-04-09	10年“RUBYCARP” 罗马尼亚装有Botnet的黑客组表面
22246	Webinar: Learn How to Stop Hackers from Exploiting Hidden Identity Weaknesses	https://thehackernews.com/2024/04/webinar-learn-how-to-stop-hackers-from.html	feedburner	news;	1	2024-04-10	Webinar:学习如何阻止黑客利用隐藏身份弱点
22959	Cyber Espionage: Turla APT Hackers Attack European Organization With Backdoor	https://gbhackers.com/cyber-espionage-turla-apt-hackers-attack-european-organization-with-backdoor/	GBHacker	news;Malware;computer security;Cyber Security News;	2	2024-04-11	网络间谍:Turla APT 黑客攻击欧洲后门组织
20836	Researchers discover new ransomware gang ‘Muliaka’ attacking Russian businesses	https://therecord.media/muliaka-ransomware-group-targeting-russian-businesses-conti	therecord	ransom;Cybercrime;Malware;News;News Briefs;	4	2024-04-09	研究者发现新的赎金软件团伙“Muliaka”攻击俄罗斯企业,
22995	Leveraging AI for enhanced compliance and governance	https://www.helpnetsecurity.com/2024/04/11/joseph-sweeney-ibrs-ai-information-management/	helpnetsecurity	news;Don't miss;Features;Hot stuff;News;artificial intelligence;compliance;cybersecurity;data security;IBRS;opinion;privacy;regulation;	1	2024-04-11	利用大赦国际加强遵约和治理
20816	LG smart TVs may be taken over by remote attackers	https://www.helpnetsecurity.com/2024/04/09/lg-smart-tvs-webos-vulnerabilities/	helpnetsecurity	news;Don't miss;Hot stuff;News;Bitdefender;Internet of Things;LG;security update;smart tv;vulnerability;	1	2024-04-09	远程攻击者可能接管LG智能电视机
20829	Section 702: The Future of the Biggest US Spy Program Hangs in the Balance	https://www.wired.com/live/section-702-reauthorization-congress-2024/	wired	news;Security;Security / National Security;Security / Privacy;Politics;Politics / Policy;	1	2024-04-09	第702节 美国最大的间谍计划的未来
20834	German database company Genios confirms ransomware attack	https://therecord.media/genios-germany-ransomware-attack	therecord	ransom;Industry;Cybercrime;News;	2	2024-04-09	德国数据库公司Genios确认赎金软件攻击
3420	Researchers Find Flaws in OpenAI ChatGPT, Google Gemini	https://securityboulevard.com/2024/03/researchers-find-flaws-in-openai-chatgpt-google-gemini/	securityboulevard	news;Cloud Security;Cybersecurity;Data Security;DevOps;Featured;Network Security;News;Security Boulevard (Original);Social - Facebook;Social - LinkedIn;Social - X;Spotlight;Threat Intelligence;Vulnerabilities;API vulnerabilities;Generative AI risks;Google Gemini;OpenAI ChatGPT;	1	2024-03-14	在OpenAI ChatGPT、谷歌双子星中寻找法律
11015	What Is Session Management & Tips to Do It Securely	https://securityboulevard.com/2024/03/what-is-session-management-tips-to-do-it-securely/	securityboulevard	news;Security Bloggers Network;	1	2024-03-30	安全地进行会话管理及提示
19535	Vietnamese Cybercrime Group CoralRaider Nets Financial Data	https://www.darkreading.com/vulnerabilities-threats/vietnamese-cybercrime-group-coralraider-nets-financial-data	darkreading	news;	1	2024-04-09	越南网络犯罪集团
18515	Multiple CData Vulnerabilities Let Attackers Bypass Security Restrictions	https://gbhackers.com/multiple-cdata-vulnerabilities/	GBHacker	news;CVE/vulnerability;Cyber Security News;Vulnerability;CData Security;Jetty Server;	1	2024-04-08	让攻击者绕过安全限制
19590	Strategies for secure identity management in hybrid environments	https://www.helpnetsecurity.com/2024/04/09/charlotte-wylie-okta-hybrid-environments-identity-security/	helpnetsecurity	news;Don't miss;Features;Hot stuff;News;access management;authentication;critical infrastructure;cyber hygiene;identity;identity management;Okta;password management;passwordless;strategy;	1	2024-04-09	混合环境中安全身份管理战略
18478	Notepad++ needs your help in 'parasite website' shutdown	https://www.bleepingcomputer.com/news/security/notepad-plus-plus-needs-your-help-in-parasite-website-shutdown/	bleepingcomputer	news;Security;	1	2024-04-08	Notpad+++ 需要您在“ 平行网站” 关闭时的帮助
11021	DinodasRAT malware targets Linux servers in espionage campaign	https://www.bleepingcomputer.com/news/security/dinodasrat-malware-targets-linux-servers-in-espionage-campaign/	bleepingcomputer	news;Security;	1	2024-03-31	DinodasRAT恶意软件攻击Linux服务器进行间谍活动
11008	Critical Backdoor Found in XZ Utils (CVE-2024-3094) Enables SSH Compromise	https://securityboulevard.com/2024/03/critical-backdoor-found-in-xz-utils-cve-2024-3094-enables-ssh-compromise/	securityboulevard	news;Security Bloggers Network;	3	2024-03-31	在 XZ 内发现的关键后门( CVE-2024- 3094) 启用 SSH 折叠
19620	A Case Study for Protecting Files with Sensitive Data in the Cloud	https://securityboulevard.com/2024/04/a-case-study-for-protecting-files-with-sensitive-data-in-the-cloud/	securityboulevard	news;Data Security;Security Bloggers Network;File Transfer Security;	1	2024-04-08	保护云中敏感数据档案案例研究
11009	Cybersecurity Tabletop Exercises: How Far Should You Go?	https://securityboulevard.com/2024/03/cybersecurity-tabletop-exercises-how-far-should-you-go/	securityboulevard	news;Security Bloggers Network;	1	2024-03-31	网络安全桌面演习:你应该走多远?
11014	Understanding and Mitigating the Fedora Rawhide Vulnerability (CVE-2024-3094)	https://securityboulevard.com/2024/03/understanding-and-mitigating-the-fedora-rawhide-vulnerability-cve-2024-3094/	securityboulevard	news;Application Security;Security Bloggers Network;CVE;Vulnerability Insights;	3	2024-03-30	了解并减轻费多拉·罗希德脆弱性(CVE-2024-3094)
19593	How exposure management elevates cyber resilience	https://www.helpnetsecurity.com/2024/04/09/organizations-exposure-management/	helpnetsecurity	news;Don't miss;Expert analysis;Expert corner;News;cyber resilience;cybersecurity;opinion;risk;security controls;shadow IT;WithSecure;	1	2024-04-09	风险管理如何提升网络复原力
22260	AT&T now says data breach impacted 51 million customers	https://www.bleepingcomputer.com/news/security/att-now-says-data-breach-impacted-51-million-customers/	bleepingcomputer	news;Security;	1	2024-04-10	AT&T现在说数据中断 影响了5100万客户
19591	EJBCA: Open-source public key infrastructure (PKI), certificate authority (CA)	https://www.helpnetsecurity.com/2024/04/09/ejbca-open-source-pki-ca/	helpnetsecurity	news;Don't miss;Hot stuff;News;authentication;certificate authority;GitHub;open source;PKI;software;	1	2024-04-09	EJBCA: 开放源公共钥匙基础设施(PKI)、验证局(CA)
11019	AT&T confirms data for 73 million customers leaked on hacker forum	https://www.bleepingcomputer.com/news/security/atandt-confirms-data-for-73-million-customers-leaked-on-hacker-forum/	bleepingcomputer	news;Security;	1	2024-03-30	AT&T确认在黑客论坛上泄露的7 300万客户的数据
11016	What You Need to Know About the XZ Utils Backdoor	https://securityboulevard.com/2024/03/what-you-need-to-know-about-the-xz-utils-backdoor/	securityboulevard	news;Security Bloggers Network;AppSec;Legit;threats;	1	2024-03-30	您需要了解的 XZ 后门的 XZ 工具
11007	An Accidental Discovery of a Backdoor Likely Prevented Thousands of Infections	https://securityboulevard.com/2024/03/an-accidental-discovery-of-a-backdoor-likely-prevented-thousands-of-infections/	securityboulevard	news;Security Bloggers Network;Uncategorized;	1	2024-03-30	意外发现后门可能预防的成千上万感染者
18517	Multiple Cisco Small Business Routers Vulnerable to XSS Attacks	https://gbhackers.com/vulnerable-to-xss-attacks/	GBHacker	news;Cisco;CVE/vulnerability;Cyber Attack;cyber security;Cyber Security News;Vulnerability;	1	2024-04-08	易受XSS袭击的多 Cisco小型商业路由
11012	How did CVE-2024-27198 Lead to Critical Vulnerability in JetBrains?	https://securityboulevard.com/2024/03/how-did-cve-2024-27198-lead-to-critical-vulnerability-in-jetbrains/	securityboulevard	news;Application Security;Network Security;Security Bloggers Network;Threats & Breaches;Vulnerabilities;CVE-2024-27198;cyber attacks;Cyber awareness;Cyber Security;Penetration Testing;pentesting;VAPT;	3	2024-03-30	CVE 2024-27198如何导致喷气呼吸系统的关键脆弱性?
22261	Chrome Enterprise gets Premium security but you have to pay for it	https://www.bleepingcomputer.com/news/security/chrome-enterprise-gets-premium-security-but-you-have-to-pay-for-it/	bleepingcomputer	news;Security;	1	2024-04-10	铬企业公司拿到了保证金 但你必须为此付出代价
22264	Google Workspace rolls out multi-admin approval feature for risky changes	https://www.bleepingcomputer.com/news/security/google-workspace-rolls-out-multi-admin-approval-feature-for-risky-changes/	bleepingcomputer	news;Security;Google;	1	2024-04-10	Google 工作空间推出风险改变的多成分批准功能
22265	Malicious PowerShell script pushing malware looks AI-written	https://www.bleepingcomputer.com/news/security/malicious-powershell-script-pushing-malware-looks-ai-written/	bleepingcomputer	news;Security;	1	2024-04-10	恶意的 PowerShell 脚本推恶意软件看起来像 AI 写
22266	Malicious Visual Studio projects on GitHub push Keyzetsu malware	https://www.bleepingcomputer.com/news/security/malicious-visual-studio-projects-on-github-push-keyzetsu-malware/	bleepingcomputer	news;Security;	1	2024-04-10	GitHub推Keyzetsu恶意软件的恶意视觉演播室项目
22267	New Spectre v2 attack impacts Linux systems on Intel CPUs	https://www.bleepingcomputer.com/news/security/new-spectre-v2-attack-impacts-linux-systems-on-intel-cpus/	bleepingcomputer	news;Security;Hardware;Linux;	1	2024-04-10	新的光谱 v2 攻击在 Intel CPUs 上撞击 Linux 系统
18562	Cybercriminals Targeting Latin America with Sophisticated Phishing Scheme	https://thehackernews.com/2024/04/cybercriminals-targeting-latin-america.html	feedburner	news;	1	2024-04-08	利用先进的幻影计划针对拉丁美洲的网络罪犯
11051	关于Modbus协议攻防与检测	https://www.freebuf.com/articles/ics-articles/396458.html	freebuf	news;工控安全;	1	2024-03-29	关于Modbus协议攻防与检测
11026	It's surprisingly difficult for AI to create just a plain white image	https://www.bleepingcomputer.com/news/technology/its-surprisingly-difficult-for-ai-to-create-just-a-plain-white-image/	bleepingcomputer	news;Technology;	1	2024-03-31	人工智能很难创造出 纯白的白色形象
11050	时间线全记录 | Xzliblzma 被植入源码级后门   	https://www.freebuf.com/articles/396531.html	freebuf	news;文章;系统安全;网络安全;	1	2024-03-30	时间线全记录 | Xzliblzma 被植入源码级后门
11025	Vultur banking malware for Android poses as McAfee Security app	https://www.bleepingcomputer.com/news/security/vultur-banking-malware-for-android-poses-as-mcafee-security-app/	bleepingcomputer	news;Security;Mobile;	2	2024-03-30	作为McAfee 安全应用程序的Android合成物的 Vultur银行恶意软件
19313	【公益译文】欧洲量子网络安全议程	https://blog.nsfocus.net/cybersecurity_dp/	绿盟	news;公益译文;	1	2024-04-09	【公益译文】欧洲量子网络安全议程
20855	Hyperproof Is a G2 Category Leader (Again) for Spring 2024	https://securityboulevard.com/2024/04/hyperproof-is-a-g2-category-leader-again-for-spring-2024/	securityboulevard	news;Security Bloggers Network;Blog Posts;Hyperproof News;	1	2024-04-09	高防重度是2024年春季的G2级头目(再次)
20854	FCC Mulls Rules to Protect Abuse Survivors from Stalking Through Cars	https://securityboulevard.com/2024/04/fcc-mulls-rules-to-protect-abuse-survivors-from-stalking-through-cars/	securityboulevard	news;Cloud Security;Cybersecurity;Data Security;Featured;Industry Spotlight;IoT & ICS Security;News;Security Awareness;Security Boulevard (Original);Social - Facebook;Social - LinkedIn;Social - X;Spotlight;automobile;automobiles;Car;connected car security;domestic abuse;fcc;government;MVNO;telematics;	1	2024-04-09	FCC 防止虐待幸存者通过汽车跟踪跟踪的枪管规则
20859	USENIX Security ’23 – Qifan Xiao, Xudong Pan, Yifan Lu, Mi Zhang, Jiarun Dai, Min Yang,- xorcising “Wraith”: Protecting LiDAR-based Object Detector In Automated Driving System From Appearing Attacks	https://securityboulevard.com/2024/04/usenix-security-23-qifan-xiao-xudong-pan-yifan-lu-mi-zhang-jiarun-dai-min-yang-xorcising-wraith-protecting-lidar-based-object-detector-in-automated-driving-system-from-appearing-attack/	securityboulevard	news;Security Bloggers Network;Security Conferences;USENIX;USENIX Security ’23;	1	2024-04-09	USENIX 安全 23 - Qifan Xiao, Xudong Pan, Yifan Lu, Mi Zhang, Jiarrun Dai, Min Yang, 划断 " Wraith " :在自动驾驶系统中保护以LiDAR为基地的物体探测器,使其不露面
19334	随手分享的APP链接，可能会让你“大型社死”	https://www.freebuf.com/articles/neopoints/397225.html	freebuf	news;观点;	1	2024-04-08	随手分享的APP链接，可能会让你“大型社死”
22268	Reusing passwords: The hidden cost of convenience	https://www.bleepingcomputer.com/news/security/reusing-passwords-the-hidden-cost-of-convenience/	bleepingcomputer	news;Security;	1	2024-04-10	重复使用密码:隐藏的方便成本
22273	Google Gives Gemini a Security Boost	https://www.darkreading.com/cloud-security/google-gives-gemini-a-security-boost	darkreading	news;	1	2024-04-10	Google 给双子星一个安全刺激
20861	Zero-Day Attacks on the Rise: Google Reports 50% Increase in 2023	https://securityboulevard.com/2024/04/zero-day-attacks-on-the-rise-google-reports-50-increase-in-2023/	securityboulevard	news;Security Bloggers Network;Blog;Zero Day Attacks;zero-day;zero-day attack;zero-day attack identification;Zero-day threats;	1	2024-04-09	2023年Google报告增加50%。
22271	XZ Utils Scare Exposes Hard Truths About Software Security	https://www.darkreading.com/application-security/xz-utils-scare-exposes-hard-truths-in-software-security	darkreading	news;	1	2024-04-10	XZ UTUS 护理展览 关于软件安全的硬真相
20857	Should You Pay a Ransomware Attacker?	https://securityboulevard.com/2024/04/should-you-pay-a-ransomware-attacker/	securityboulevard	news;Security Bloggers Network;Blog;Ransomware;Threats and Trends;	2	2024-04-09	你该付钱买个火炉攻击器吗?
20860	What Security Metrics Should I Be Looking At?	https://securityboulevard.com/2024/04/what-security-metrics-should-i-be-looking-at-3/	securityboulevard	news;Security Bloggers Network;Security Automation;SOC;	1	2024-04-09	我该看什么安全度量?
4914	User Enumeration Techniques and Tactics In an Active Directory Pentesting Engagement.	https://infosecwriteups.com/user-enumeration-techniques-and-tactics-in-an-active-directory-pentesting-engagement-c634bf241017?source=rss----7b722bfd1b8d---4	infosecwriteups	tech;penetration-testing;pentesting;ethical-hacking;active-directory;cybersecurity;	1	2024-03-15	用户编号技术和策略在活动目录 Pentercontroduction 中使用。
22275	Selecting the Right Authentication Protocol for Your Business	https://www.darkreading.com/cloud-security/selecting-the-right-authentication-protocol-for-your-business	darkreading	news;	1	2024-04-10	选择您企业的右权认证协议
26120	360完成鸿蒙原生应用核心版本 	https://s.weibo.com/weibo?q=%23360完成鸿蒙原生应用核心版本 %23	sina.weibo	hotsearch;weibo	1	2023-12-27	360完成鸿蒙原生应用核心版本
26121	B站崩了 	https://s.weibo.com/weibo?q=%23B站崩了 %23	sina.weibo	hotsearch;weibo	1	2024-01-17	B站崩了
26122	B站股价大跌遭阿里减持 	https://s.weibo.com/weibo?q=%23B站股价大跌遭阿里减持 %23	sina.weibo	hotsearch;weibo	1	2024-03-22	B站股价大跌遭阿里减持
26123	CEO称字节该有的大公司病全有了 	https://s.weibo.com/weibo?q=%23CEO称字节该有的大公司病全有了 %23	sina.weibo	hotsearch;weibo	1	2024-01-30	CEO称字节该有的大公司病全有了
26124	TikTok回应美议员要求165天内剥离字节跳动 	https://s.weibo.com/weibo?q=%23TikTok回应美议员要求165天内剥离字节跳动 %23	sina.weibo	hotsearch;weibo	1	2024-03-06	TikTok回应美议员要求165天内剥离字节跳动
26125	Vidda回应小米诉讼 	https://s.weibo.com/weibo?q=%23Vidda回应小米诉讼 %23	sina.weibo	hotsearch;weibo	1	2024-03-28	Vidda回应小米诉讼
26126	XYG	https://s.weibo.com/weibo?q=%23XYG%23	sina.weibo	hotsearch;weibo	1	2024-01-04	XYG( XYG)
26127	nova12搭载鸿蒙智慧通信 	https://s.weibo.com/weibo?q=%23nova12搭载鸿蒙智慧通信 %23	sina.weibo	hotsearch;weibo	1	2023-12-26	nova12搭载鸿蒙智慧通信
26128	wind崩了 	https://s.weibo.com/weibo?q=%23wind崩了 %23	sina.weibo	hotsearch;weibo	1	2024-01-08	wind崩了
26129	wps崩了 	https://s.weibo.com/weibo?q=%23wps崩了 %23	sina.weibo	hotsearch;weibo	1	2024-01-05	wps崩了
26130	一加和小米谁急了 	https://s.weibo.com/weibo?q=%23一加和小米谁急了 %23	sina.weibo	hotsearch;weibo	1	2023-12-07	一加和小米谁急了
26131	一网民造谣阿里献血事件被行拘 	https://s.weibo.com/weibo?q=%23一网民造谣阿里献血事件被行拘 %23	sina.weibo	hotsearch;weibo	1	2023-12-26	一网民造谣阿里献血事件被行拘
26132	上海女子阿里车祸救治过程始末 	https://s.weibo.com/weibo?q=%23上海女子阿里车祸救治过程始末 %23	sina.weibo	hotsearch;weibo	1	2023-12-06	上海女子阿里车祸救治过程始末
26133	专家称买小米汽车不如买小米股票 	https://s.weibo.com/weibo?q=%23专家称买小米汽车不如买小米股票 %23	sina.weibo	hotsearch;weibo	1	2024-03-29	专家称买小米汽车不如买小米股票
11095	FoF Pretty Mail 1.1.2 Command Injection	https://cxsecurity.com/issue/WLB-2024030073	cxsecurity	vuln;	1	2024-03-30	FF 漂亮邮件 1.1.2 命令注射
11240	lavellecom	http://www.ransomfeed.it/index.php?page=post_details&id_post=14045	ransomfeed	ransom;lockbit3;	1	2024-03-31	花叶
11236	W-y	http://www.ransomfeed.it/index.php?page=post_details&id_post=14038	ransomfeed	ransom;play;	1	2024-03-29	W - y
11839	Infosec products of the month: March 2024	https://www.helpnetsecurity.com/2024/04/01/infosec-products-of-the-month-march-2024/	helpnetsecurity	news;News;Appdome;AuditBoard;Bedrock Security;Cado Security;Check Point;CyberArk;Cynerio;DataDome;Delinea;Drata;Exabeam;GitGuardian;GitHub;GlobalSign;Legato Security;Legit Security;Malwarebytes;Ordr;Pentera;Portnox;Regula;Sentra;Sonatype;Spin.AI;Tenable;Tufin;Viavi Solutions;Zoom;	1	2024-04-01	该月的信息产品:2024年3月
11094	Intel PowerGadget 3.6 Local Privilege Escalation	https://cxsecurity.com/issue/WLB-2024030072	cxsecurity	vuln;	1	2024-03-30	英特尔 PowerGadget 3.6 地方特权升级
11131	R2Frida - Radare2 And Frida Better Together	http://www.kitploit.com/2024/03/r2frida-radare2-and-frida-better.html	kitploit	tool;Android Security;Dynamic Analysis;iOS;iOS Security;R2Frida;radare2;Static Analysis;Typescript;Windows;	1	2024-03-30	R2Frida - 雷达2 和Frida更好在一起
19794	HTTP/2 Vulnerability Let Hackers Launch DOS Attacks on Web Servers	https://gbhackers.com/http-2-vulnerability/	GBHacker	news;CVE/vulnerability;cyber security;Cyber Security News;Vulnerability;	1	2024-04-09	HTTP/2 脆弱性让黑客在网络服务器上发动DOS攻击
8475	Cheating Hack Halts Apex Legends E-Sports Tourney	https://www.darkreading.com/cyber-risk/apex-legends-tourney-spoiled-by-hackers	darkreading	news;	1	2024-03-19	骗骗黑克停止 顶级传说 电子体育旅行
86	Japan Blames North Korea for PyPI Supply Chain Cyberattack	https://www.darkreading.com/application-security/japan-blames-north-korea-for-pypi-supply-chain-cyberattack	darkreading	news;	3	2024-03-11	日本为PyPPI供应链网络攻击点燃北朝鲜
11837	How to design and deliver an effective cybersecurity exercise	https://www.helpnetsecurity.com/2024/04/01/cybersecurity-exercises/	helpnetsecurity	news;Don't miss;Expert analysis;Expert corner;Hot stuff;News;cyberattacks;cybersecurity;digital transformation;incident response;Information Security Forum;opinion;penetration testing;red team;	1	2024-04-01	如何设计和交付有效的网络安全工作
11238	Pavilion-Construction-LLC	http://www.ransomfeed.it/index.php?page=post_details&id_post=14042	ransomfeed	ransom;bianlian;	1	2024-03-30	馆馆-建筑-LLC
11136	HTB — Active	https://infosecwriteups.com/htb-active-d9fed1c4da72?source=rss----7b722bfd1b8d---4	infosecwriteups	tech;medium;writing;hackthebox;learning;technology;	1	2024-03-30	HTB-主动
10010	CyberheistNews Vol 14 #13 If Social Engineering Accounts for Up to 90% of Attacks, Why Is It Ignored?	https://blog.knowbe4.com/cyberheistnews-vol-14-13-if-social-engineering-accounts-for-up-to-90-percent-of-attacks-why-is-it-ignored	knowbe4	news;Cybercrime;KnowBe4;	1	2024-03-26	如果社会工程账户 高达90%的袭击, 为什么被忽略?
454	Manipulating LLMs – How to confuse ChatGPT	https://buaq.net/go-227538.html	buaq	newscopy;	0	2024-03-12	操纵LLMS — — 如何混淆聊天GPT
628	Change-Healthcare---Optum---UnitedHealth	http://www.ransomfeed.it/index.php?page=post_details&id_post=13489	ransomfeed	ransom;alphv;	1	2024-02-28	改变-保健-保健-Optum-United Health 改变-保健-Optum-United Health 改变-保健-Optum-United Health
19792	D-Link RCE Vulnerability That Affects 92,000 Devices Exploited in Wild	https://gbhackers.com/d-link-rce-vulnerability-exploited-in-wild/	GBHacker	news;Cyber Attack;cyber security;Cyber Security News;Malware;Vulnerability;	1	2024-04-09	D-Link RCE 影响在野外被利用的92 000台装置的脆弱性
11239	Claro	http://www.ransomfeed.it/index.php?page=post_details&id_post=14044	ransomfeed	ransom;trigona;	1	2024-03-30	克拉罗Name
9047	northerncasketcom	http://www.ransomfeed.it/index.php?page=post_details&id_post=13884	ransomfeed	ransom;lockbit3;	1	2024-03-21	北卡塞科科
10878	Beware! Backdoor found in XZ utilities used by many Linux distros (CVE-2024-3094)	https://www.helpnetsecurity.com/2024/03/29/cve-2024-3094-linux-backdoor/	helpnetsecurity	news;Don't miss;Hot stuff;News;backdoor;CISA;CVE;Debian;Fedora;Kali Linux;Linux;open source;Red Hat;supply chain compromise;SUSE;vulnerability;	3	2024-03-29	当心! 许多Linux变异器(CVE-2024-3094)使用的 XZ 公用设施中发现后门
1285	15,000+ Roku Accounts Compromised — Take These Steps to Protect Yourself	https://www.mcafee.com/blogs/internet-security/15000-roku-accounts-compromised-take-these-steps-to-protect-yourself/	mcafee	news;Internet Security;	1	2024-03-12	15 000个罗库账户被扭曲——采取这些步骤保护自己
12086	秘鲁军方勒索事件及相关勒索组织深度分析	https://paper.seebug.org/3138/	seebug	news;威胁情报;	1	2024-04-01	秘鲁军方勒索事件及相关勒索组织深度分析
1172	Google paid $10 million in bug bounty rewards last year	https://www.bleepingcomputer.com/news/google/google-paid-10-million-in-bug-bounty-rewards-last-year/	bleepingcomputer	news;Google;Security;	1	2024-03-12	谷歌去年花了1 000万美元给虫子赏金
11085	Hack The Box: Rebound Machine Walkthrough – Insane Difficulty	https://threatninja.net/2024/03/hack-the-box-rebound-machine-walkthrough-insane-difficulty/	threatninja	sectest;Insane Machine;Challenges;crackmapexec;dacledit;HackTheBox;impacket;john the ripper;ldapdomaindump;libfaketime;Penetration Testing;PowerView;RemotePotato;Windows;	1	2024-03-30	黑盒:重新约束机器走过 — — 精神困难症
1169	How to Customize a Risk Register Template for Your Needs	https://securityboulevard.com/2024/03/how-to-customize-a-risk-register-template-for-your-needs/	securityboulevard	news;CISO Suite;Governance, Risk & Compliance;Security Bloggers Network;Blog Posts;risk management;	1	2024-03-12	如何定制用于您需要的风险登记册模板
9045	Sctz	http://www.ransomfeed.it/index.php?page=post_details&id_post=13857	ransomfeed	ransom;raworld;	1	2024-03-21	Sctz
1283	ZeroFox launches EASM to provide visibility and control over external assets	https://www.helpnetsecurity.com/2024/03/12/zerofox-external-attack-surface-management-easm/	helpnetsecurity	news;Industry news;ZeroFOX;	1	2024-03-12	EASM 提供对外资产的能见度和控制
12197	绿盟科技威胁周报（2024.03.25-2024.03.31）	https://blog.nsfocus.net/weeklyreport202413/	绿盟	news;威胁通告;周报;威胁防护;	1	2024-04-01	绿盟科技威胁周报（2024.03.25-2024.03.31）
11077	AT&T Data Leak: What You Need to Know and How to Protect Yourself	https://www.mcafee.com/blogs/security-news/att-data-leak-what-you-need-to-know-and-how-to-protect-yourself/	mcafee	news;Security News;	1	2024-03-30	AT&T 数据泄漏 : 您需要知道什么 以及如何保护自己
18626	Vedalia APT Group Exploits Oversized LNK Files to Deliver Malware	https://gbhackers.com/vedalia-apt-group-exploits/	GBHacker	news;Cyber Security News;Malware;	2	2024-04-08	Vedalia APT Group Explatings Explitits 为交付 Malware 的超大小 LNK 文件
1281	Rubrik EPE secures enterprise data from cyberattacks	https://www.helpnetsecurity.com/2024/03/12/rubrik-epe/	helpnetsecurity	news;Industry news;Rubrik;	1	2024-03-12	Rubrik EPE 保护企业数据免受网络攻击
11448	FreeBuf 早报 | NIST成立新联盟来运营其国家漏洞数据库；Hot Topic 遭到网络攻击	https://www.freebuf.com/news/396462.html	freebuf	news;资讯;	3	2024-03-29	FreeBuf 早报 | NIST成立新联盟来运营其国家漏洞数据库；Hot Topic 遭到网络攻击
1165	Daniel Stori’s ‘PHP v. Banana’	https://securityboulevard.com/2024/03/daniel-storis-php-v-banana/	securityboulevard	news;Humor;Security Bloggers Network;Banana;Daniel Stori;Sarcasm;satire;turnoff.us;	1	2024-03-12	Daniel Storori的`PPP诉香蕉 '
18661	新兴TOP2勒索软件！存在中国受害者的BianLian勒索软件解密原理剖析	https://xz.aliyun.com/t/14263	阿里先知实验室	news;	1	2024-04-08	新兴TOP2勒索软件！存在中国受害者的BianLian勒索软件解密原理剖析
12198	XZ-Utils工具库后门漏洞（CVE-2024-3094）通告	https://blog.nsfocus.net/xz-utilscve-2024-3094/	绿盟	news;威胁通告;安全漏洞;漏洞防护;	5	2024-04-01	XZ-Utils工具库后门漏洞（CVE-2024-3094）通告
9048	tmbsch	http://www.ransomfeed.it/index.php?page=post_details&id_post=13885	ransomfeed	ransom;lockbit3;	1	2024-03-21	tmbsch( mmbsch)
1273	哥斯拉二开-Websocket shell	https://www.freebuf.com/sectool/394065.html	freebuf	news;工具;	1	2024-03-12	哥斯拉二开-Websocket shell
12205	Hackers Using Microsoft OneNote Files to Orchestrate Cyber Attacks	https://gbhackers.com/microsoft-onenote-orchestrate/	GBHacker	news;Cyber Attack;Cyber Security News;Microsoft;cyber security;	1	2024-04-01	使用微软单注文件来指挥网络攻击的黑客
1458	Red Hat Security Advisory 2024-1244-03	https://packetstormsecurity.com/files/177533/RHSA-2024-1244-03.txt	packetstorm	vuln;;	1	2024-03-12	红帽子安保咨询 2024-1244-03
1200	Cyberattack Targets Regulator Database in South Africa	https://www.darkreading.com/cyberattacks-data-breaches/cyberattack-targets-south-african-regulator-database	darkreading	news;	1	2024-03-12	南非网络攻击目标监管数据库
9046	La-Pastina-	http://www.ransomfeed.it/index.php?page=post_details&id_post=13882	ransomfeed	ransom;ransomhub;	1	2024-03-21	拉 - 帕斯蒂纳
4771	ChatGPT vs. Gemini: Which Is Better for 10 Common Infosec Tasks?	https://www.darkreading.com/cybersecurity-operations/chatgpt-vs-gemini-which-is-better-for-10-common-infosec-tasks	darkreading	news;	1	2024-03-15	ChatGPT 诉 Gemini: 10个常见的Infesec任务哪一个更好?
1164	Control the Network, Control the Universe	https://securityboulevard.com/2024/03/control-the-network-control-the-universe/	securityboulevard	news;Security Bloggers Network;Events & Webinars;Live Webinars;	1	2024-03-12	控制网络,控制宇宙
16385	emaloncoil	http://www.ransomfeed.it/index.php?page=post_details&id_post=14125	ransomfeed	ransom;malekteam;	1	2024-04-05	含氟油
8899	How to Build a Phishing Playbook Part 3: Playbook Development	https://buaq.net/go-229512.html	buaq	newscopy;	0	2024-03-21	如何建立《钓钓鱼游览手册》第三部分:《书书发展》
19818	D-Link NAS 设备存在严重 RCE 漏洞，数万用户受到影响	https://www.freebuf.com/news/397297.html	freebuf	news;资讯;	3	2024-04-09	D-Link NAS 设备存在严重 RCE 漏洞，数万用户受到影响
1178	Acer confirms Philippines employee data leaked on hacking forum	https://www.bleepingcomputer.com/news/security/acer-confirms-philippines-employee-data-leaked-on-hacking-forum/	bleepingcomputer	news;Security;	1	2024-03-12	Acer确认菲律宾员工数据在黑客论坛泄露
1168	How Scalpers Scored Thousands of Fred again.. Tickets	https://securityboulevard.com/2024/03/how-scalpers-scored-thousands-of-fred-again-tickets/	securityboulevard	news;Security Bloggers Network;Cybersecurity;	1	2024-03-12	斯卡勒斯又如何再次收下数千张弗雷德的票。
1177	Windows KB5035849 update failing to install with 0xd000034 errors	https://www.bleepingcomputer.com/news/microsoft/windows-kb5035849-update-failing-to-install-with-0xd000034-errors/	bleepingcomputer	news;Microsoft;	1	2024-03-12	Windows KB50355849 更新未安装 0xd000034 错误
19819	卡巴斯基粉丝论坛泄露了5.7万名用户数据	https://www.freebuf.com/news/397320.html	freebuf	news;资讯;	1	2024-04-09	卡巴斯基粉丝论坛泄露了5.7万名用户数据
10014	New Phishing-as-a-Service Kit Attempts to Bypass MFA	https://blog.knowbe4.com/phishing-kit-attempts-bypass-mfa	knowbe4	news;Phishing;Security Culture;MFA;	1	2024-03-26	企图绕过外务省的新钓钓鱼服务工具包
8883	Critical flaw in Atlassian Bamboo Data Center and Server must be fixed immediately	https://buaq.net/go-229467.html	buaq	newscopy;	0	2024-03-21	Atlassian竹竹子数据中心和服务器的重大缺陷必须立即予以纠正
19846	Embracing the Cloud: Revolutionizing Privileged Access Management with One Identity Cloud PAM Essentials	https://thehackernews.com/2024/03/embracing-cloud-revolutionizing.html	feedburner	news;	1	2024-04-09	拥抱云云:以单一身份云层PAM基本需要实现特权准入管理革命化
244	Windows下SEHOP保护机制详解及其绕过	https://xz.aliyun.com/t/13992	阿里先知实验室	news;	1	2024-03-01	Windows下SEHOP保护机制详解及其绕过
8897	Smashing Security podcast #364: Bing pop-up wars, and the British Library ransomware scandal	https://buaq.net/go-229506.html	buaq	newscopy;	0	2024-03-21	Smashing安全播客#364#364:Bing爆爆战争和英国图书馆赎金软件丑闻
1282	Thrive Incident Response & Remediation helps organizations contain and remove threats	https://www.helpnetsecurity.com/2024/03/12/thrive-incident-response-remediation/	helpnetsecurity	news;Industry news;Thrive;	1	2024-03-12	突发事件反应
19849	Critical Flaws Leave 92,000 D-Link NAS Devices Vulnerable to Malware Attacks	https://thehackernews.com/2024/04/critical-flaws-leave-92000-d-link-nas.html	feedburner	news;	1	2024-04-09	关键法律留下92 000个D-链接NAS装置,易受恶意攻击伤害
19861	CVE-2024-3094: RCE Vulnerability Discovered in XZ Utils	https://securityboulevard.com/2024/04/cve-2024-3094-rce-vulnerability-discovered-in-xz-utils/	securityboulevard	news;Security Bloggers Network;Threats & Breaches;cyber attacks;Cyber awareness;Cyber Security;	3	2024-04-09	CVE-2024-3094:在XZ装置中发现的RCE脆弱性
9053	pbgbankcom	http://www.ransomfeed.it/index.php?page=post_details&id_post=13895	ransomfeed	ransom;killsec;	1	2024-03-21	Pbgbankcom 银行
1459	Red Hat Security Advisory 2024-1248-03	https://packetstormsecurity.com/files/177534/RHSA-2024-1248-03.txt	packetstorm	vuln;;	1	2024-03-12	红色帽子安保咨询2024-1248-03
1170	Tweaks Stealer Targets Roblox Users Through YouTube and Discord	https://securityboulevard.com/2024/03/tweaks-stealer-targets-roblox-users-through-youtube-and-discord/	securityboulevard	news;Security Bloggers Network;	1	2024-03-12	透过YouTube 和 Discoord,
8879	Workings of MalSync Malware Unveiled: DLL Hijacking & PHP Malware	https://gbhackers.com/workings-of-malsync-malware/	GBHacker	news;Cyber Security News;Malware;cyber security;DLL Hijacking;Malware analysis;	1	2024-03-20	MalSync Wallware Unvied: DLL 劫劫和 PHP 恶意
1162	5 more Burp extensions for API hacking	https://securityboulevard.com/2024/03/5-more-burp-extensions-for-api-hacking/	securityboulevard	news;Security Bloggers Network;API Hacking Fundamentals;API Hacking Tools;	1	2024-03-12	API黑客入侵的5个以上的 Burp 扩展 。
1167	How NIST CSF 2.0 Helps Small Businesses	https://securityboulevard.com/2024/03/how-nist-csf-2-0-helps-small-businesses/	securityboulevard	news;Security Bloggers Network;Small-to-Medium Business;	1	2024-03-12	NIST CTF 2.0 如何帮助小企业
10015	Widespread TeamCity exploitation (March ‘24)	https://threats.wiz.io/all-incidents/teamcity-exploitation	wizio	incident;	1	2024-03-26	广泛部落剥削(3月24日)
1176	Windows 11 KB5035853 update released, here's what's new	https://www.bleepingcomputer.com/news/microsoft/windows-11-kb5035853-update-released-heres-whats-new/	bleepingcomputer	news;Microsoft;Software;	1	2024-03-12	Windows 11 KB5035853 最新消息发布, 以下是新消息
20947	FreeBuf早报 | 谷歌 Chrome 新增 V8 沙盒；著名 YouTube 频道遭黑客攻击	https://www.freebuf.com/news/397295.html	freebuf	news;资讯;	1	2024-04-09	FreeBuf早报 | 谷歌 Chrome 新增 V8 沙盒；著名 YouTube 频道遭黑客攻击
255	记一次黑名单后缀+文件头双重效验的文件上传和getshell命令执行绕过	https://xz.aliyun.com/t/14030	阿里先知实验室	news;	1	2024-02-28	记一次黑名单后缀+文件头双重效验的文件上传和getshell命令执行绕过
9867	Privacy, please! Why a VPN on your smartphone may be a smart move for you.	https://www.mcafee.com/blogs/mobile-security/privacy-please-why-a-vpn-on-your-smartphone-may-be-a-smart-move-for-you/	mcafee	news;Mobile Security;VPN;Mobile vpn;Do I need vpn on my phone?;What does a VPN do for your phone;	1	2024-03-22	为什么智能手机上的VPN对你来说是个明智的举动
12219	Malicious Apps Caught Secretly Turning Android Phones into Proxies for Cybercriminals	https://thehackernews.com/2024/04/malicious-apps-caught-secretly-turning.html	feedburner	news;	2	2024-04-01	秘密将机器人手机变成网络罪犯的近身
12223	Confidence in the Cloud Starts With Visibility and Zero-Trust	https://securityboulevard.com/2024/04/confidence-in-the-cloud-starts-with-visibility-and-zero-trust/	securityboulevard	news;Cloud Security;Cybersecurity;Governance, Risk & Compliance;Identity & Access;Network Security;Security Boulevard (Original);Social - X;security;visibility;zero trust;	1	2024-04-01	以能见度和零信任为开始的云中的信心
12227	No Joke: You Can Actually Save Money on Cyber Insurance	https://securityboulevard.com/2024/04/no-joke-you-can-actually-save-money-on-cyber-insurance/	securityboulevard	news;Cyberlaw;Security Bloggers Network;cyber insurance;	1	2024-04-01	笑话:你可以在网络保险上省钱
12217	Detecting Windows-based Malware Through Better Visibility	https://thehackernews.com/2024/04/detecting-windows-based-malware-through.html	feedburner	news;	1	2024-04-01	通过更好的可见度检测基于 Windows 的恶意软件
8891	Serverless Software Development: Everything You Need to Know	https://buaq.net/go-229486.html	buaq	newscopy;	0	2024-03-21	无服务器软件开发:你需要知道的一切
8861	Two Russians sanctioned by US for alleged disinformation campaign	https://therecord.media/russians-sanctioned-disinformation-social-design-agency-company-group-structura	therecord	ransom;Government;Nation-state;News;	3	2024-03-20	两名俄罗斯人被美国制裁 罪名是进行假情报活动
16386	casio-india	http://www.ransomfeed.it/index.php?page=post_details&id_post=14126	ransomfeed	ransom;stormous;	1	2024-04-05	cassio- 内dia
22281	Attack on Consumer Electronics Manufacturer boAt Leaks Data on 7.5M Customers	https://www.darkreading.com/cyberattacks-data-breaches/indian-consumer-electronics-manufacturer-boat-leaks-data-on-7m-customers	darkreading	news;	1	2024-04-10	7.5M客户数据
16387	Aussizz-Group	http://www.ransomfeed.it/index.php?page=post_details&id_post=14127	ransomfeed	ransom;dragonforce;	1	2024-04-05	Aussizz集团
12230	The Strategic Role of AI in Governance, Risk and Compliance (GRC)	https://securityboulevard.com/2024/04/the-strategic-role-of-ai-in-governance-risk-and-compliance-grc/	securityboulevard	news;Cloud Security;Cybersecurity;Governance, Risk & Compliance;Security Boulevard (Original);Social - X;AI in Compliance;AI in Cyber Governance;AI in Risk Management;Cyber GRC;	1	2024-04-01	大赦国际在治理、风险和遵约方面的战略作用
22282	Medusa Gang Strikes Again, Hits Nearly 300 Fort Worth Property Owners	https://www.darkreading.com/cyberattacks-data-breaches/nearly-300-fort-worth-individuals-exploited-by-medusa-cybergang	darkreading	news;	1	2024-04-10	美杜萨帮再次罢工,击中近300个有价财产拥有者堡
8875	Microsoft Notifies of Major Domain Change With Teams is Coming	https://gbhackers.com/microsoft-teams-apps-domain-changes-update/	GBHacker	news;Cloud;cyber security;Microsoft;app development;Domain Migration;Microsoft Teams;	1	2024-03-20	Microsoft Notifies of Major Domain Change With Teams is Coming
10141	Mamba Architecture: What Is It and Can It Beat Transformers?	https://buaq.net/go-230692.html	buaq	newscopy;	0	2024-03-27	曼巴建筑:它是什么? 它能战胜变异体吗?
22276	Wiz Acquires Gem Security to Expand Cloud Detection and Response Offering	https://www.darkreading.com/cloud-security/wiz-acquires-gem-security-to-expand-cloud-detection-and-response-offering	darkreading	news;	1	2024-04-10	Wiz Accquires Gem 安全以扩大云探测和反应提供
12229	The AI Revolution in Access Management: Intelligent Provisioning and Fraud Prevention	https://securityboulevard.com/2024/04/the-ai-revolution-in-access-management-intelligent-provisioning-and-fraud-prevention/	securityboulevard	news;Data Security;Identity & Access;Security Bloggers Network;Access control;AI (Artificial Intelligence);Authentication;Automation;data protection;	1	2024-04-01	AI 获取管理革命:提供智能和预防欺诈
12232	Google now blocks spoofed emails for better phishing protection	https://www.bleepingcomputer.com/news/google/google-now-blocks-spoofed-emails-for-better-phishing-protection/	bleepingcomputer	news;Google;Security;	1	2024-04-01	Google现在封锁了被窃邮件,以更好地保护网络钓鱼。
8886	New Windows Server updates cause domain controller crashes, reboots	https://buaq.net/go-229478.html	buaq	newscopy;	0	2024-03-21	新 Windows 服务器更新导致域控制器崩溃, 重新启动
12222	A software supply chain meltdown: What we know about the XZ Trojan	https://securityboulevard.com/2024/04/a-software-supply-chain-meltdown-what-we-know-about-the-xz-trojan/	securityboulevard	news;Security Bloggers Network;AppSec & Supply Chain Security;	1	2024-04-01	软件供应链崩溃:我们所了解的XZTrojan
8880	AceCryptor malware has surged in Europe, researchers say	https://buaq.net/go-229463.html	buaq	newscopy;	0	2024-03-21	研究人员说,欧洲的加密软件已经涌出
8888	The 2024 Inundation of Fake Photos, Videos and Documents: And Why 2023 Was Just the Beginning	https://buaq.net/go-229483.html	buaq	newscopy;	0	2024-03-21	2024年假照片、视频和文件被淹没:为什么2023年才刚刚开始
16384	Doctorim	http://www.ransomfeed.it/index.php?page=post_details&id_post=14124	ransomfeed	ransom;malekteam;	1	2024-04-05	博士博士学位
22280	How Nation-State DDoS Attacks Impact Us All	https://www.darkreading.com/cyberattacks-data-breaches/how-nation-state-ddos-attacks-impact-us-all	darkreading	news;	1	2024-04-10	国家DDoS攻击如何影响我们所有人
12231	Webinar Recap: Cybersecurity Trends to Watch in 2024	https://securityboulevard.com/2024/04/webinar-recap-cybersecurity-trends-to-watch-in-2024/	securityboulevard	news;Security Bloggers Network;AI;Blog;Business of Cyber;Threats and Trends;trends;	1	2024-04-01	网络安全趋势:2024年网络安全趋势观察
8876	NCSC Released an Advisory to Secure Cloud-hosted SCADA	https://gbhackers.com/ncsc-released-an-advisory-to-secure-cloud-hosted-scada/	GBHacker	news;cyber security;Cyber Security News;computer security;	1	2024-03-20	NCSC 发布了 " 保证云托管安全咨询 " 方案。
9874	OpenVPN-GUI-AS - OpenVPN with API for your company	https://www.nu11secur1ty.com/2024/03/openvpn-gui-as-openvpn-with-api-for.html	nu11security	vuln;	1	2024-03-25	OpenVPN-GUI-AS - OpenVPN 公司使用API 的 OpenVPN
8566	Synopsys fAST Dynamic enables DevOps teams to fix security vulnerabilities in modern web apps	https://www.helpnetsecurity.com/2024/03/19/synopsys-fast-dynamic-enables-devops-teams-to-fix-security-vulnerabilities-in-modern-web-apps/	helpnetsecurity	news;Industry news;Synopsys;	1	2024-03-19	FAST动态使DevOps团队能够在现代网络应用程序中修补安全弱点
3454	SIM swappers hijacking phone numbers in eSIM attacks	https://www.bleepingcomputer.com/news/security/sim-swappers-hijacking-phone-numbers-in-esim-attacks/	bleepingcomputer	news;Security;	1	2024-03-14	在eSIM攻击中劫持电话号码
9940	COURT DOC: Seven Hackers Associated with Chinese Government Charged with Computer Intrusions Targeting Perceived Critics of China and U.S. Businesses and Politicians	https://buaq.net/go-230427.html	buaq	newscopy;	0	2024-03-26	与中国政府有联系的七家黑客公司,负责中国和美国商界和政界人士的计算机入侵活动。
12225	HYAS Threat Intel Report April 1 2024	https://securityboulevard.com/2024/04/hyas-threat-intel-report-april-1-2024/	securityboulevard	news;Security Bloggers Network;	1	2024-04-01	HYAS 威胁英特尔报告 2024年4月1日
12226	Millions Impacted in Mass Passcode Reset of AT&T Accounts	https://securityboulevard.com/2024/04/millions-impacted-in-mass-passcode-reset-of-att-accounts/	securityboulevard	news;Data Security;Security Bloggers Network;Threats & Breaches;Cybersecurity;Data breaches;	1	2024-04-01	百万人受到AT&T账户质量密码重置的影响
10704	Market Forces vs. Regulation: How to Drive IT Product Safety	https://securityboulevard.com/2024/03/market-forces-vs-regulation-how-to-drive-it-product-safety/	securityboulevard	news;Security Bloggers Network;Live Webinars;	1	2024-03-29	市场力量对监管:如何驱动信息技术产品安全
10700	‘Darcula’ PhaaS Campaign Sinks Fangs into Victims	https://securityboulevard.com/2024/03/darcula-phaas-campaign-sinks-fangs-into-victims/	securityboulevard	news;Cloud Security;Cybersecurity;Data Security;Endpoint;Featured;Industry Spotlight;Malware;Mobile Security;News;Security Boulevard (Original);Social - Facebook;Social - LinkedIn;Social - X;Social Engineering;Spotlight;Threat Intelligence;Phishing-as-a-Service (PhaaS);postal service;RaaS;	1	2024-03-29	`Darcula ' PhaaS " 救教运动将爱爱的芳芳转向受害者
9869	先知安全沙龙(成都站) - Windows驱动自动化漏洞挖掘系统设计与实践	https://xz.aliyun.com/t/14183	阿里先知实验室	news;	3	2024-03-25	先知安全沙龙(成都站) - Windows驱动自动化漏洞挖掘系统设计与实践
1234	Microsoft Discloses Critical Hyper-V Flaws in Low-Volume Patch Update	https://www.darkreading.com/vulnerabilities-threats/microsoft-discloses-two-critical-hyper-v-flaws-low-volume-patch-update	darkreading	news;	1	2024-03-12	微软 Microsoft 在低排补丁更新中披露 关键超V 条状
10654	Hilary Clinton: AI and deepfakes pose a ‘totally different type of threat’	https://buaq.net/go-231165.html	buaq	newscopy;	0	2024-03-29	Hilary Clinton:大赦国际和深刻的假象构成了“完全不同的威胁类型”。
9056	Industrial-de-Alimentos-EYL-SA	http://www.ransomfeed.it/index.php?page=post_details&id_post=13898	ransomfeed	ransom;ransomhub;	1	2024-03-21	Industrial-de-Alimentos-EYL-SA
11752	Bombshell in SSH servers! What CVE-2024-3094 means for Kubernetes users	https://securityboulevard.com/2024/03/bombshell-in-ssh-servers-what-cve-2024-3094-means-for-kubernetes-users/	securityboulevard	news;Security Bloggers Network;K8s Security;K8s Vulnerabilities;	3	2024-03-31	SSH 服务器中的轰炸贝壳! CVE 2024-3094 对 Kubernetes 用户意味着什么 ?
8469	White House and EPA warn of hackers breaching water systems	https://www.bleepingcomputer.com/news/security/white-house-and-epa-warn-of-hackers-breaching-water-systems/	bleepingcomputer	news;Security;	1	2024-03-19	白宫和环保局警告黑客破坏供水系统
12228	Strong Passwords: A Keystone of Cybersecurity for Water and Wastewater Infrastructure	https://securityboulevard.com/2024/04/strong-passwords-a-keystone-of-cybersecurity-for-water-and-wastewater-infrastructure/	securityboulevard	news;Data Security;Security Bloggers Network;Threats & Breaches;Cybersecurity;Data breaches;NIST 800-63;Regulation and Compliance;	1	2024-04-01	强有力的密码:水和废水基础设施网络安全的基石
10698	10 Must-Have Elements for an Air-Tight IT Security Policy	https://securityboulevard.com/2024/03/10-must-have-elements-for-an-air-tight-it-security-policy/	securityboulevard	news;Security Bloggers Network;articles;	1	2024-03-29	空中对空信息技术安全政策必须具备的10个要素
4713	独家授权！广东盈世获网易邮箱反垃圾服务的独家授权，邮件反垃圾更全面	https://buaq.net/go-228273.html	buaq	newscopy;	0	2024-03-15	独家授权！广东盈世获网易邮箱反垃圾服务的独家授权，邮件反垃圾更全面
4903	mapXplore - Allow Exporting The Information Downloaded With Sqlmap To A Relational Database Like Postgres And Sqlite	http://www.kitploit.com/2024/03/mapxplore-allow-exporting-information.html	kitploit	tool;mapXplore;PostgreSQL;SQLite;SQLMap;	1	2024-03-17	地图Xplore - 允许将用 Sqlmap 下载的信息导出到像 Postgres 和 Sqlite 一样的关系数据库
16390	TermoPlastic-SRL	http://www.ransomfeed.it/index.php?page=post_details&id_post=14133	ransomfeed	ransom;ciphbit;	1	2024-04-06	电磁-SRL
16389	Better-Accounting-Solutions-	http://www.ransomfeed.it/index.php?page=post_details&id_post=14132	ransomfeed	ransom;ransomhub;	1	2024-04-06	更好的问责解决方案
16388	truehomescom	http://www.ransomfeed.it/index.php?page=post_details&id_post=14129	ransomfeed	ransom;lockbit3;	1	2024-04-05	真正的家庭之家
10684	New Linux Bug Could Lead to User Password Leaks and Clipboard Hijacking	https://thehackernews.com/2024/03/new-linux-bug-could-lead-to-user.html	feedburner	news;	1	2024-03-29	新建 Linux 错误可能导致用户密码漏漏和剪贴板劫劫
3416	Comic Agilé – Mikkel Noe-Nygaard, Luxshan Ratnaravi – #282 – ReadMe	https://securityboulevard.com/2024/03/comic-agile-mikkel-noe-nygaard-luxshan-ratnaravi-282-readme/	securityboulevard	news;DevOps;Security Bloggers Network;Agile;Comics – Comic Agilé;DEVOPS;DevOps Satire;Luxshan Ratnaravi;Mikkel Noe-Nygaard;	1	2024-03-14	科米克·阿吉莱 — — 米克克尔·诺-内加尔德、卢克斯山·拉特纳拉维 — —
12262	Must-Read New Study on Russian Propaganda Techniques	https://blog.knowbe4.com/must-read-new-study-on-russian-propaganda-techniques	knowbe4	news;Social Engineering;Russia;Disinformation;	3	2024-04-01	关于俄罗斯宣传技术的必须读的新研究
12266	Thread Hijacking Phishing Attack Targets Pennsylvania Journalist	https://blog.knowbe4.com/thread-hijacking-phishing-targets-journalist	knowbe4	news;Phishing;Security Culture;	1	2024-04-01	宾夕法尼亚州记者
12295	CTF比赛中JWT漏洞的利用	https://xz.aliyun.com/t/14214	阿里先知实验室	news;	3	2024-04-01	CTF比赛中JWT漏洞的利用
12296	免杀手法大总结（入门向）	https://xz.aliyun.com/t/14215	阿里先知实验室	news;	1	2024-04-01	免杀手法大总结（入门向）
12300	The Incognito Mode Myth Has Fully Unraveled	https://www.wired.com/story/google-chrome-incognito-mode-data-deletion-settlement/	wired	news;Security;Security / Privacy;Security / Security News;	1	2024-04-01	怪兽模式神话完全未受干扰
12303	RDP remains a security concern – Week in security with Tony Anscombe	https://www.welivesecurity.com/en/videos/rdp-security-concern-week-security-tony-anscombe/	eset	news;	1	2024-03-29	RDP仍是一个安全问题 — — 与Tony Ascombe的“安全周”
12315	Gibbon 26.0.00 Server-Side Template Injection / Remote Code Execution	https://cxsecurity.com/issue/WLB-2024040001	cxsecurity	vuln;	1	2024-04-01	Gibbon 26.0.00 服务器- Side 模板喷射/远程代码执行
12316	BioTime Directory Traversal / Remote Code Execution	https://cxsecurity.com/issue/WLB-2024040002	cxsecurity	vuln;	1	2024-04-01	生物时间目录Traversal/远程代码执行
12317	ARIS: Business Process Management 10.0.21.0 Cross Site Scripting	https://cxsecurity.com/issue/WLB-2024040003	cxsecurity	vuln;	1	2024-04-01	10.0.21.0 跨地点脚本
12318	OpenCart Core 'search' - Blind SQLi	https://cxsecurity.com/issue/WLB-2024040004	cxsecurity	vuln;	1	2024-04-01	OpenCart 核心“ 搜索” - 盲 SQLi
12319	Rapid7 nexpose vulnerability management software - 'nexposeconsole' Unquoted Service Path	https://cxsecurity.com/issue/WLB-2024040005	cxsecurity	vuln;	1	2024-04-01	Rapid 7 内附脆弱程度管理软件 - “ 排除容留 ” 未引用的服务路径
12320	Workout Journal App 1.0 Cross Site Scripting	https://cxsecurity.com/issue/WLB-2024040006	cxsecurity	vuln;	1	2024-04-01	《日刊》第1.0号 跨站点脚本
12334	Red Hat Security Advisory 2024-1576-03	https://packetstormsecurity.com/files/177858/RHSA-2024-1576-03.txt	packetstorm	vuln;;	1	2024-04-01	红色帽子安保咨询2024-1576-03
16408	多部门联合破获虚拟货币欺诈案，涉案资金达 20 亿	https://www.freebuf.com/news/397037.html	freebuf	news;资讯;	1	2024-04-07	多部门联合破获虚拟货币欺诈案，涉案资金达 20 亿
12336	ghba PTR Record Scanner	https://packetstormsecurity.com/files/177860/ghba.tgz	packetstorm	vuln;;	1	2024-04-01	ghba PTR 记录扫描器
10690	The Golden Age of Automated Penetration Testing is Here	https://thehackernews.com/2024/03/the-golden-age-of-automated-penetration.html	feedburner	news;	1	2024-03-29	这里是自动穿透测试的黄金时代
16391	On-Q-Financial-LLC	http://www.ransomfeed.it/index.php?page=post_details&id_post=14134	ransomfeed	ransom;bianlian;	1	2024-04-06	Q-财务- LLC
12337	Debian Security Advisory 5650-1	https://packetstormsecurity.com/files/177861/dsa-5650-1.txt	packetstorm	vuln;;	1	2024-04-01	Debian安全咨询 5650-1
12338	Linux nf_tables Local Privilege Escalation	https://packetstormsecurity.com/files/177862/CVE-2024-1086-main.zip	packetstorm	vuln;;	1	2024-04-01	Linux nf_ables 本地特权升级
12339	ARIS: Business Process Management 10.0.21.0 Cross Site Scripting	https://packetstormsecurity.com/files/177863/arisbpm10210-xss.txt	packetstorm	vuln;;	1	2024-04-01	10.0.21.0 跨地点脚本
12340	Gentoo Linux Security Advisory 202403-04	https://packetstormsecurity.com/files/177864/glsa-202403-04.txt	packetstorm	vuln;;	1	2024-04-01	Gentoo Linux 安保咨询 2024003-04
12341	WordPress Gutenberg 18.0.0 Cross Site Scripting	https://packetstormsecurity.com/files/177865/wpgutenberg1800-xss.txt	packetstorm	vuln;;	1	2024-04-01	18.0.0 跨站点脚本
12342	Debian Security Advisory 5651-1	https://packetstormsecurity.com/files/177866/dsa-5651-1.txt	packetstorm	vuln;;	1	2024-04-01	Debian安全咨询 5651-1
12343	Packet Storm New Exploits For March, 2024	https://packetstormsecurity.com/files/177867/202403-exploits.tgz	packetstorm	vuln;;	1	2024-04-01	2024年3月的新爆炸
12346	Losses linked to impersonation scams top $1 billion yearly, FTC says	https://therecord.media/impersonation-scam-losses-top-1-billion	therecord	ransom;Cybercrime;News;News Briefs;	1	2024-04-01	与冒冒名骗骗案相关的损失每年高达10亿美元,
12347	Prudential Insurance says data of 36,000 exposed during February cyberattack	https://therecord.media/prudential-discloses-new-information-from-february-incident	therecord	ransom;Cybercrime;News;News Briefs;	1	2024-04-02	谨慎保险公司说 2月网络攻击期间 暴露了36000人的数据
12250	India Repatriates Citizens Duped Into Forced Cyber Fraud Labor in Cambodia	https://www.darkreading.com/cyberattacks-data-breaches/india-repatriates-citizens-duped-into-forced-cyber-fraud-cambodia	darkreading	news;	1	2024-04-01	印度遣返柬埔寨公民,
12252	Sprawling Sellafield Nuclear Waste Site Prosecuted for Cybersecurity Failings	https://www.darkreading.com/ics-ot-security/sellafield-nuclear-waste-site-prosecuted-cybersecurity-failings	darkreading	news;	1	2024-04-01	为网络安全失灵而起诉的Sellafield核废料场地
12253	AT&amp;T Confirms 73M Customers Affected in Data Leak	https://www.darkreading.com/remote-workforce/att-confirms-73m-customers-affected-data-leak	darkreading	news;	1	2024-04-01	AT&T 确认 73M 受数据泄漏影响的客户
12254	Cybercriminals Weigh Options for Using LLMs: Buy, Build, or Break?	https://www.darkreading.com/threat-intelligence/cybercriminals-options-lms-buy-build-break	darkreading	news;	1	2024-04-01	网络罪犯使用LLMS的微小选项:买、建还是断?
12257	Collaboration Needed to Fight Ransomware	https://www.darkreading.com/vulnerabilities-threats/collaboration-needed-to-fight-ransomware	darkreading	news;	2	2024-04-01	需要协作打击暖器
12260	Your KnowBe4 Compliance Plus Fresh Content Updates from March 2024	https://blog.knowbe4.com/knowbe4-cmp-content-updates-march-2024	knowbe4	news;Security Awareness Training;KnowBe4;Compliance;	1	2024-04-01	您的KnowBe4 遵章加新内容更新自2024年3月
16392	Madero	http://www.ransomfeed.it/index.php?page=post_details&id_post=14136	ransomfeed	ransom;qilin;	1	2024-04-06	马德罗
12453	xz工具供应链后门事件 紧急处理	https://www.freebuf.com/sectool/396616.html	freebuf	news;工具;	1	2024-04-01	xz工具供应链后门事件 紧急处理
12356	Activision Players Attacked by Password Stealing Malware: Investigation In Progress	https://gbhackers.com/activision-players-attacked-by-malware/	GBHacker	news;Cyber Security News;Malware;	1	2024-04-01	被密码窃窃恶意:调查进展中
12333	Gibbon 26.0.00 Server-Side Template Injection / Remote Code Execution	https://packetstormsecurity.com/files/177857/Gibbon_SSTI_to_RCE_PoC.py.txt	packetstorm	vuln;;	1	2024-04-01	Gibbon 26.0.00 服务器- Side 模板喷射/远程代码执行
12344	‘Cybercrime organization’ stole customer and employee data, boating giant says	https://therecord.media/cybercrime-organization-stole-customer-data-sec-marinemax	therecord	ransom;News;Cybercrime;	1	2024-04-01	" 网络犯罪组织 " 偷窃客户和雇员数据,船船巨头说
12348	Vulnerability database backlog due to increased volume, changes in 'support,' NIST says	https://therecord.media/vulnerability-database-backlog-nist-support	therecord	ransom;News;Industry;Government;Technology;	1	2024-04-01	由数量增加、“支持”的变更而导致的脆弱性数据库积压。
12352	Drozer - The Leading Security Assessment Framework For Android	http://www.kitploit.com/2024/04/drozer-leading-security-assessment.html	kitploit	tool;ADB;Android;Dalvik;Drozer;Framework;java;Linux;Malware;Mwr;Protobuf;Python;vulnerabilities;Windows;	2	2024-04-01	Drozer - Android的主要安全评估框架
12249	XZ Utils Backdoor Implanted in Carefully Executed, Multiyear Supply Chain Attack	https://www.darkreading.com/cyber-risk/xz-utils-backdoor-implanted-in-intricate-multi-year-supply-chain-attack	darkreading	news;	1	2024-04-01	XZ 工具后门植入的精心执行、多年供应链攻击
12259	Despite Cybersecurity Improvements in UK Organizations, Attacks Still Persist	https://blog.knowbe4.com/despite-cybersecurity-improvements-uk-organizations-attacks-persist	knowbe4	news;Phishing;Security Awareness Training;Security Culture;	1	2024-04-01	尽管英国组织网络安全有所改善,
12360	Imperva Web Application Firewall Flaw Let Attackers Bypass WAF Rules	https://gbhackers.com/imperva-waf-flaw-bypass-security/	GBHacker	news;CVE/vulnerability;Cyber Attack;Cyber Security News;Firewall;Imperva WAF Vulnerability;Security Flaw Exploitation;	1	2024-04-01	Imperva Web 应用程序 Firewalf Flaw 让攻击者绕过WAF规则
12362	Ross Anderson, Professor & Author of ‘Security Engineering’ Book passes away	https://gbhackers.com/ross-anderson-passes-away/	GBHacker	news;cyber security;Cyber Security News;	1	2024-04-01	Ross Anderson, " 安全工程 " 书的教授和作者
12365	Werewolf Hackers Exploiting WinRAR Vulnerability To Deploy RingSpy Backdoor	https://gbhackers.com/werewolf-hackers-winrar-vulnerability/	GBHacker	news;cyber security;Malware;Phishing;Cyber Security News;phishing;	1	2024-04-01	狼人黑客利用WinRAR的弱点 来部署后门环 Spy Spy
12357	Backdoor in upstream xz/liblzma Let Attackers Hack SSH Servers	https://gbhackers.com/backdoor-in-upstream-xz-liblzma/	GBHacker	news;cyber security;Cyber Security News;web server;	1	2024-04-01	上层 xz/ liblzma 的后门 Let 攻击者 Hack SSH 服务器
12388	Unearthing Identity Threat Exposures	https://securityboulevard.com/2024/04/unearthing-identity-threat-exposures/	securityboulevard	news;Careers;Identity & Access;Security Awareness;Security Bloggers Network;Blog;identity security;Identity Theft;identity underground report;	1	2024-04-01	身份威胁暴露
12395	India rescues 250 citizens enslaved by Cambodian cybercrime gang	https://www.bleepingcomputer.com/news/security/india-rescues-250-citizens-enslaved-by-cambodian-cybercrime-gang/	bleepingcomputer	news;Security;	1	2024-04-01	印度营救250名被柬埔寨网络犯罪团伙奴役的公民
12451	自然资源部发布《自然资源领域数据安全管理办法》	https://www.freebuf.com/news/396689.html	freebuf	news;资讯;	1	2024-04-01	自然资源部发布《自然资源领域数据安全管理办法》
9802	Japan Runs Inaugural Cyber Defense Drills With Pacific Island Nations	https://www.darkreading.com/cyber-risk/japan-runs-inaugural-cyber-defense-drills-with-pacific-island-nations	darkreading	news;	1	2024-03-25	日本与太平洋岛国一起运行创世网络防御钻井
24377	Sisense Password Breach Triggers 'Ominous' CISA Warning	https://www.darkreading.com/threat-intelligence/sisense-breach-triggers-cisa-password-reset-advisory	darkreading	news;	1	2024-04-11	Sisense 密码破解触发器“ Ominous ” CISA 警告
12436	aerodynamicinccom	http://www.ransomfeed.it/index.php?page=post_details&id_post=14052	ransomfeed	ransom;cactus;	1	2024-04-01	空气动力学
12437	besttranscom	http://www.ransomfeed.it/index.php?page=post_details&id_post=14053	ransomfeed	ransom;cactus;	1	2024-04-01	最佳互换
12438	anwaltskanzlei-kaufbeurende	http://www.ransomfeed.it/index.php?page=post_details&id_post=14054	ransomfeed	ransom;lockbit3;	1	2024-04-01	anwaltskanzenzlei-kaufbeurende 国家
12439	pdq-airsparescouk	http://www.ransomfeed.it/index.php?page=post_details&id_post=14055	ransomfeed	ransom;blackbasta;	1	2024-04-01	Pdq-空气公园
8644	USENIX Security ’23 – Abderrahmen Amich, Birhanu Eshete, Vinod Yegneswaran, Nguyen Phong Hoang – DeResistor: Toward Detection-Resistant Probing for Evasion Of Internet Censorship	https://buaq.net/go-229101.html	buaq	newscopy;	0	2024-03-20	USENIX 安全 23 — — Abderrahmen Amich, Birhanu Eshete, Vinod Yegneswaran, Nguyen Phong Hoang — — 捍卫者:为逃避互联网审查而寻求侦察-较远探查
10870	FreeBuf 周报 | Gartner公布2024年网络安全预测；《银行业数据资产估值指南》发布	https://www.freebuf.com/news/396351.html	freebuf	news;资讯;	1	2024-03-29	FreeBuf 周报 | Gartner公布2024年网络安全预测；《银行业数据资产估值指南》发布
12523	JumpServer远程代码执行漏洞（CVE-2024-29201/CVE-2024-29202）通告	https://blog.nsfocus.net/jumpservercve-2024-29201-cve-2024-29202/	绿盟	news;威胁通告;安全漏洞;漏洞防护;	5	2024-04-02	JumpServer远程代码执行漏洞（CVE-2024-29201/CVE-2024-29202）通告
13903	liblzmaxz被植入后门，过程堪比谍战片！	https://www.freebuf.com/articles/network/396687.html	freebuf	news;网络安全;	1	2024-04-01	System error
13904	传统渗透测试爆破有困难？	https://www.freebuf.com/articles/web/396629.html	freebuf	news;Web安全;	1	2024-04-01	System error
13901	对美国防部《2025财年国防预算申请报告》分析和解读	https://www.freebuf.com/articles/neopoints/396619.html	freebuf	news;观点;	1	2024-04-01	System error
13937	针对某黑产组织钓鱼攻击样本分析	https://xz.aliyun.com/t/14226	阿里先知实验室	news;	1	2024-04-02	System error
13902	对《关于在欧盟全境实现高度统一网络安全措施的指令》 的分析和思考	https://www.freebuf.com/articles/neopoints/396621.html	freebuf	news;观点;	1	2024-04-01	System error
14651	FreeBuf 早报 | 首次全国数据工作会议召开；网安独角兽Rubrik赴美IPO	https://www.freebuf.com/news/396810.html	freebuf	news;资讯;	1	2024-04-02	FreeBuf 早报 | 首次全国数据工作会议召开；网安独角兽Rubrik赴美IPO
14624	Authentic8 launches Silo Shield Program to Protect High-Risk Communities in Partnership with CISA	https://gbhackers.com/authentic8/	GBHacker	news;cyber security;Press Release;computer security;	1	2024-04-02	真实8 与独联体国家情报和安全局合作,为保护高风险群体而启动筒状盾牌方案
13905	2980邮箱多种类验证码逆向	https://www.freebuf.com/articles/web/396686.html	freebuf	news;Web安全;	1	2024-04-01	System error
12279	FreeBuf 早报 | 攻击者利用选举窃取俄罗斯人个人信息；黑客针对 macOS 用户投放恶意广告	https://www.freebuf.com/news/396653.html	freebuf	news;资讯;	1	2024-04-01	FreeBuf 早报 | 攻击者利用选举窃取俄罗斯人个人信息；黑客针对 macOS 用户投放恶意广告
12224	The Cybersecurity Industry Starts Picking Through Malicious XZ Utils Code	https://securityboulevard.com/2024/04/cybersecurity-industry-starts-picking-through-malicious-xz-utils-code/	securityboulevard	news;Cybersecurity;Data Security;DevOps;Featured;Incident Response;Industry Spotlight;Malware;Mobile Security;Network Security;News;Security Boulevard (Original);Social - Facebook;Social - LinkedIn;Social - X;Spotlight;Threat Intelligence;Vulnerabilities;Linux;open source code;software supply chain attack;	1	2024-04-01	网络安全产业开始通过恶意的 XZ 工具代码
14623	4 Incident Triage Best Practices for Your Organization in 2024	https://gbhackers.com/4-incident-triage-best-practices-for-your-organization/	GBHacker	news;cyber security;Cyber Security News;	1	2024-04-02	4 2024年为贵组织举办的事故外逃事件最佳做法
10687	PyPI Halts Sign-Ups Amid Surge of Malicious Package Uploads Targeting Developers	https://thehackernews.com/2024/03/pypi-halts-sign-ups-amid-surge-of.html	feedburner	news;	1	2024-03-29	PyPI 在恶意套件上传目标开发者的激增中停止签名
12289	Watch Out For IRS Scams and Avoid Identity Theft	https://www.mcafee.com/blogs/privacy-identity-protection/tax-season-scams-identity-theft/	mcafee	news;Internet Security;Privacy & Identity Protection;identity theft;data protection;cybersafety;cybersecurity;	1	2024-04-01	注意 IRS scams 和避免身份盗窃
10702	Guarding Education: The Impact of Compromised Credentials	https://securityboulevard.com/2024/03/guarding-education-the-impact-of-compromised-credentials/	securityboulevard	news;Security Bloggers Network;credential screening;Cybersecurity;edtech;	1	2024-03-29	保护教育: 侵蚀的全权证书的影响
13908	9n-triton部署bert模型实战经验	https://www.freebuf.com/news/396573.html	freebuf	news;资讯;	1	2024-04-01	System error
12781	Cloud Active Defense: Open-source cloud protection	https://www.helpnetsecurity.com/2024/04/02/cloud-active-defense-open-source-cloud-protection/	helpnetsecurity	news;Don't miss;Hot stuff;News;cloud security;GitHub;open source;software;	1	2024-04-02	云层主动防御:开放源云保护
14198	大模型安全的融合与挑战 | FreeBuf 企业安全俱乐部·广州站议题前瞻	https://www.freebuf.com/fevents/396736.html	freebuf	news;活动;	1	2024-04-02	大模型安全的融合与挑战 | FreeBuf 企业安全俱乐部·广州站议题前瞻
14262	Harnessing the Power of CTEM for Cloud Security	https://thehackernews.com/2024/04/harnessing-power-of-ctem-for-cloud.html	feedburner	news;	1	2024-04-02	利用CTEM的力量来保证云层安全
13989	Navigating the PHP 7.4 End of Life: A Retrospective Analysis	https://securityboulevard.com/2024/04/navigating-the-php-7-4-end-of-life-a-retrospective-analysis/	securityboulevard	news;Security Bloggers Network;Extended Lifecycle Support;Navigating the PHP 7.4;PHP 7.4 end of life;PHP 7.4 EOL;	1	2024-04-02	PHP 7.4 生命结束:回溯性分析
14630	5 Major Phishing Campaigns in March 2024	https://gbhackers.com/phishing-campaigns/	GBHacker	news;Cyber Attack;Malware;Phishing;What is;Cyber Security News;phishing;	1	2024-04-02	5. 2024年3月5日的重大钓鱼运动
14170	VolWeb - A Centralized And Enhanced Memory Analysis Platform	http://www.kitploit.com/2024/04/volweb-centralized-and-enhanced-memory.html	kitploit	tool;Forensics;Linux;Scripts;Teams;Volatility;VolWeb;Windows;	1	2024-04-02	VolWeb - 一个集中和增强的记忆分析平台
13992	The Best SIEM Tools To Consider in 2024	https://securityboulevard.com/2024/04/the-best-siem-tools-to-consider-in-2024/	securityboulevard	news;Security Bloggers Network;Blog;Topic;	1	2024-04-02	2024年考虑的SIMEM最佳工具
12628	73% brace for cybersecurity impact on business in the next year or two	https://www.helpnetsecurity.com/2024/04/02/cybersecurity-risks-readiness-level/	helpnetsecurity	news;News;Cisco;cyber risk;cybersecurity;report;strategy;survey;	1	2024-04-02	73%的网络安全对下一年或第二年商业影响的牙套
14181	Google to Delete Billions of User’s Personal Data Collected Via Chrome Browser	https://gbhackers.com/google-to-delete-personal-data/	GBHacker	news;Cyber Security News;Google;cyber security;	1	2024-04-02	谷歌删除数十亿用户个人数据收集的Via Chrome浏览器
10706	Q1 2024 Success Services Use Cases	https://securityboulevard.com/2024/03/q1-2024-success-services-use-cases/	securityboulevard	news;Security Bloggers Network;Success Services;	1	2024-03-29	问题1 2024 成功服务使用案例
10707	Strengthening Security in Distributed Payment Systems: Exploring Innovative Solutions	https://securityboulevard.com/2024/03/strengthening-security-in-distributed-payment-systems-exploring-innovative-solutions/	securityboulevard	news;Security Bloggers Network;Financial Instant Issuance;	1	2024-03-29	加强分配付款系统的安全:探索创新解决办法
10708	Google Podcasts service shuts down in the US next week	https://www.bleepingcomputer.com/news/google/google-podcasts-service-shuts-down-in-the-us-next-week/	bleepingcomputer	news;Google;Software;	1	2024-03-29	下星期美国Google播客服务关闭
10710	Activision: Enable 2FA to secure accounts recently stolen by malware	https://www.bleepingcomputer.com/news/security/activision-enable-2fa-to-secure-accounts-recently-stolen-by-malware/	bleepingcomputer	news;Security;CryptoCurrency;Gaming;	1	2024-03-29	缩略语: 使2FA能够安全最近被恶意软件窃取的账户
10717	Red Hat warns of backdoor in XZ tools used by most Linux distros	https://www.bleepingcomputer.com/news/security/red-hat-warns-of-backdoor-in-xz-tools-used-by-most-linux-distros/	bleepingcomputer	news;Security;	1	2024-03-29	红色帽子警告大多数Linux变异器使用的 XZ 工具的后门警告
12746	Funding the Organizations Securing the Internet	https://www.darkreading.com/vulnerabilities-threats/	darkreading	news;	1	2024-04-02	资助确保互联网安全的组织
10726	Cloud Email Filtering Bypass Attack Works 80% of the Time	https://www.darkreading.com/cloud-security/cloud-email-filtering-bypass-attack	darkreading	news;	1	2024-03-29	云层邮件过滤绕过攻击工程 80%的时间
10733	UN Peace Operations Under Fire From State-Sponsored Hackers	https://www.darkreading.com/cyber-risk/un-peace-operations-under-fire-from-state-sponsored-hackers	darkreading	news;	1	2024-03-29	受国家赞助的黑客火力攻击的联合国和平行动
10744	Iran's Evolving Cyber-Enabled Influence Operations to Support Hamas	https://www.darkreading.com/cybersecurity-operations/iran-s-evolving-cyber-enabled-influence-operations-to-support-hamas	darkreading	news;	3	2024-03-29	伊朗不断演变的网络连网连网影响行动 支持哈马斯
10748	TheMoon Malware Rises Again with Malicious Botnet for Hire	https://www.darkreading.com/endpoint-security/themoon-malware-rises-malicious-botnet-for-hire	darkreading	news;	1	2024-03-29	月亮 Mamalware 再次崛起 与恶意的植物网为 hire
10749	Lessons From the LockBit Takedown	https://www.darkreading.com/threat-intelligence/lessons-from-the-lockbit-takedown	darkreading	news;	2	2024-03-29	从LockBit上缴中吸取的教训
10752	Are You Affected by the Backdoor in XZ Utils?	https://www.darkreading.com/vulnerabilities-threats/are-you-affected-by-the-backdoor-in-xz-utils	darkreading	news;	1	2024-03-29	你是否受到 XZ 工程的后门的影响?
10753	Geopolitical Conflicts: 5 Ways to Cushion the Blow	https://www.darkreading.com/vulnerabilities-threats/geopolitical-conflicts-5-ways-to-cushion-the-blow	darkreading	news;	1	2024-03-29	地缘政治冲突:5种方法
12773	漏洞挖掘 | 如何利用CDN升级你的XSS	https://www.freebuf.com/vuls/396433.html	freebuf	news;漏洞;	3	2024-03-29	漏洞挖掘 | 如何利用CDN升级你的XSS
2961	FreeBuf 早报 | 美国23年因网络犯罪损失125亿美元；印度某金融公司泄露3TB用户数据	https://www.freebuf.com/news/394697.html	freebuf	news;资讯;	1	2024-03-13	FreeBuf 早报 | 美国23年因网络犯罪损失125亿美元；印度某金融公司泄露3TB用户数据
3377	现已修复！微软 SmartScreen 漏洞被用于分发 DarkGate 恶意软件	https://buaq.net/go-228045.html	buaq	newscopy;	0	2024-03-14	现已修复！微软 SmartScreen 漏洞被用于分发 DarkGate 恶意软件
10725	CISO Corner: Cyber-Pro Swindle; New Faces of Risk; Cyber Boosts Valuation	https://www.darkreading.com/cloud-security/ciso-corner-cyber-pro-swindle-risk-valuation	darkreading	news;	1	2024-03-29	CISO角:网络-Pro Swindle;风险的新面孔;网络促动估值
10699	A(nother) Ransomware Saga with a Twist	https://securityboulevard.com/2024/03/another-ransomware-saga-with-a-twist/	securityboulevard	news;Security Bloggers Network;Threats & Breaches;Blackcat;cyberattack;healthcare;Linux & Open Source News;ransomware attack;	2	2024-03-29	A(其他) 带Twist 的Ransomware Saga
10825	PT-Bank-Pembangunan-Daerah-Banten-Tbk	http://www.ransomfeed.it/index.php?page=post_details&id_post=14005	ransomfeed	ransom;medusa;	1	2024-03-27	PT-Pembangunan银行-Daerah银行-Banten-Tbk银行
10826	anovahealthcom	http://www.ransomfeed.it/index.php?page=post_details&id_post=14006	ransomfeed	ransom;lockbit3;	1	2024-03-27	创新健康公司
10827	Otolaryngology-Associates	http://www.ransomfeed.it/index.php?page=post_details&id_post=14007	ransomfeed	ransom;incransom;	1	2024-03-27	臭氧学协会
10828	Exela-Technologies	http://www.ransomfeed.it/index.php?page=post_details&id_post=14009	ransomfeed	ransom;hunters;	1	2024-03-28	Exela技术
10829	Reeves-Wiedeman	http://www.ransomfeed.it/index.php?page=post_details&id_post=14010	ransomfeed	ransom;bianlian;	1	2024-03-28	里韦斯- Wiedeman
10830	Florida-Memorial-University	http://www.ransomfeed.it/index.php?page=post_details&id_post=14011	ransomfeed	ransom;incransom;	1	2024-03-28	佛罗里达-纪念大学
10831	Neurobehavioral-Medicine-Consultants	http://www.ransomfeed.it/index.php?page=post_details&id_post=14012	ransomfeed	ransom;bianlian;	1	2024-03-28	神经医学顾问
10832	Santa-Cruz-Seaside	http://www.ransomfeed.it/index.php?page=post_details&id_post=14013	ransomfeed	ransom;akira;	1	2024-03-28	圣克鲁斯海滨
10833	Avant-IT-Norway	http://www.ransomfeed.it/index.php?page=post_details&id_post=14014	ransomfeed	ransom;ransomhub;	1	2024-03-28	Avant-IT-挪威
10834	Lakes-Precision	http://www.ransomfeed.it/index.php?page=post_details&id_post=14015	ransomfeed	ransom;akira;	1	2024-03-28	湖泊精确度
10835	K2systemsca	http://www.ransomfeed.it/index.php?page=post_details&id_post=14016	ransomfeed	ransom;redransomware;	1	2024-03-28	K2systemsca 系统
10836	Sfi-wfccom	http://www.ransomfeed.it/index.php?page=post_details&id_post=14017	ransomfeed	ransom;redransomware;	1	2024-03-28	Sfi-wfccom 翻译: Sfi-wfccom 翻译: Sfi-wfccom
12949	What the ID of tomorrow may look like	https://www.helpnetsecurity.com/2024/04/02/identity-documents-security/	helpnetsecurity	news;Don't miss;Expert analysis;Expert corner;Hot stuff;News;cybersecurity;identity verification;opinion;QR codes;Regula;	1	2024-04-02	明天的身份证是什么样子的?
10758	Your KnowBe4 Fresh Content Updates from March 2024	https://blog.knowbe4.com/knowbe4-content-updates-march-2024	knowbe4	news;Security Awareness Training;KnowBe4;	1	2024-03-29	您的 KnowBe4 新内容更新自2024年3月
26134	业内人士称滴滴底层系统疑遭攻击 	https://s.weibo.com/weibo?q=%23业内人士称滴滴底层系统疑遭攻击 %23	sina.weibo	hotsearch;weibo	1	2023-11-28	业内人士称滴滴底层系统疑遭攻击
26135	中国夫妻疑因被谷歌裁员在美身亡 	https://s.weibo.com/weibo?q=%23中国夫妻疑因被谷歌裁员在美身亡 %23	sina.weibo	hotsearch;weibo	1	2024-01-19	中国夫妻疑因被谷歌裁员在美身亡
13331	CBG用户被钓鱼远控搭建隧道成功	Q0JH55So5oi36KKr6ZKT6bG86L+c5o6n5pCt5bu66Zqn6YGT5oiQ5Yqf	IT战区	inside	HW	2024-04-02	z84291078、q00524141等被钓鱼，并下载wiseeye文档
13330	JUMPSERVER远程代码执行漏洞	SlVNUFNFUlZFUui/nOeoi+S7o+eggeaJp+ihjOa8j+a0ng==	https://blog.nsfocus.net/jumpservercve-2024-29201-cve-2024-29202/	vuln	HW	2024-04-02	JUMPSERVER远程代码执行漏洞
10760	Narwhal Spider Threat Group Behind New Phishing Campaign Impersonating Reputable Law Firms	https://blog.knowbe4.com/narwhal-spider-threat-group-behind-phishing	knowbe4	news;Phishing;Spear Phishing;Security Culture;	1	2024-03-29	Narwhal 蜘蛛威胁组织在新钓鱼运动背后
12872	Cybersecurity Threats Intensify in the Middle East During Ramadan	https://www.darkreading.com/cyber-risk/cyber-threats-intensify-in-middle-east-during-ramadan	darkreading	news;	1	2024-04-02	斋月期间中东网络安全威胁加剧
26136	中国空间站和鸿蒙入选2023全球十大工程 	https://s.weibo.com/weibo?q=%23中国空间站和鸿蒙入选2023全球十大工程 %23	sina.weibo	hotsearch;weibo	1	2023-12-20	中国空间站和鸿蒙入选2023全球十大工程
26137	中方回应英伟达将华为列为竞争对手 	https://s.weibo.com/weibo?q=%23中方回应英伟达将华为列为竞争对手 %23	sina.weibo	hotsearch;weibo	1	2024-02-27	中方回应英伟达将华为列为竞争对手
26138	乐华为王一博报警 	https://s.weibo.com/weibo?q=%23乐华为王一博报警 %23	sina.weibo	hotsearch;weibo	1	2024-02-20	乐华为王一博报警
26139	五粮液声明称没在拼多多开设官方店 	https://s.weibo.com/weibo?q=%23五粮液声明称没在拼多多开设官方店 %23	sina.weibo	hotsearch;weibo	1	2024-03-13	五粮液声明称没在拼多多开设官方店
12917	TUBEX-Aluminium-Tubes	http://www.ransomfeed.it/index.php?page=post_details&id_post=14062	ransomfeed	ransom;raworld;	1	2024-04-02	TUBEX-铝管
10759	New Malware Loader Delivers Agent Tesla Remote Access Trojan Via Phishing	https://blog.knowbe4.com/malware-agent-tesla-delivered-via-phishin	knowbe4	news;Phishing;Malware;Security Culture;	1	2024-03-29	新 Malware 装载器 运送Tesla 代理远程访问 Tosla 远程访问 Trojan Via Phishing
12914	Wyoming-Machinery	http://www.ransomfeed.it/index.php?page=post_details&id_post=14059	ransomfeed	ransom;play;	1	2024-04-02	怀俄明-中年
10762	75% of Organizations Believe They Are at Risk of Careless or Negligent Employees	https://blog.knowbe4.com/organizations-believe-risk-careless-negligent-employees	knowbe4	news;Security Awareness Training;Security Culture;	1	2024-03-29	75%的组织认为,他们面临不谨慎或失明雇员的风险
26140	京东采销直播喊话拼多多 	https://s.weibo.com/weibo?q=%23京东采销直播喊话拼多多 %23	sina.weibo	hotsearch;weibo	1	2024-01-17	京东采销直播喊话拼多多
26141	什么是警察荣耀他们说 	https://s.weibo.com/weibo?q=%23什么是警察荣耀他们说 %23	sina.weibo	hotsearch;weibo	1	2024-01-10	什么是警察荣耀他们说
12916	CC-Casa-e-Construo-Ltda	http://www.ransomfeed.it/index.php?page=post_details&id_post=14061	ransomfeed	ransom;raworld;	1	2024-04-02	CC-Casa-e-Construo-Ltda
12913	Roberson--Sons-Insurance-Services	http://www.ransomfeed.it/index.php?page=post_details&id_post=14058	ransomfeed	ransom;qilin;	1	2024-04-01	保 险 服务
12915	Sterling-Plumbing-Inc	http://www.ransomfeed.it/index.php?page=post_details&id_post=14060	ransomfeed	ransom;raworld;	1	2024-04-02	Sterling- 管道布插插插件c
13017	Massive Phishing Campaign Strikes Latin America: Venom RAT Targeting Multiple Sectors	https://thehackernews.com/2024/04/massive-phishing-campaign-strikes-latin.html	feedburner	news;	1	2024-04-02	拉丁美洲:毒液RAT针对多个部门
22290	NSA Updates Zero-Trust Advice to Reduce Attack Surfaces	https://www.darkreading.com/cybersecurity-operations/nsa-updates-zero-trust-advice-to-reduce-attack-surfaces	darkreading	news;	1	2024-04-10	消极安全保证更新零信任建议,以减少攻击表面
22296	Cagey Phishing Campaign Delivers Multiple RATs to Steal Windows Data	https://www.darkreading.com/remote-workforce/cagey-phishing-attack-delivers-multiple-rats-to-steal-windows-data	darkreading	news;	1	2024-04-10	Cagey 幻影运动为偷视窗数据提供多RAT
9449	Russian hackers target German political parties with WineLoader malware	https://www.bleepingcomputer.com/news/security/russian-hackers-target-german-political-parties-with-wineloader-malware/	bleepingcomputer	news;Security;	3	2024-03-22	俄国黑客用Wine Loader恶意软件攻击德国政党
8544	2024全球智能汽车网络安全法规和监管分析	https://www.freebuf.com/articles/neopoints/395045.html	freebuf	news;观点;	1	2024-03-17	2024全球智能汽车网络安全法规和监管分析
8457	Why IT General Controls Are Important for Compliance and Cybersecurity	https://securityboulevard.com/2024/03/why-it-general-controls-are-important-for-compliance-and-cybersecurity-2/	securityboulevard	news;Security Bloggers Network;Blog Posts;Compliance Operations;Cybersecurity;	1	2024-03-19	为何信息技术总控制对合规和网络安全至关重要
2827	Guarding Your Business: A Guide to Employee Training for Cybersecurity Vigilance	https://securityboulevard.com/2024/03/guarding-your-business-a-guide-to-employee-training-for-cybersecurity-vigilance/	securityboulevard	news;Data Security;Malware;Security Bloggers Network;Blog;Cybersecurity;cyberthreats;data protection;Identity Theft;Phishing;Ransomware;	1	2024-03-13	保护业务:网络安全警戒员工培训指南
9315	Organizations under pressure to modernize their IT infrastructures	https://www.helpnetsecurity.com/2024/03/22/it-modernization-investment-challenges/	helpnetsecurity	news;News;data;hybrid cloud;Nutanix;report;strategy;survey;	1	2024-03-22	面临使其信息技术基础设施现代化的压力的组织
13767	Veracode acquires Longbow Security to help organizations reduce application risk	https://www.helpnetsecurity.com/2024/04/02/veracode-longbow-security-acquisition/	helpnetsecurity	news;Industry news;Veracode;	1	2024-04-02	Veracode 获得长弓安全 帮助组织降低应用风险
8277	CISA: Healthcare Organizations Should Be Wary of Increased Ransomware Attacks by ALPHV Blackcat	https://blog.knowbe4.com/healthcare-organizations-be-wary-of-increased-ransomware-attacks	knowbe4	news;Social Engineering;Phishing;Ransomware;Security Culture;	2	2024-03-18	CISA: 保健组织应警惕ALPHV Blackcat增加的辐射器攻击
8543	勒索软件为何总能“复活”？	https://www.freebuf.com/articles/395260.html	freebuf	news;	1	2024-03-19	勒索软件为何总能“复活”？
8551	FreeBuf早报 | 麦当劳 IT 系统中断；TikTok剥离法案可能会波及微信	https://www.freebuf.com/news/395077.html	freebuf	news;资讯;	1	2024-03-18	FreeBuf早报 | 麦当劳 IT 系统中断；TikTok剥离法案可能会波及微信
13722	xz-utils Backdoor Affects Kali Linux Installations – How to Check for Infection	https://gbhackers.com/xz-utils-affects-kali-linux/	GBHacker	news;cyber security;Cyber Security News;KALI;Kali Linux;	1	2024-04-02	Kali Linux 装置的后门影响 - 如何检查感染情况
13716	Live Forensic Techniques To Detect Ransomware Infection On Linux Machines	https://gbhackers.com/linux-ransomware-detection-live-forensics/	GBHacker	news;cyber security;Cyber Security News;Forensics Tools;IoT;IoT Security;Linux Ransomware Detection;Live Forensic Techniques;	2	2024-04-02	用于检测Linux机用离子机进行放射器感染的现场法医技术
22287	Japan, Philippines, &amp; US Forge Cyber Threat Intel-Sharing Alliance	https://www.darkreading.com/cybersecurity-operations/japan-philippines-us-forge-cyber-threat-intelligence-sharing-alliance	darkreading	news;	1	2024-04-10	日本、菲律宾、 & amp; US Forge网络威胁情报分享联盟
11838	Securing privacy in the face of expanding data volumes	https://www.helpnetsecurity.com/2024/04/01/data-privacy-protection-aspects-video/	helpnetsecurity	news;Video;BDO USA;cybersecurity;data;Egnyte;Ground Labs;privacy;video;Virtru;	1	2024-04-01	面对数据量不断扩大,保障隐私
10137	Windows 10 KB5035941 update released with lock screen widgets	https://buaq.net/go-230688.html	buaq	newscopy;	0	2024-03-27	Windows 10 KB5035941 以锁定屏幕部件发布最新消息
8933	Beyond Detection: Enhancing Your Security Posture with Predictive Cyberthreat Insights	https://securityboulevard.com/2024/03/beyond-detection-enhancing-your-security-posture-with-predictive-cyberthreat-insights/	securityboulevard	news;Endpoint;Incident Response;Security Bloggers Network;Blog;endpoint detection and response;Endpoint Protection;security posture;sophos;Sophos X-Ops;	1	2024-03-21	超越探测:通过预测网络威胁透视加强您的安全态势
13779	The XZ Backdoor: Everything You Need to Know	https://www.wired.com/story/xz-backdoor-everything-you-need-to-know/	wired	news;Security;Security / Cyberattacks and Hacks;	1	2024-04-02	XZ后门:你需要知道的一切
22298	TA547 Uses an LLM-Generated Dropper to Infect German Orgs	https://www.darkreading.com/threat-intelligence/ta547-uses-llm-generated-dropper-infect-german-orgs	darkreading	news;	1	2024-04-10	TA547 使用一个LLM引流器来感染德国鸟类
22304	RemoteTLSCallbackInjection - Utilizing TLS Callbacks To Execute A Payload Without Spawning Any Threads In A Remote Process	http://www.kitploit.com/2024/04/remotetlscallbackinjection-utilizing.html	kitploit	tool;Anti-Debugging;Injection;Payload;RemoteTLSCallbackInjection;TLS;	1	2024-04-10	远程 TLSC allCall backpack 输入 - 利用 TLS 回击来执行有效装入,而不在远程程序中生成任何线索
9795	US sanctions crypto exchanges used by Russian darknet market, banks	https://www.bleepingcomputer.com/news/security/us-sanctions-crypto-exchanges-used-by-russian-darknet-market-banks/	bleepingcomputer	news;Security;	4	2024-03-25	俄罗斯黑网市场、银行使用的美国制裁秘密交易
26224	外媒称小米SU7定价激进 	https://s.weibo.com/weibo?q=%23外媒称小米SU7定价激进 %23	sina.weibo	hotsearch;weibo	1	2024-03-29	外媒称小米SU7定价激进
26225	女子投诉小米SU7未交付掉漆 	https://s.weibo.com/weibo?q=%23女子投诉小米SU7未交付掉漆 %23	sina.weibo	hotsearch;weibo	1	2024-04-07	女子投诉小米SU7未交付掉漆
26226	如何看待华为全新鸿蒙平板 	https://s.weibo.com/weibo?q=%23如何看待华为全新鸿蒙平板 %23	sina.weibo	hotsearch;weibo	1	2023-11-28	如何看待华为全新鸿蒙平板
14364	AT&T data leaked: 73 million customers affected	https://www.helpnetsecurity.com/2024/04/02/att-data-leaked/	helpnetsecurity	news;Don't miss;Hot stuff;News;AT&T;data leak;USA;	1	2024-04-02	AT&T数据泄漏:7 300万客户受到影响
2677	The effects of law enforcement takedowns on the ransomware landscape	https://www.helpnetsecurity.com/2024/03/13/law-enforcement-action-ransomware/	helpnetsecurity	news;Don't miss;Hot stuff;News;botnet;law enforcement;ransomware;RedSense;Symantec;trends;	2	2024-03-13	执法收缩对赎金软件景观的影响
14710	Declassified NSA Newsletters	https://securityboulevard.com/2024/04/declassified-nsa-newsletters/	securityboulevard	news;Security Bloggers Network;Applied Cryptography;foia;history of cryptography;history of security;nsa;Uncategorized;	1	2024-04-02	解密的《消极安全保证通讯》
14697	YouTube failed to block disinformation about Indian elections, researchers find	https://therecord.media/youtube-failed-to-block-indian-disinformation-elections	therecord	ransom;News;Elections;Technology;	1	2024-04-02	研究人员发现,YouTube未能阻止有关印度选举的虚假信息,
14712	How to Escape the 3 AM Page as a Kubernetes Site Reliability Engineer	https://securityboulevard.com/2024/04/how-to-escape-the-3-am-page-as-a-kubernetes-site-reliability-engineer/	securityboulevard	news;Security Bloggers Network;Managed Kubernetes;	1	2024-04-02	如何逃离3号上午3点的Kubernetes站点可靠性工程师页面
14713	Prioritizing Cyber Risk: Get a leg up with AI	https://securityboulevard.com/2024/04/prioritizing-cyber-risk-get-a-leg-up-with-ai/	securityboulevard	news;Security Bloggers Network;Vulnerabilities;Vulnerability Management;	1	2024-04-02	优先处理网络风险:与AI联系
15441	Critical Security Flaw Found in Popular LayerSlider WordPress Plugin	https://thehackernews.com/2024/04/critical-security-flaw-found-in-popular.html	feedburner	news;	1	2024-04-03	在大众层中找到的关键安全法Slider WordPress插件
14708	A Deep Dive on the xz Compromise	https://securityboulevard.com/2024/04/a-deep-dive-on-the-xz-compromise/	securityboulevard	news;Security Bloggers Network;GitHub;Malware & Exploits;Ransomware;xz compromise;xz dissabled;xz incident;	1	2024-04-02	xz 折叠上的深底下潜
14270	In the News | State Governments Can Boost K-12 Cybersecurity	https://securityboulevard.com/2024/04/in-the-news-state-governments-can-boost-k-12-cybersecurity/	securityboulevard	news;Security Bloggers Network;Cybersecurity;education;In The News;	1	2024-04-02	州政府可以提升K-12网络安全,
15250	Cybersecurity jobs available right now: April 3, 2024	https://www.helpnetsecurity.com/2024/04/03/cybersecurity-jobs-available-right-now-april-3-2024/	helpnetsecurity	news;Don't miss;Hot stuff;News;cybersecurity jobs;	1	2024-04-03	网络安全工作: 2024年4月3日
14333	PandaBuy Data Breach: 1.3 Million Customers Data Leaked	https://gbhackers.com/pandabuy-data-breach/	GBHacker	news;Cyber Attack;Cyber Security News;Data Breach;	1	2024-04-02	PandaBuy数据突破:130万客户数据泄漏
15252	Location tracking and the battle for digital privacy	https://www.helpnetsecurity.com/2024/04/03/location-data-privacy/	helpnetsecurity	news;Don't miss;Expert analysis;Expert corner;Hot stuff;News;cybersecurity;data;GPS;location tracking;LOKKER;opinion;privacy;regulation;	1	2024-04-03	地点跟踪和数字隐私斗争
4161	波及4300万人！法国官方就业机构数据遭窃	https://buaq.net/go-228246.html	buaq	newscopy;	0	2024-03-15	波及4300万人！法国官方就业机构数据遭窃
4742	How to Identify & Monitor Insider Threat Indicators [A Guide]	https://securityboulevard.com/2024/03/how-to-identify-monitor-insider-threat-indicators-a-guide/	securityboulevard	news;Security Bloggers Network;Blog;Constella Dome;dark web monitoring;Digital Breach;Digital Risk Protection;Identity Theft;	1	2024-03-16	如何识别
15229	「帮会店铺」功能正式上线 | 知识大陆APP重要更新	https://www.freebuf.com/articles/others-articles/396895.html	freebuf	news;其他;	1	2024-04-03	「帮会店铺」功能正式上线 | 知识大陆APP重要更新
203	Evolving Microsoft Security Development Lifecycle (SDL): How continuous SDL can help you build more secure software	https://www.microsoft.com/en-us/security/blog/2024/03/07/evolving-microsoft-security-development-lifecycle-sdl-how-continuous-sdl-can-help-you-build-more-secure-software/	microsoft	news;	1	2024-03-07	不断演化的微软安全开发生命周期(SDL):如何持续SDL能帮助你建立更安全的软件
16068	More Than Half of Organizations Plan to Adopt AI Solutions in Coming Year, Reports Cloud Security Alliance and Google Cloud	https://www.darkreading.com/cloud-security/more-than-half-of-organizations-plan-to-adopt-ai-solutions-in-coming-year-according-to-cloud-security-alliance-and-google-cloud-report	darkreading	news;	1	2024-04-03	在来年采用AI解决方案的组织计划、关于云层安全联盟和谷歌云的报告
14711	Guide to New CSRD Regulation for Data Center Operators	https://securityboulevard.com/2024/04/guide-to-new-csrd-regulation-for-data-center-operators/	securityboulevard	news;Security Bloggers Network;Infrastructure;	1	2024-04-02	CSRD数据中心操作员新条例指南指南
14695	OWASP Foundation warns members of data breach after discovering 1,000 resumes on Wiki server	https://therecord.media/owasp-foundation-warns-of-data-breach-resumes	therecord	ransom;News;Privacy;Technology;	1	2024-04-02	OWASP基金会在维基服务器上发现1,000份履历后警告成员数据被破坏
16069	Reconsider Your CNAPP Strategy Using These 5 Scenarios	https://www.darkreading.com/cloud-security/reconsider-your-cnapp-strategy-using-these-5-scenarios	darkreading	news;	1	2024-04-05	利用这5种设想方案,重新考虑国家国家国家适应方案战略
11074	XZ Utils backdoor update: Which Linux distros are affected and what can you do?	https://www.helpnetsecurity.com/2024/03/31/xz-backdoored-linux-affected-distros/	helpnetsecurity	news;Don't miss;Hot stuff;News;Alpine;backdoor;Debian;Fedora;Kali Linux;Linux;Linux Mint;open source;Orca Security;Red Hat;supply chain attacks;Ubuntu;vulnerability;	1	2024-03-31	XZ 用户名后门更新: Linux 哪些变异器受到影响,
14694	Missouri county home to Kansas City says suspected ransomware attack affecting tax payments	https://therecord.media/kansas-city-missouri-county-suspected-ransomware-attack-tax-payments	therecord	ransom;Cybercrime;Government;News;	2	2024-04-02	密苏里县 堪萨斯市的家乡 密苏里县 说疑似勒索软件袭击 影响纳税
26277	小米SU7退订率 	https://s.weibo.com/weibo?q=%23小米SU7退订率 %23	sina.weibo	hotsearch;weibo	1	2024-04-02	小米SU7退订率
26278	小米SU7霞光紫 	https://s.weibo.com/weibo?q=%23小米SU7霞光紫 %23	sina.weibo	hotsearch;weibo	1	2024-03-28	小米SU7霞光紫
11083	Yogurt Heist Reveals a Rampant Form of Online Fraud	https://www.wired.com/story/yogurt-heist-security-roundup/	wired	news;Security;Security / Cyberattacks and Hacks;Security / Privacy;Security / Security News;	1	2024-03-30	Yogurt Heist 揭露网络欺诈的一股暴光形式
11086	SolarView Compact 6.00 - Command Injection Bypass authentication	https://cxsecurity.com/issue/WLB-2024030070	cxsecurity	vuln;	1	2024-03-30	SolarView Contact 6.00 - 指令喷射绕天认证
11097	FusionPBX Session Fixation	https://cxsecurity.com/issue/WLB-2024030076	cxsecurity	vuln;	1	2024-03-30	FisionPBX 会话固定
14567	New Chrome feature aims to stop hackers from using stolen cookies	https://www.bleepingcomputer.com/news/security/new-chrome-feature-aims-to-stop-hackers-from-using-stolen-cookies/	bleepingcomputer	news;Security;Google;	1	2024-04-02	新铬特写旨在阻止黑客使用偷来的饼干
14568	New XZ backdoor scanner detects implant in any Linux binary	https://www.bleepingcomputer.com/news/security/new-xz-backdoor-scanner-detects-implant-in-any-linux-binary/	bleepingcomputer	news;Security;Linux;	1	2024-04-02	新建 XZ 后门扫描仪检测任何Linux 二进制的植入器
14569	Omni Hotels experiencing nationwide IT outage since Friday	https://www.bleepingcomputer.com/news/security/omni-hotels-experiencing-nationwide-it-outage-since-friday/	bleepingcomputer	news;Security;	1	2024-04-02	自星期五以来全国信息技术中断的Omni旅馆
14571	Russia charges suspects behind theft of 160,000 credit cards	https://www.bleepingcomputer.com/news/security/russia-charges-suspects-behind-theft-of-160-000-credit-cards/	bleepingcomputer	news;Security;Legal;	3	2024-04-02	俄罗斯对盗窃160 000张信用卡的嫌疑人提出指控
14573	Winnti's new UNAPIMON tool hides malware from security software	https://www.bleepingcomputer.com/news/security/winntis-new-unapimon-tool-hides-malware-from-security-software/	bleepingcomputer	news;Security;	1	2024-04-02	Winnti 的新 UAPIMON 工具隐藏安全软件中的恶意软件
14579	Attackers Abuse Google Ad Feature to Target Slack, Notion Users	https://www.darkreading.com/cyberattacks-data-breaches/attackers-use-google-ad-feature-to-target-slack-notion-users	darkreading	news;	1	2024-04-02	攻击者滥用 Google 的Google 特写,
14580	China-Linked Threat Actor Taps 'Peculiar' Malware to Evade Detection	https://www.darkreading.com/cyberattacks-data-breaches/china-linked-threat-actor-using-peculiar-malware-to-hide-malicious-activities	darkreading	news;	4	2024-04-02	与中国相关的威胁动画家“粉末”磁磁器磁器,用于蒸发探测
14582	HHS Plans for Cyber 'One-Stop Shop' After United Healthcare Attack	https://www.darkreading.com/cybersecurity-operations/hhs-plans-for-cyber-one-stop-shop-after-change-healthcare-attack	darkreading	news;	1	2024-04-02	联合医疗攻击后网络“一站式商店”的HHS计划
14583	Instilling the Hacker Mindset Organizationwide	https://www.darkreading.com/cybersecurity-operations/instilling-hacker-mindset-organizationwide	darkreading	news;	1	2024-04-02	在整个组织内向黑克明心系统公司注入资金
14589	Funding the Organizations That Secure the Internet	https://www.darkreading.com/vulnerabilities-threats/funding-the-organizations-that-secure-the-internet	darkreading	news;	1	2024-04-02	资助确保互联网安全的组织
14590	NIST Wants Help Digging Out of Its NVD Backlog	https://www.darkreading.com/vulnerabilities-threats/nist-needs-help-digging-out-of-its-vulnerability-backlog	darkreading	news;	1	2024-04-02	NIST 想要帮助挖掘其 NVID 积压文件
14620	Gaia-Herbs	http://www.ransomfeed.it/index.php?page=post_details&id_post=14067	ransomfeed	ransom;blacksuit;	1	2024-04-02	盖亚赫布斯
14621	WPJ-McCarthy-and-Company	http://www.ransomfeed.it/index.php?page=post_details&id_post=14068	ransomfeed	ransom;qilin;	1	2024-04-02	WPJ-Mc-Carthy-and-Company WPJ-Mc-Carthy-兼兼合公司
14622	Precision-Pulley-ampamp-Idler	http://www.ransomfeed.it/index.php?page=post_details&id_post=14071	ransomfeed	ransom;blacksuit;	1	2024-04-02	精精精度- Pulley- ampamp- Idler
14457	CyberheistNews Vol 14 #14 [SCARY] Research Shows Weaponized GenAI Worm That Gets Distributed Via A Zero Click Phishing Email	https://blog.knowbe4.com/cyberheistnews-vol-14-14-scary-research-shows-weaponized-genai-worm-that-gets-distributed-via-a-zero-click-phishing-email	knowbe4	news;Cybercrime;KnowBe4;	1	2024-04-02	网络新闻第14卷14#14[SCARIR]研究显示,
14463	Indian Govt Rescues 250 Citizens Trapped In Cambodia Forced Into Cyber-Slavery	https://gbhackers.com/indian-citizens-rescued-cambodia-cyber-slavery/	GBHacker	news;Cyber Crime;Cyber Security News;Incident Response;Cyber-Slavery;Fraudulent Recruitment;Rescue Operation;	1	2024-04-02	印度政府援救250名柬埔寨公民,
4036	《民航数据管理办法（征求意见稿）》&《民航数据共享管理办法（征求意见稿）》正式发布	https://www.freebuf.com/articles/394860.html	freebuf	news;	1	2024-03-14	《民航数据管理办法（征求意见稿）》&《民航数据共享管理办法（征求意见稿）》正式发布
14468	Swalwell for Congress Campaign Partners with Wolfsbane.ai to Protect Against AI-Generated Cloning	https://gbhackers.com/swalwell-for-congress-campaign-partners-with-wolfsbane-ai/	GBHacker	news;Press Release;press release;	1	2024-04-02	与沃尔夫斯班(Wolfsbane.ai)合作,保护不受AI-Genered Cloning的伤害。
14498	Fastly Bot Management protects websites, apps, and valuable data from malicious automated traffic	https://www.helpnetsecurity.com/2024/04/02/fastly-bot-management-protects-websites-apps-and-valuable-data-from-malicious-automated-traffic/	helpnetsecurity	news;Industry news;Fastly;	1	2024-04-02	快速平台管理保护网站、应用程序和宝贵数据免遭恶意自动贩运
14499	Fortinet upgrades its real-time network security operating system	https://www.helpnetsecurity.com/2024/04/02/fortinet-fortios-7-6/	helpnetsecurity	news;Industry news;Fortinet;	1	2024-04-02	Fortinet更新其实时网络安全操作系统
11081	You Should Update Apple iOS and Google Chrome ASAP	https://www.wired.com/story/apple-ios-google-chrome-critical-update-march/	wired	news;Security;Security / Cyberattacks and Hacks;Security / Security Advice;	1	2024-03-31	您应该尽快更新苹果 iOS 和 Google 铬
14564	Microsoft warns Gmail blocks some Outlook email as spam, shares fix	https://www.bleepingcomputer.com/news/microsoft/microsoft-warns-gmail-blocks-some-outlook-email-as-spam-shares-fix/	bleepingcomputer	news;Microsoft;Google;	1	2024-04-02	微软警告 Gmail 将 Outlook 电子邮件封为垃圾邮件, 共享修正
11098	Circontrol Raption Buffer Overflow / Command Injection	https://cxsecurity.com/issue/WLB-2024030078	cxsecurity	vuln;	2	2024-03-30	中枢控制 呼吸缓冲 过流 / 命令喷射
11093	Wazuh Dashboard - Information Discoluser	https://cxsecurity.com/issue/WLB-2024030071	cxsecurity	vuln;	1	2024-03-30	Wazuh Dashboard - 信息拆卸
13655	Volt Typhoon Threat Report	https://securityboulevard.com/2024/04/volt-typhoon-threat-report/	securityboulevard	news;Security Bloggers Network;Threat Research;	1	2024-04-01	伏特台风威胁报告
11130	DroidLysis - Property Extractor For Android Apps	http://www.kitploit.com/2024/03/droidlysis-property-extractor-for.html	kitploit	tool;Decompile;dex2jar;DroidLysis;Dumping;GPS;Python;Python3;SHA256;	2	2024-03-31	DroidLysis - Android Apps 财产提取器
11237	Williams-County-Abstract-Company	http://www.ransomfeed.it/index.php?page=post_details&id_post=14041	ransomfeed	ransom;medusa;	1	2024-03-30	Williams公司
14715	The Challenges of Zero Trust 800-207 and Advocating for Prescriptive Controls	https://securityboulevard.com/2024/04/the-challenges-of-zero-trust-800-207-and-advocating-for-prescriptive-controls/	securityboulevard	news;Security Bloggers Network;zero trust;	1	2024-04-02	零信任800-207和倡导规范性控制的挑战
409	RKS - A Script To Automate Keystrokes Through A Graphical Desktop Program	http://www.kitploit.com/2024/03/rks-script-to-automate-keystrokes.html	kitploit	tool;msfvenom;Remote Desktop;RKS;Rubber Ducky;VNC;Windows;	1	2024-03-01	RKS - 通过图形化桌面程序自动显示键的脚本
14869	Ransomware, Junk Bank Accounts: Cyber Threats Proliferate in Vietnam	https://www.darkreading.com/cyber-risk/ransomware-junk-bank-accounts-cyberthreats-proliferates-in-vietnam	darkreading	news;	2	2024-04-03	Ransomware, Jank银行帐户:网络威胁在越南蔓延
14717	xz Utils Backdoor	https://securityboulevard.com/2024/04/xz-utils-backdoor/	securityboulevard	news;Application Security;DevOps;Malware;Security Bloggers Network;Social Engineering;backdoors;Cybersecurity;Hacking;open source;social engineering;Uncategorized;	1	2024-04-02	后门
14714	Sophos: Backups are in Ransomware Groups’ Crosshairs	https://securityboulevard.com/2024/04/sophos-backups-are-in-the-crosshairs-of-ransomware-groups/	securityboulevard	news;Cloud Security;Cybersecurity;Data Security;Featured;Incident Response;Industry Spotlight;Malware;Network Security;News;Security Awareness;Security Boulevard (Original);Social - Facebook;Social - LinkedIn;Social - X;Spotlight;Threat Intelligence;Threats & Breaches;backup and restore;Ransomware;sophos;	2	2024-04-02	索福斯:后援在Ransomware Groups十字架上
14716	The Open-Source Backdoor That Almost Compromised SSH	https://securityboulevard.com/2024/04/the-open-source-backdoor-that-almost-compromised-ssh/	securityboulevard	news;Security Bloggers Network;Breach explained;supply chain security;	1	2024-04-02	开放源码后门 几乎被扭曲的SSH
14848	MY TAKE: Why email security desperately needs retooling in this post-Covid 19, GenAI era	https://securityboulevard.com/2024/04/my-take-why-email-security-desperately-needs-retooling-in-this-post-covid-19-genai-era/	securityboulevard	news;SBN News;Security Awareness;Security Bloggers Network;For Consumers;For Technologists;My Take;Top Stories;	1	2024-04-02	为什么电子邮件安全 迫切需要重新改造 在Covid 19, GenAI时代
11088	util-linux wall Escape Sequence Injection	https://cxsecurity.com/issue/WLB-2024030077	cxsecurity	vuln;	1	2024-03-30	util-linux 墙
11087	WatchGuard XTM Firebox Unauthenticated Remote Command Execution	https://cxsecurity.com/issue/WLB-2024030074	cxsecurity	vuln;	1	2024-03-30	WatchGuard XTM Firebox 未认证远程命令执行
2557	'PixPirate' RAT Invisibly Triggers Wire Transfers From Android Devices	https://www.darkreading.com/application-security/pixpirate-rat-invisibly-triggers-wire-transfers-android-devices	darkreading	news;	2	2024-03-13	“ PixPirate ” RAT 不可见地触发从 Android 设备传输的电线
14563	Google agrees to delete Chrome browsing data of 136 million users	https://www.bleepingcomputer.com/news/legal/google-agrees-to-delete-chrome-browsing-data-of-136-million-users/	bleepingcomputer	news;Legal;Google;	1	2024-04-02	Google同意删除1.36亿用户的铬浏览数据
11096	Purei CMS 1.0 SQL Injection	https://cxsecurity.com/issue/WLB-2024030075	cxsecurity	vuln;	1	2024-03-30	Purei CMS 1.0 SQL 注射
3856	Google-Dorks-Bug-Bounty - A List Of Google Dorks For Bug Bounty, Web Application Security, And Pentesting	http://www.kitploit.com/2024/03/google-dorks-bug-bounty-list-of-google.html	kitploit	tool;Google-Dorks-Bug-Bounty;Web Application;XSS;	1	2024-03-14	Google-Dorks-Bug-Bounty - Google Dorks for Bug Bounty、 Web 应用程序安全及 Pensuit 列表
12335	BioTime Directory Traversal / Remote Code Execution	https://packetstormsecurity.com/files/177859/biotime901-exec.txt	packetstorm	vuln;;	1	2024-04-01	生物时间目录Traversal/远程代码执行
13916	上海市财政局发布关于进一步加强本市数据资产管理的通知	https://www.freebuf.com/news/396818.html	freebuf	news;资讯;	1	2024-04-02	System error
15111	Cyber attacks on critical infrastructure show advanced tactics and new capabilities	https://www.helpnetsecurity.com/2024/04/03/marty-edwards-tenable-critical-infrastructure-systems-cybersecurity/	helpnetsecurity	news;Don't miss;Features;Hot stuff;News;CISO;critical infrastructure;cyberattacks;cybersecurity;government;opinion;ransomware;strategy;Tenable;tips;	1	2024-04-03	对重要基础设施的网络网络攻击显示先进战术和新能力
13991	OpenSSL Vulnerabilities Patched in Ubuntu 18.04	https://securityboulevard.com/2024/04/openssl-vulnerabilities-patched-in-ubuntu-18-04/	securityboulevard	news;Security Bloggers Network;Denial of Service (DoS) attacks;Extended Lifecycle Support;Linux & Open Source News;OpenSSL library;OpenSSL Patches;OpenSSL Patching;openssl vulnerabilities;Ubuntu 16.04;Ubuntu 16.04 End of Life;Ubuntu 18.04 End of Life;ubuntu 18.04 security updates;Ubuntu 18.04 security vulnerabilities;Ubuntu Security Fixes;Ubuntu Security Updates;	1	2024-04-02	Ubuntu 18.04 中的 OpenSSL 漏洞已修复
4741	10 Takeaways from the 2024 Gartner IAM Summit UK  	https://securityboulevard.com/2024/03/10-takeaways-from-the-2024-gartner-iam-summit-uk/	securityboulevard	news;Identity & Access;Security Bloggers Network;Cool Vendor;Gartner;identity management;Identity Security Posture Management;Identity-First Security;ITDR;Market;security;	1	2024-03-17	10名从2024年英国Gartner IAM高峰会议外出
15122	网络安全赛事中开源威胁情报的妙用	https://xz.aliyun.com/t/14234	阿里先知实验室	news;	1	2024-04-02	网络安全赛事中开源威胁情报的妙用
12345	FCC to probe ‘grave’ weaknesses in phone network infrastructure	https://therecord.media/fcc-ss7-diameter-protocols-investigation	therecord	ransom;Industry;Government;Privacy;Technology;News;	1	2024-04-01	FCC 调查电话网络基础设施中的“严重”弱点
15117	nginxwebui后台rce审计	https://xz.aliyun.com/t/14227	阿里先知实验室	news;	1	2024-04-02	nginxwebui后台rce审计
15120	记几道CTF-Java反序列化题目(二）	https://xz.aliyun.com/t/14231	阿里先知实验室	news;	1	2024-04-02	记几道CTF-Java反序列化题目(二）
15110	Human risk is the top cyber threat for IT teams	https://www.helpnetsecurity.com/2024/04/03/human-risk-cyber-incidents-video/	helpnetsecurity	news;Don't miss;Hot stuff;Video;artificial intelligence;cybercrime;cybersecurity;deepfakes;Mimecast;video;	1	2024-04-03	人类风险是信息技术团队最大的网络威胁
15119	IP网络对讲广播系统审计	https://xz.aliyun.com/t/14230	阿里先知实验室	news;	1	2024-04-02	IP网络对讲广播系统审计
15121	某次小红书帮助下的Edu挖掘	https://xz.aliyun.com/t/14232	阿里先知实验室	news;	1	2024-04-02	某次小红书帮助下的Edu挖掘
15118	PHP之殇 : 一个IR设计缺陷引发的蝴蝶效应	https://xz.aliyun.com/t/14228	阿里先知实验室	news;	1	2024-04-02	PHP之殇 : 一个IR设计缺陷引发的蝴蝶效应
12461	6 keys to navigating security and app development team tensions	https://www.helpnetsecurity.com/2024/04/02/navigating-security-app-development-team-tensions/	helpnetsecurity	news;Don't miss;Hot stuff;News;application security;cybersecurity;data security;DevSecOps;Probely;tips;	1	2024-04-02	安保和应用程序开发团队紧张状态导航6个关键
13926	LogRhythm Axon enhancements improve data management and operational efficiency	https://www.helpnetsecurity.com/2024/04/02/logrhythm-security-tools/	helpnetsecurity	news;Industry news;LogRhythm;	1	2024-04-02	LologRhythm Axon 改进数据管理和提高业务效率
15532	DarkGate Malware Abusing Cloud Storage & SEO Following Delivery Over Teams	https://gbhackers.com/darkgate-malware-abusing/	GBHacker	news;Cloud;Cyber Security News;	1	2024-04-03	DarkGate DarkGate 恶意滥用云存和SEO 跟踪送货团队
14552	5 Best Vanta Alternatives To Consider in 2024	https://securityboulevard.com/2024/04/5-best-vanta-alternatives-to-consider-in-2024/	securityboulevard	news;Security Bloggers Network;All;Blog;Security and Compliance;	1	2024-04-02	5 2024年万塔最佳考虑替代方案
15365	delhipolicegovin	http://www.ransomfeed.it/index.php?page=post_details&id_post=14080	ransomfeed	ransom;killsec;	1	2024-04-03	国家警察局
15363	casajovecom	http://www.ransomfeed.it/index.php?page=post_details&id_post=14078	ransomfeed	ransom;lockbit3;	1	2024-04-02	casajovecom
15598	Persistence – DLL Proxy Loading	http://pentestlab.blog/2024/04/03/persistence-dll-proxy-loading/	pentestlab	tech;Persistence;DLL Loading;Red Team;SharpDLLProxy;	1	2024-04-03	持久性 - DLL 代理装载
22325	Alert! Brute-Force SSH Attacks Rampant in the Wild: New Study From 427 Million Failed SSH Login Attempts	https://gbhackers.com/alert-brute-force-ssh-attacks-rampant-in-the-wild/	GBHacker	news;Cyber Attack;Cyber Crime;cyber security;Cyber Security News;computer security;	1	2024-04-10	警告! 野生的布鲁特-部队SSH攻击狂野:来自4.27亿SSH登机失败的4. 7亿次新研究
16064	Critical Bugs Put Hugging Face AI Platform in a 'Pickle'	https://www.darkreading.com/cloud-security/critical-bugs-hugging-face-ai-platform-pickle	darkreading	news;	1	2024-04-05	关键错误将 抱抱脸的 AI 平台放入“ 滑鼠” 平台
15366	Seven-Seas-Technology	http://www.ransomfeed.it/index.php?page=post_details&id_post=14081	ransomfeed	ransom;rhysida;	1	2024-04-03	七海技术
16066	Feds to Microsoft: Clean Up Your Cloud Security Act Now	https://www.darkreading.com/cloud-security/feds-microsoft-clean-up-cloud-security-act	darkreading	news;	1	2024-04-03	美联储致微软:立即清理你的云安全法
15364	regencyfurniturecom	http://www.ransomfeed.it/index.php?page=post_details&id_post=14079	ransomfeed	ransom;cactus;	1	2024-04-02	翻新孔
16062	How Do We Integrate LLMs Security Into Application Development?	https://www.darkreading.com/application-security/how-do-we-integrate-llm-security-into-application-development-	darkreading	news;	1	2024-04-05	我们如何将LLMS安全纳入应用开发?
16063	How to Tame SQL Injection	https://www.darkreading.com/application-security/tools-and-techniques-to-tame-sql-injection	darkreading	news;	1	2024-04-03	如何修补 SQL 注射
15531	Beware of New Mighty Stealer That Takes Webcam Pictures & Capture Cookies	https://gbhackers.com/beware-of-new-mighty-stealer/	GBHacker	news;cyber security;Cyber Security News;	2	2024-04-03	当心新万能偷盗者 摄像头图片和捕捉曲奇
8938	Sentry, GitHub Use AI to Help Fix Coding Errors	https://securityboulevard.com/2024/03/sentry-github-use-ai-to-help-fixing-coding-errors/	securityboulevard	news;Application Security;Cybersecurity;Data Security;DevOps;Featured;Industry Spotlight;Mobile Security;News;Security Awareness;Security Boulevard (Original);Social - Facebook;Social - LinkedIn;Social - X;Spotlight;application developers;coding assistant;generative AI;GitHub;	1	2024-03-21	哨兵, GitHub 使用 AI 帮助修正编码错误
19979	Continuous ATO: Going from Authority to Operate (ATO) to Ability to Respond	https://securityboulevard.com/2024/04/continuous-ato-going-from-authority-to-operate-ato-to-ability-to-respond/	securityboulevard	news;DevOps;Security Bloggers Network;ato acceleration;Blog;cato;continuous ato;DevSecOps;FedRAMP;fisma ato;nist ongoing authorizations;	1	2024-04-08	ATO:从当局到操作(ATO)到反应能力
16065	CyberRatings.org Announces Test Results for Cloud Network Firewall	https://www.darkreading.com/cloud-security/cyberratings-org-announces-test-results-for-cloud-network-firewall	darkreading	news;	1	2024-04-03	Cyberratings.org 宣布云网防火墙测试结果
16061	Visa warns of new JSOutProx malware variant targeting financial orgs	https://www.bleepingcomputer.com/news/security/visa-warns-of-new-jsoutprox-malware-variant-targeting-financial-orgs/	bleepingcomputer	news;Security;	1	2024-04-04	签证警告针对金融大兽的新的JSOutProx恶意软件变体
19984	How Avast One Silver adapts to your unique online world	https://securityboulevard.com/2024/04/how-avast-one-silver-adapts-to-your-unique-online-world/	securityboulevard	news;Security Bloggers Network;	2	2024-04-09	Avast One Silver 如何适应你独特的在线世界
16059	The Week in Ransomware - April 5th 2024 - Virtual Machines under Attack	https://www.bleepingcomputer.com/news/security/the-week-in-ransomware-april-5th-2024-virtual-machines-under-attack/	bleepingcomputer	news;Security;	2	2024-04-05	2024年4月5日 被攻击的虚拟机器
16060	US Health Dept warns hospitals of hackers targeting IT help desks	https://www.bleepingcomputer.com/news/security/us-health-dept-warns-hospitals-of-hackers-targeting-it-help-desks/	bleepingcomputer	news;Security;Healthcare;	1	2024-04-06	美国卫生署警告医院黑客将信息技术服务台作为黑客攻击目标
15368	Apex-Business-Advisory	http://www.ransomfeed.it/index.php?page=post_details&id_post=14084	ransomfeed	ransom;8base;	1	2024-04-03	高级商业顾问
15369	Pim	http://www.ransomfeed.it/index.php?page=post_details&id_post=14085	ransomfeed	ransom;8base;	1	2024-04-03	平平
15362	KICO-GROUP	http://www.ransomfeed.it/index.php?page=post_details&id_post=14076	ransomfeed	ransom;raworld;	1	2024-04-02	基 基 基 固 固 固 固 基 固 固 固 固 基 固 固
14693	Google to delete billions of web browsing data records to resolve lawsuit	https://therecord.media/google-to-delete-web-browsing-records-to-resolve-lawsuit	therecord	ransom;Industry;News;News Briefs;Privacy;	1	2024-04-02	谷歌删除数十亿网络浏览数据记录以解决诉讼
15367	Innomotive-Systems-Hainichen-GmbH	http://www.ransomfeed.it/index.php?page=post_details&id_post=14082	ransomfeed	ransom;raworld;	1	2024-04-03	动机性 - - - - - - - - - - - - - - - - - Hainichen - -
18730	The Cyber Achilles' Heel: Why World Leaders and High-Profile Individuals Must Prioritise Cybersecurity	https://blog.knowbe4.com/why-world-leaders-and-high-profile-individuals-must-prioritise-cybersecurity	knowbe4	news;Social Engineering;Phishing;	1	2024-04-08	Achilles网络的脚跟:为什么世界领导人和高素质个人必须优先关注网络安全?
16053	Fake Facebook MidJourney AI page promoted malware to 1.2 million people	https://www.bleepingcomputer.com/news/security/fake-facebook-midjourney-ai-page-promoted-malware-to-12-million-people/	bleepingcomputer	news;Security;Artificial Intelligence;Software;	1	2024-04-05	假脸书MidJourney AI网页向120万人宣传恶意软件
16054	Microsoft fixes Outlook security alerts bug caused by December updates	https://www.bleepingcomputer.com/news/security/microsoft-fixes-outlook-security-alerts-bug-caused-by-december-updates/	bleepingcomputer	news;Security;Microsoft;	1	2024-04-04	微软修补12月更新引起的 Outlook 安全警报错误
18729	Large-Scale StrelaStealer Campaign Impacts Over 100 Organizations Within the E.U. and U.S.	https://blog.knowbe4.com/strelastealer-campaign-impacts-over-100-organizations	knowbe4	news;Social Engineering;Security Awareness Training;Security Culture;	1	2024-04-08	大型Strela Stealer运动对美国和美国境内100多个组织产生了影响。
15907	Customer Story | Content Filter Protects Student Safety, Data Security, and CIPA Compliance At Azusa Unified School District	https://securityboulevard.com/2024/04/customer-story-content-filter-protects-student-safety-data-security-and-cipa-compliance-at-azusa-unified-school-district/	securityboulevard	news;Security Bloggers Network;Customer Success Stories;education;Web Content Filtering;	1	2024-04-02	内容过滤器保护学生安全、数据安全和Azusa统一学校区CIPA遵守规定的情况
15823	Tamura-Corporation	http://www.ransomfeed.it/index.php?page=post_details&id_post=14087	ransomfeed	ransom;8base;	1	2024-04-03	多村公司
15824	Ringhoffer-Verzahnungstechnik-GmbH-and-Co-KG	http://www.ransomfeed.it/index.php?page=post_details&id_post=14088	ransomfeed	ransom;8base;	1	2024-04-03	Ringhoffer-Verzahnungstechnik-GmbH和Co-KG 集团
18794	The Drop in Ransomware Attacks in 2024 and What it Means	https://thehackernews.com/2024/04/the-drop-in-ransomware-attacks-in-2024.html	feedburner	news;	2	2024-04-08	2024年核磁器袭击的下降 以及它的意义
16050	Microsoft fixes Windows Sysprep issue behind 0x80073cf2 errors	https://www.bleepingcomputer.com/news/microsoft/microsoft-fixes-windows-sysprep-issue-behind-0x80073cf2-errors/	bleepingcomputer	news;Microsoft;	1	2024-04-05	微软在 0x80073cf2 错误后面修正 Windows Sysprep 问题
15993	Bitwarden releases magic links API to improve passwordless user authentication	https://www.helpnetsecurity.com/2024/04/03/bitwarden-magic-links-api/	helpnetsecurity	news;Industry news;Bitwarden;	1	2024-04-03	Bitwarden 释放魔法链接 API 改进无密码用户认证
18747	倒计时两天！| FreeBuf 企业安全俱乐部·广州站	https://www.freebuf.com/fevents/397141.html	freebuf	news;活动;	1	2024-04-08	倒计时两天！| FreeBuf 企业安全俱乐部·广州站
16058	Panera Bread week-long IT outage caused by ransomware attack	https://www.bleepingcomputer.com/news/security/panera-bread-week-long-it-outage-caused-by-ransomware-attack/	bleepingcomputer	news;Security;	2	2024-04-05	赎金软件袭击造成Panera Bread一周时间的信息技术中断
16057	Over 92,000 exposed D-Link NAS devices have a backdoor account	https://www.bleepingcomputer.com/news/security/over-92-000-exposed-d-link-nas-devices-have-a-backdoor-account/	bleepingcomputer	news;Security;	1	2024-04-06	超过92 000个接触D-Link NAS装置的D-Link NAS装置有一个后门账户
15965	Jackson County Missouri Ransomware Attack Impacts IT Systems	https://gbhackers.com/jackson-county-missouri-ransomware-attack/	GBHacker	news;cyber security;Cyber Security News;Ransomware;computer security;ransomware;	2	2024-04-03	密苏里州密苏里Ransomware 攻击冲击信息技术系统
16056	New Latrodectus malware replaces IcedID in network breaches	https://www.bleepingcomputer.com/news/security/new-latrodectus-malware-replaces-icedid-in-network-breaches/	bleepingcomputer	news;Security;	1	2024-04-04	在网络破坏时替换 IcedID 。
18776	AI Scam Calls: How to Protect Yourself, How to Detect	https://www.wired.com/story/how-to-protect-yourself-ai-scam-calls-detect/	wired	news;Security;Security / Security Advice;Gear / How To and Advice;	1	2024-04-08	AI Scam 呼吁:如何保护自己,如何侦测
16052	Acuity confirms hackers stole non-sensitive govt data from GitHub repos	https://www.bleepingcomputer.com/news/security/acuity-confirms-hackers-stole-non-sensitive-govt-data-from-github-repos/	bleepingcomputer	news;Security;	1	2024-04-05	Acuity确认黑客盗取GitHub的不敏感的政府数据
16038	Mispadu Trojan Targets Europe, Thousands of Credentials Compromised	https://thehackernews.com/2024/04/mispadu-trojan-targets-europe-thousands.html	feedburner	news;	1	2024-04-03	Mispadu Trojan 目标欧洲, 数千份全权证书
15864	Owl Talon 3 provides hardware-enforced, one-way data transfers	https://www.helpnetsecurity.com/2024/04/03/owl-talon-3/	helpnetsecurity	news;News;Owl Cyber Defense Solutions;	1	2024-04-03	Owl Talon 3 提供硬件强化单向数据传输
16055	New Ivanti RCE flaw may impact 16,000 exposed VPN gateways	https://www.bleepingcomputer.com/news/security/new-ivanti-rce-flaw-may-impact-16-000-exposed-vpn-gateways/	bleepingcomputer	news;Security;	1	2024-04-05	新的Ivanti RCE缺陷可能影响到16,000个暴露于VPN的VPN网关
15822	Samhwa-Paint-Ind-Ltd	http://www.ransomfeed.it/index.php?page=post_details&id_post=14086	ransomfeed	ransom;8base;	1	2024-04-03	萨姆瓦-帕图-印地图-利特德
15783	'Unfaking' News: How to Counter Disinformation Campaigns in Global Elections	https://www.darkreading.com/vulnerabilities-threats/unfaking-news-how-to-counter-disinformation-campaigns-in-global-elections	darkreading	news;	1	2024-04-03	“揭露”新闻:如何在全球选举中反假消息运动
15702	TrueMedia.org introduces deepfake detection tool	https://www.helpnetsecurity.com/2024/04/03/truemedia-org-deepfake-detection/	helpnetsecurity	news;Industry news;TrueMedia.org;	1	2024-04-03	TrueMedia.org 介绍深假检测工具
16096	Exploiting Language Models (LLM) with “Virtual Prompt Injection” (VPI)	https://infosecwriteups.com/exploiting-language-models-llm-with-virtual-prompt-injection-vpi-c5d2fe5a6439?source=rss----7b722bfd1b8d---4	infosecwriteups	tech;chatgpt;prompt-engineering;cybersecurity;prompt-injection-attack;artificial-intelligence;	1	2024-04-05	利用语言模型(LLM)和“虚拟快速注射”(VPI)
18796	Watch Out for 'Latrodectus' - This Malware Could Be In Your Inbox	https://thehackernews.com/2024/04/watch-out-for-latrodectus-this-malware.html	feedburner	news;	1	2024-04-08	注意“ 后进Decutus ” - 此恶意可能在您的收件箱中
18801	How to Get CMMC Certified	https://securityboulevard.com/2024/04/how-to-get-cmmc-certified/	securityboulevard	news;Security Bloggers Network;All;Blog;CMMC;	1	2024-04-08	如何获得CMMC认证
16098	What happens when a DNS request is made?	https://infosecwriteups.com/what-happens-when-a-dns-request-is-made-10f26c5501f9?source=rss----7b722bfd1b8d---4	infosecwriteups	tech;dns-servers;dns;networking;network;cybersecurity;	1	2024-04-05	当DNS请求被提出时会怎样?
16099	Apple Users Become the Latest Targets of MFA Attacks	https://blog.knowbe4.com/apple-users-become-targets-of-mfa-attacks	knowbe4	news;Phishing;Security Awareness Training;MFA;	1	2024-04-04	苹果用户成为外交部袭击的最新目标
16100	Catfishing Campaign Targets Members of the UK Government	https://blog.knowbe4.com/catfishing-campaign-targets-members-of-uk-government	knowbe4	news;Spear Phishing;Security Culture;	1	2024-04-04	以联合王国政府成员为对象的加网捕鱼运动
22326	Beware of Encrypted Phishing Attack With Weaponized SVG Files	https://gbhackers.com/beware-of-encrypted-phishing-attack/	GBHacker	news;cyber security;Cyber Security News;Phishing;	1	2024-04-10	使用已加密的 SVG 文件进行加密钓鱼攻击时要当心
16073	Cyberattack Shutters Some Operations at Japanese Lens Manufacturer	https://www.darkreading.com/cyberattacks-data-breaches/cyberattack-shutters-some-operations-at-japanese-lens-manufacturer	darkreading	news;	1	2024-04-04	日本冷心制造厂的一些操作
16075	Why Cybersecurity Is a Whole-of-Society Issue	https://www.darkreading.com/cyberattacks-data-breaches/why-cybersecurity-is-whole-of-society-issue	darkreading	news;	1	2024-04-03	网络安全为何是一个全社会问题?
16076	AI's Dual Role in SMB Brand Spoofing	https://www.darkreading.com/cybersecurity-analytics/ai-dual-role-smb-brand-spoofing	darkreading	news;	1	2024-04-04	AI在SMB品牌涂鸦中的双重作用
16077	Singapore Sets High Bar in Cybersecurity Preparedness	https://www.darkreading.com/cybersecurity-analytics/singapore-sets-high-bar-in-cybersecurity-preparedness	darkreading	news;	1	2024-04-04	新加坡设置网络安全戒备高律师协会
16078	Action1 Unveils 'School Defense' Program To Help Small Educational Institutions Thwart Cyberattacks	https://www.darkreading.com/cybersecurity-operations/action1-unveils-school-defense-program-to-help-small-educational-institutions-thwart-cyberattacks	darkreading	news;	1	2024-04-04	Action1 联合“学校防御”方案,帮助小型教育机构进行网络攻击
16079	The Biggest Mistake Security Teams Make When Buying Tools	https://www.darkreading.com/cybersecurity-operations/biggest-mistake-security-teams-make-when-buying-tools	darkreading	news;	1	2024-04-03	买工具时最大的错误安全团队
20186	SINEC Security Guard identifies vulnerable production assets	https://www.helpnetsecurity.com/2024/04/09/siemens-sinec-security-guard/	helpnetsecurity	news;Industry news;Siemens;	1	2024-04-09	SINEC 保安警卫队查明脆弱生产资产
16080	Omni Hotel IT Outage Disrupts Reservations, Digital Key Systems	https://www.darkreading.com/cybersecurity-operations/omni-hotel-it-outage-causes-operational-disruptions	darkreading	news;	1	2024-04-03	Omni Hotel IT 外部信息技术
20221	Supporting Cross Domain Solutions	https://securityboulevard.com/2024/04/supporting-cross-domain-solutions/	securityboulevard	news;Security Bloggers Network;Solution Briefs;	1	2024-04-08	支持跨域解决方案
16081	Panera Bread Fuels Ransomware Suspicions With Silence	https://www.darkreading.com/cybersecurity-operations/panera-bread-outage-leads-to-frustrated-customers	darkreading	news;	2	2024-04-05	静静的预感
16084	Critical Security Flaw Exposes 1 Million WordPress Sites to SQL Injection	https://www.darkreading.com/remote-workforce/critical-security-flaw-wordpress-sql-injection	darkreading	news;	1	2024-04-04	SQL 输入的100万个单词新闻站点
16085	Ivanti Pledges Security Overhaul the Day After 4 More Vulns Disclosed	https://www.darkreading.com/remote-workforce/ivanti-ceo-commits-to-security-overhaul-day-after-vendor-discloses-4-more-vulns	darkreading	news;	1	2024-04-04	伊凡提保证安全,
16086	Thousands of Australian Businesses Targeted With 'Reliable' Agent Tesla RAT	https://www.darkreading.com/remote-workforce/thousands-of-australian-businesses-targeted-with-agent-tesla-rat	darkreading	news;	1	2024-04-04	数千家澳大利亚企业以“可靠”Tesla RAT探员为目标
16087	LockBit Ransomware Takedown Strikes Deep Into Brand's Viability	https://www.darkreading.com/threat-intelligence/lockbit-ransomware-takedown-strikes-brand-viability	darkreading	news;	3	2024-04-03	Lock Bit Ransomware 实战击打 深入品牌的可耐性
16088	Malicious Latrodectus Downloader Picks Up Where QBot Left Off	https://www.darkreading.com/threat-intelligence/new-loader-takes-over-where-qbot-left-off	darkreading	news;	1	2024-04-04	QBot 离开位置的恶意 Latrodectus 下载器采集器
16089	SEXi Ransomware Desires VMware Hypervisors in Ongoing Campaign	https://www.darkreading.com/threat-intelligence/sexi-ransomware-desires-vmware-hypervisors	darkreading	news;	2	2024-04-04	Sexi Ransomware 在进行中运动中的VMwar超视仪
16091	ADOKit - Azure DevOps Services Attack Toolkit	http://www.kitploit.com/2024/04/adokit-azure-devops-services-attack.html	kitploit	tool;ADOKit;Toolkit;X-force;Yara;	1	2024-04-06	ADOKit - Azure DevOps服务攻击工具包
16093	Chiasmodon - An OSINT Tool Designed To Assist In The Process Of Gathering Information About A Target Domain	http://www.kitploit.com/2024/04/chiasmodon-osint-tool-designed-to.html	kitploit	tool;Chiasmodon;	1	2024-04-04	Chiasmodon - 用于协助收集目标域信息过程的OSINT工具
16095	Comprehensive Guide to AWS WAF — Protecting Web Applications	https://infosecwriteups.com/comprehensive-guide-to-aws-waf-protecting-web-applications-23846e4a59ed?source=rss----7b722bfd1b8d---4	infosecwriteups	tech;aws;aws-security;aws-certification;aws-waf;waf;	1	2024-04-05	AWS WAF-保护网络应用综合指南
16129	NIST awards $3.6 million to address the cybersecurity workforce gap	https://www.helpnetsecurity.com/2024/04/04/nist-cooperative-agreements-3-6-million/	helpnetsecurity	news;Industry news;NIST;	1	2024-04-04	NIST授予360万美元,以解决网络安全员工队伍差距问题
16130	Omni Hotels suffer prolonged IT outage due to cyberattack	https://www.helpnetsecurity.com/2024/04/04/omni-hotels-suffer-prolonged-it-outage-due-to-cyberattack/	helpnetsecurity	news;Don't miss;Hot stuff;News;attack;Closed Door Security;cyberattack;cybercrime;hospitality industry;USA;	1	2024-04-04	由于网络攻击,Omni旅馆长期信息技术中断
16131	How manual access reviews might be weakening your defenses	https://www.helpnetsecurity.com/2024/04/05/access-reviews-video/	helpnetsecurity	news;Don't miss;Hot stuff;Video;access management;compliance;cybersecurity;data;regulation;video;Zluri;	1	2024-04-05	人工访问审查会如何削弱你的防御
16133	Cybercriminal adoption of browser fingerprinting	https://www.helpnetsecurity.com/2024/04/05/browser-fingerprinting/	helpnetsecurity	news;Don't miss;Expert analysis;Expert corner;Hot stuff;News;bot;browser;cybercriminals;cybersecurity;Fortra;opinion;phishing;PhishLabs;	1	2024-04-05	网上犯罪采用浏览器指纹指纹
16134	22% of employees admit to breaching company rules with GenAI	https://www.helpnetsecurity.com/2024/04/05/employee-security-productivity-balance/	helpnetsecurity	news;News;1Password;artificial intelligence;cybersecurity;Generative AI;report;survey;	1	2024-04-05	22%的雇员承认与GENAI公司违反公司规则
16135	New infosec products of the week: April 5, 2024	https://www.helpnetsecurity.com/2024/04/05/new-infosec-products-of-the-week-april-5-2024/	helpnetsecurity	news;News;Fastly;LogRhythm;Owl Cyber Defense Solutions;TrueMedia.org;	1	2024-04-05	2024年4月5日 2024年4月5日
16136	Trellix ZTS enables organizations to strengthen cyber resilience	https://www.helpnetsecurity.com/2024/04/05/trellix-zts/	helpnetsecurity	news;Industry news;Trellix;	1	2024-04-05	Trelllix ZTS使各组织能够加强网络复原力
16102	Malicious App Impersonates McAfee to Distribute Malware Via Text and Phone Calls	https://blog.knowbe4.com/malicious-app-impersonates-mcafee-to-distribute-malware	knowbe4	news;Phishing;Security Culture;	1	2024-04-03	McAfee 传播 Malware Via 文本和电话
16103	New Report Shows Phishing Links and Malicious Attachments Are The Top Entry Points of Cyber Attacks	https://blog.knowbe4.com/phishing-and-users-top-list-as-cyberattack-initial-access-enablers	knowbe4	news;Phishing;Spear Phishing;Security Awareness Training;Security Culture;	1	2024-04-03	新报告显示捕捉链接和恶意附件是网络攻击的顶尖切入点
16104	Affirmed Networks breach	https://threats.wiz.io/all-incidents/affirmed-networks-breach	wizio	incident;	1	2024-04-06	经证实的网络被破坏
16105	Fujitsu exposed bucket	https://threats.wiz.io/all-incidents/fujitsu-exposed-bucket	wizio	incident;	1	2024-04-06	藤津露水桶
16106	Top.gg repo compromise	https://threats.wiz.io/all-incidents/topgg-repo-compromise	wizio	incident;	1	2024-04-06	顶级(gg)后级(rpo)妥协
16107	XZ Utils backdoor incident	https://threats.wiz.io/all-incidents/xz-utils-backdoor-incident	wizio	incident;	1	2024-04-06	XZ X 工具后门事件
16108	AI Package Hallucination – Hackers Abusing ChatGPT, Gemini to Spread Malware	https://gbhackers.com/ai-package-hallucination/	GBHacker	news;Uncategorized;	1	2024-04-05	AI 一揽子幻觉 — — 黑客滥用聊天GPT,基米尼传播假软件
16083	CISO Corner: Ivanti's Mea Culpa; World Cup Hack; CISOs &amp; Cyber Awareness	https://www.darkreading.com/remote-workforce/ciso-corner-ivanti-mea-culpa-world-cup-hack-cyber-awareness	darkreading	news;	1	2024-04-05	CISO 角: Ivanti's Mea Culpa; 世界杯Hack; CISOs & amp; 网络意识
16110	10M+ Downloaded Dating App Discloses User’s Exact Location	https://gbhackers.com/app-discloses-location/	GBHacker	news;cyber security;Cyber Security News;	1	2024-04-05	10M+ 下载的约会应用披露显示用户的精确位置
16111	Bing Ads Exploited by Hackers to Spread SecTopRAT Through NordVPN Mimic	https://gbhackers.com/bing-ads-exploited/	GBHacker	news;cyber security;Cyber Security News;vpn;	1	2024-04-05	黑客利用Bing Adds通过NordVPN Mimimic 将 SecTopRAT 扩散到黑客们的Bing Ads
16113	Multiple Ivanti Connect Secure Flaw Let Attackers Execute Remote Code	https://gbhackers.com/ivanti-connect-secure-remote-code-execution-flaws/	GBHacker	news;CVE/vulnerability;cyber security;Network Security;Cyber Security News;Ivanti Vulnerabilities;Remote code execution;	1	2024-04-05	多重 Ivanti 连接安全flaw 让攻击者执行远程代码
16114	Critical Progress Flowmon Vulnerability Let Attackers Inject Malicious Code	https://gbhackers.com/progress-flowmon-vulnerability/	GBHacker	news;CVE/vulnerability;Cyber Security News;Network Security;CVE-2024-2389;cyber security;Progress Flowmon;	1	2024-04-05	让攻击者注入恶意守则
16115	Ransomware Attack Via Unpatched Vulnerabilities Are Brutal: New Survey	https://gbhackers.com/ransomware-attack-unpatched-vulnerabilities/	GBHacker	news;CVE/vulnerability;cyber security;Ransomware;Cybersecurity Risks;Ransomware Vulnerabilities;	2	2024-04-06	Ransomware 攻击 " 无源脆弱性是残酷的:新调查 " 。
16117	YubiKey Manager Privilege Escalation Let Attacker Perform Admin Functions	https://gbhackers.com/yubikey-manager-privilege-escalation/	GBHacker	news;CVE/vulnerability;Cyber Security News;Security Updates;computer security;Vulnerability;YubiKey Vulnerability;	1	2024-04-05	YubiKey 管理者 Privilge Escapeation 让攻击者履行管理职能
16121	虚拟专用网络安装包“引狼入室”：疑似金眼狗（APT-Q-27）团伙的窃密行动	https://www.freebuf.com/articles/paper/396978.html	freebuf	news;安全报告;	2	2024-04-03	虚拟专用网络安装包“引狼入室”：疑似金眼狗（APT-Q-27）团伙的窃密行动
16124	FreeBuf 早报 | 全球首个涉AI安全双边协议签署；Omni酒店出现全国性IT故障	https://www.freebuf.com/news/396890.html	freebuf	news;资讯;	1	2024-04-03	FreeBuf 早报 | 全球首个涉AI安全双边协议签署；Omni酒店出现全国性IT故障
16125	FreeBuf 周报 | Vultur 安卓银行木马“卷土重来”；黑客滥用谷歌虚假广告传播恶意软件	https://www.freebuf.com/news/396918.html	freebuf	news;资讯;	2	2024-04-03	FreeBuf 周报 | Vultur 安卓银行木马“卷土重来”；黑客滥用谷歌虚假广告传播恶意软件
16128	Ivanti vows to transform its security operating model, reveals new vulnerabilities	https://www.helpnetsecurity.com/2024/04/04/ivanti-connect-secure-vulnerabilities/	helpnetsecurity	news;Don't miss;Hot stuff;News;enterprise;Ivanti;VPN;vulnerability;vulnerability management;	1	2024-04-04	Ivanti誓言改变其安全操作模式 暴露出新的弱点
16155	From PDFs to Payload: Bogus Adobe Acrobat Reader Installers Distribute Byakugan Malware	https://thehackernews.com/2024/04/from-pdfs-to-payload-bogus-adobe.html	feedburner	news;	1	2024-04-05	从 PDFs 到有效载荷: Bogus Adobe Acrobat 阅读器安装器
16157	Google Warns: Android Zero-Day Flaws in Pixel Phones Exploited by Forensic Companies	https://thehackernews.com/2024/04/google-warns-android-zero-day-flaws-in.html	feedburner	news;	2	2024-04-03	Google Warns:法证公司在像素电话中利用的无日无日的机器人法
16158	Hackers Exploit Magento Bug to Steal Payment Data from E-commerce Websites	https://thehackernews.com/2024/04/hackers-exploit-magento-bug-to-steal.html	feedburner	news;	1	2024-04-06	Hackers 利用Magento Bug从电子商务网站窃取付款数据
16159	Ivanti Rushes Patches for 4 New Flaws in Connect Secure and Policy Secure	https://thehackernews.com/2024/04/ivanti-rushes-patches-for-4-new-flaw-in.html	feedburner	news;	1	2024-04-04	Ivanti Rushes 4项连接安全和政策安全新法补丁
16161	New HTTP/2 Vulnerability Exposes Web Servers to DoS Attacks	https://thehackernews.com/2024/04/new-http2-vulnerability-exposes-web.html	feedburner	news;	1	2024-04-04	新建的HTTP/2 脆弱性暴露网络服务器用于 DoS 攻击
16163	New Wave of JSOutProx Malware Targeting Financial Firms in APAC and MENA	https://thehackernews.com/2024/04/new-wave-of-jsoutprox-malware-targeting.html	feedburner	news;	1	2024-04-05	APAC和MENA的JSOTProx恶意针对金融公司的新浪潮
16164	Researchers Identify Multiple China Hacker Groups Exploiting Ivanti Security Flaws	https://thehackernews.com/2024/04/researchers-identify-multiple-china.html	feedburner	news;	4	2024-04-05	研究者确定多中国黑客集团 利用伊万提安全法
16165	U.S. Cyber Safety Board Slams Microsoft Over Breach by China-Based Hackers	https://thehackernews.com/2024/04/us-cyber-safety-board-slams-microsoft.html	feedburner	news;	4	2024-04-03	美国网络安全委员会 打击微软 防止中国黑客侵入
16166	Vietnam-Based Hackers Steal Financial Data Across Asia with Malware	https://thehackernews.com/2024/04/vietnam-based-hackers-steal-financial.html	feedburner	news;	1	2024-04-04	以越南为基地的黑客与Malware一起在整个亚洲窃取金融数据
16168	Data Privacy in Email Communication: Compliance, Risks, and Best Practices	https://securityboulevard.com/2024/04/data-privacy-in-email-communication-compliance-risks-and-best-practices/	securityboulevard	news;Security Bloggers Network;Cybersecurity;	1	2024-04-05	电子邮件通信中的数据隐私:合规、风险和最佳做法
16137	Get end-to-end protection with Microsoft’s unified security operations platform, now in public preview	https://www.microsoft.com/en-us/security/blog/2024/04/03/get-end-to-end-protection-with-microsofts-unified-security-operations-platform-now-in-public-preview/	microsoft	news;	1	2024-04-03	利用微软的统一安保行动平台获得端到端保护,现在公开预览
16138	CTS-QR-by-oretnom23-v1.0-Multiple-SQLi	https://www.nu11secur1ty.com/2024/04/cts-qr-by-oretnom23-v10-multiple-sqli.html	nu11security	vuln;	1	2024-04-03	CTS- QR by- ertnom23- v1.0- 多元 SQLi
16139	strapi-4.22.0.* CORS-Vulnerability	https://www.nu11secur1ty.com/2024/04/strapi-4220-cors-vulnerability.html	nu11security	vuln;	1	2024-04-04	-4.22.0.* CORS-可塑性
16140	Identity Thief Lived as a Different Man for 33 Years	https://www.wired.com/story/identity-thief-lived-as-a-different-man-for-33-years/	wired	news;Security;Security / Cyberattacks and Hacks;Security / National Security;Security / Privacy;Security / Security News;	1	2024-04-06	以不同人的身份生活了33年
16141	The Mystery of ‘Jia Tan,’ the XZ Backdoor Mastermind	https://www.wired.com/story/jia-tan-xz-backdoor/	wired	news;Security;Security / Cyberattacks and Hacks;Security / Security News;	1	2024-04-03	XZ后门万能魔术师 " Jia Tan " 的神秘
16142	A Vigilante Hacker Took Down North Korea’s Internet. Now He’s Taking Off His Mask	https://www.wired.com/story/p4x-north-korea-internet-hacker-identity-reveal/	wired	news;Security;Security / Cyberattacks and Hacks;Security / National Security;Security / Security News;	3	2024-04-04	哈克尔治安维持者占领了北朝鲜的互联网。 现在,他正在揭开面具。
16109	Oxycorat Android RAT Spotted on Dark Web Stealing Wi-Fi Passwords	https://gbhackers.com/android-rat-dark-web/	GBHacker	news;Android;Cyber Security News;Data Breach;	2	2024-04-05	Oxycorat 和机器人 RAT 出现在暗网窃取无线密码
16144	Hack The Box: Codify Machine Walkthrough – Easy Difficulty	https://threatninja.net/2024/04/hack-the-box-codify-machine-walkthrough-easy-difficulty/	threatninja	sectest;Easy Machine;BurpSuite;Challenges;HackTheBox;hashcat;john the ripper;Linux;Penetration Testing;sqlite3;ssh;	1	2024-04-06	Hack 黑盒:把机器编成法典 — — 容易困难
16145	Congress prepares for FISA Round 3	https://therecord.media/fisa-section-702-renewal-third-try-house-johnson	therecord	ransom;Government;News;Technology;Privacy;	1	2024-04-05	国会筹备FISA第3回合
16146	Germany to launch cyber military branch to combat Russian threats	https://therecord.media/germany-to-launch-cyber-military-unit-russia	therecord	ransom;Cybercrime;Government;Leadership;News;News Briefs;	3	2024-04-05	德国建立打击俄罗斯威胁的网络军事部门
16147	US Chamber of Commerce, industry groups call for 30-day delay in CIRCIA rules	https://therecord.media/industry-groups-call-for-delay-circia-commenting	therecord	ransom;Government;News;Leadership;	1	2024-04-05	美国商会、工业集团要求将CIRCIA规则推迟30天
16149	Pacific Guardian Life Insurance says 165,000 had financial info stolen in 2023 attack	https://therecord.media/pacific-guardian-life-insurance-data-breach	therecord	ransom;Cybercrime;News Briefs;News;	1	2024-04-05	太平洋卫报人寿保险公司说 2023年袭击中 16万5千个金融信息被盗
16150	AI-as-a-Service Providers Vulnerable to PrivEsc and Cross-Tenant Attacks	https://thehackernews.com/2024/04/ai-as-service-providers-vulnerable-to.html	feedburner	news;	1	2024-04-05	易遭受普里夫埃斯克和交叉袭击
16151	Attack Surface Management vs. Vulnerability Management	https://thehackernews.com/2024/04/attack-surface-management-vs.html	feedburner	news;	1	2024-04-03	地面管理与脆弱性管理
16152	CISO Perspectives on Complying with Cybersecurity Regulations	https://thehackernews.com/2024/04/ciso-perspectives-on-complying-with.html	feedburner	news;	1	2024-04-05	CISO 关于遵守网络安全条例的观点
16153	Considerations for Operational Technology Cybersecurity	https://thehackernews.com/2024/04/considerations-for-operational.html	feedburner	news;	1	2024-04-04	实用技术网络安全考虑
22327	Cypago Announces New Automation Support for AI Security & Governance	https://gbhackers.com/cypago-announces-new-automation-support/	GBHacker	news;Press Release;	1	2024-04-10	Cypago 宣布对 AI 安全和治理的新自动化支持
16171	Ivanti CEO Promises Stronger Security After a Year of Flaws	https://securityboulevard.com/2024/04/ivanti-ceo-promises-stronger-security-after-a-year-of-flaws/	securityboulevard	news;Cloud Security;Cybersecurity;Data Security;Featured;Malware;Network Security;News;Security Boulevard (Original);Social - Facebook;Social - LinkedIn;Social - X;Spotlight;Threat Intelligence;Vulnerabilities;China-linked Hackers;Ivanti Vulnerabilities;	1	2024-04-05	Ivanti CEO 保证在一年法律年之后加强安全
22333	Match Systems publishes report on the consequences of CBDC implementation	https://gbhackers.com/the-consequences-of-cbdc-implementation/	GBHacker	news;Press Release;	1	2024-04-10	Match Systems出版关于实施《生物多样性公约》的后果的报告
16174	CISA Unveils Critical Infrastructure Reporting Rule	https://securityboulevard.com/2024/04/under-the-new-rule-covered-entities-must-report-significant-cyber-incidents-within-72-hours-of-discovery-along-with-ransom-payments-within-24-hours/	securityboulevard	news;Cybersecurity;Featured;Governance, Risk & Compliance;News;Ransomware;Regulatory Compliance;Security Boulevard (Original);Social - X;Uncategorized;cisa;Compliance;government;Infrastructure;reporting;	1	2024-04-05	CISA 关键基础设施报告规则
15654	绿盟威胁情报月报-2024年3月	https://blog.nsfocus.net/monthlyreport202403/	绿盟	news;威胁通告;威胁防护;月报;	1	2024-04-03	绿盟威胁情报月报-2024年3月
16173	Small business cyber security guide: What you should prioritize & where you should spend your budget	https://securityboulevard.com/2024/04/small-business-cyber-security-guide-what-you-should-prioritize-where-you-should-spend-your-budget/	securityboulevard	news;Careers;DevOps;Security Awareness;Security Bloggers Network;CISO Suite;Creating Active Awareness;Cyber Security Risks;Employee Awareness;guide;Home;Privacy;Security Culture;Seed n soil posts;small business;tips;	1	2024-04-05	小企业网络安全指南:你应该优先考虑什么,以及你应该在哪里花费预算
16176	xz backdoor Part 2: On the Importance of Runtime Security in the Age of OSS Backdoors	https://securityboulevard.com/2024/04/xz-backdoor-part-2-on-the-importance-of-runtime-security-in-the-age-of-oss-backdoors/	securityboulevard	news;Security Bloggers Network;Uncategorized;	1	2024-04-05	第二部分:开放源码软件后门时代运行时安全的重要性
22328	GHC-SCW Hack: Ransomware Actors Stolen User’s Personal Information	https://gbhackers.com/ghc-scw-hack/	GBHacker	news;cyber security;Cyber Security News;Ransomware;ransomware;	2	2024-04-10	GHC-SCW Hack: 窃取用户个人信息
16175	When Man Pages Go Weird	https://securityboulevard.com/2024/04/when-man-pages-go-weird/	securityboulevard	news;Security Bloggers Network;coreutils;Diversions;Linux;	1	2024-04-05	当曼页变怪异
16051	Recent Windows updates break Microsoft Connected Cache delivery	https://www.bleepingcomputer.com/news/microsoft/recent-windows-updates-break-microsoft-connected-cache-delivery/	bleepingcomputer	news;Microsoft;	1	2024-04-05	最近的 Windows 更新中断 Microsoft 连接快取交付
22330	Real-World Law Enforcement Hack of Hackers End-to-Encrypted Chat Messenger	https://gbhackers.com/real-world-law-enforcement-hack-of-end-to-encrypted-chat-messanger/	GBHacker	news;Cyber Attack;Cyber Crime;cyber security;Cyber Security News;Malware;Vulnerability;	1	2024-04-10	真正的世界执法组织黑客终至加密聊天信使的黑客黑包
16170	Ghostwriter v4.1: The Custom Fields Update	https://securityboulevard.com/2024/04/ghostwriter-v4-1-the-custom-fields-update/	securityboulevard	news;Application Security;Security Bloggers Network;Social Engineering;Cybersecurity;Penetration Testing;Project Management;Red Team;reporting;	1	2024-04-05	Ghostwriter v4.1: 海关字段更新
16092	Attackgen - Cybersecurity Incident Response Testing Tool That Leverages The Power Of Large Language Models And The Comprehensive MITRE ATT&CK Framework	http://www.kitploit.com/2024/04/attackgen-cybersecurity-incident.html	kitploit	tool;Attackgen;Markdown;Mitre;Openai;Performance;Processes;Python;	1	2024-04-05	攻击 - 利用大语言模型和综合MITRE ATT&CK框架的网络安全事件应对测试工具
22329	Microsoft Patch Tuesday: 149 Security Vulnerabilities & Zero-days	https://gbhackers.com/microsoft-patch-tuesday-3/	GBHacker	news;Cyber Security News;Malware;Microsoft;CVE-2024;Microsoft Patch Tuesday;Security Vulnerabilities;	1	2024-04-10	星期二微软补丁:149个安全脆弱性和零日
8456	USENIX Security ’23 – Yuzhou Feng, Ruyu Zhai, Radu Sion, Bogdan Carbunar – A Study Of China’s Censorship And Its Evasion Through The Lens Of Online Gaming	https://securityboulevard.com/2024/03/usenix-security-23-yuzhou-feng-ruyu-zhai-radu-sion-bogdan-carbunar-a-study-of-chinas-censorship-and-its-evasion-through-the-lens-of-online-gaming/	securityboulevard	news;Security Bloggers Network;Open Access Research;Security Conferences;USENIX;USENIX Security ’23;	4	2024-03-19	USENIX 安全 23 — — Yuzhou Feng, Ruyu Zhai, Radu Sion, Bogdan Carbunar — — 关于中国审查及其通过在线赌的镜头进行规避的研究
16172	Salt Security Applies Generative AI to API Security	https://securityboulevard.com/2024/04/salt-security-applies-generative-ai-to-api-security/	securityboulevard	news;AI and ML in Security;API Security;Application Security;Cybersecurity;Featured;News;Security Boulevard (Original);AI Tools;API security;pepper;Salt Security;	1	2024-04-05	盐盐安全套用 API 安全生成的AI
16156	Google Chrome Beta Tests New DBSC Protection Against Cookie-Stealing Attacks	https://thehackernews.com/2024/04/google-chrome-beta-tests-new-dbsc.html	feedburner	news;	1	2024-04-03	Google Chrome Beta 测试新的DBSC 防止Cookie-偷窃式袭击的新DBSC
16090	White House's Call for Memory Safety Brings Challenges, Changes &amp; Costs	https://www.darkreading.com/vulnerabilities-threats/white-house-call-for-memory-safety-brings-challenges-changes-costs	darkreading	news;	1	2024-04-05	白宫呼吁记忆安全带来挑战、改变和amp; 成本
16112	Hackers Hijack Facebook Pages to Mimic AI Brands & Inject Malware	https://gbhackers.com/hijack-facebook-pages/	GBHacker	news;cyber security;Cyber Security News;FACEBOOK;Malware;	1	2024-04-05	Mimic AI 品牌与喷射 Maware 的Hackers Hackers Hackers Hackers 黑客Facebook页面
16162	New Phishing Campaign Targets Oil & Gas with Evolved Data-Stealing Malware	https://thehackernews.com/2024/04/new-phishing-campaign-targets-oil-gas.html	feedburner	news;	1	2024-04-04	新的捕捉运动以石油和天然气为对象,并配以数据转换换制的恶意软件
16148	Attempted hack on NYC continues wave of cyberattacks against municipal governments	https://therecord.media/new-york-city-government-smishing-attack	therecord	ransom;Government;Cybercrime;News;	1	2024-04-05	企图侵入纽约市, 继续不断对市政府进行网络攻击,
18807	Google rolls out new Find My Device network to Android devices	https://www.bleepingcomputer.com/news/google/google-rolls-out-new-find-my-device-network-to-android-devices/	bleepingcomputer	news;Google;	2	2024-04-08	Google向Android 设备推出新的发现我的设备网络
16127	Avast One Silver allows users to tailor their coverage based upon their personal preferences	https://www.helpnetsecurity.com/2024/04/04/avast-one-silver/	helpnetsecurity	news;Industry news;Avast;	1	2024-04-04	Avast One Silver 允许用户根据个人喜好调整其覆盖范围
16116	Winnti Hackers’ New UNAPIMON Tool Hijacks DLL And Unhook API Calls	https://gbhackers.com/winnti-unapimon-unhook/	GBHacker	news;Cyber Attack;cyber security;Malware;API Unhooking;computer security;Cyber Security News;DLL Hijacking;	1	2024-04-05	Winnti Hackers 的新 UAPIMON 工具入侵 DLL 和 HULook APIP 呼叫
16132	Security pros are cautiously optimistic about AI	https://www.helpnetsecurity.com/2024/04/05/ai-integration-cybersecurity/	helpnetsecurity	news;News;artificial intelligence;Cloud Security Alliance;cybersecurity;Generative AI;Google Cloud;report;survey;	1	2024-04-05	安全支持者对AI持谨慎乐观的乐观态度。
8812	新手法！APT28组织最新后门内置大量被控邮箱（可成功登录）用于窃取数据	https://xz.aliyun.com/t/14123	阿里先知实验室	news;	2	2024-03-18	新手法！APT28组织最新后门内置大量被控邮箱（可成功登录）用于窃取数据
18811	Critical RCE bug in 92,000 D-Link NAS devices now exploited in attacks	https://www.bleepingcomputer.com/news/security/critical-rce-bug-in-92-000-d-link-nas-devices-now-exploited-in-attacks/	bleepingcomputer	news;Security;	1	2024-04-08	现在在攻击中使用的92 000台D-链接NAS装置中的临界RCE错误
18812	Cyberattack on UK’s CVS Group disrupts veterinary operations	https://www.bleepingcomputer.com/news/security/cyberattack-on-uks-cvs-group-disrupts-veterinary-operations/	bleepingcomputer	news;Security;Healthcare;	1	2024-04-08	对英国CVS集团的网络攻击扰乱了兽医业务
16844	Facebook、Instagram将显著标记由AI生成的音视频内容	https://www.freebuf.com/news/397077.html	freebuf	news;资讯;	1	2024-04-07	Facebook、Instagram将显著标记由AI生成的音视频内容
10954	Polyglot Files: The Cybersecurity Chameleon Threat	https://infosecwriteups.com/polyglot-files-the-cybersecurity-chameleon-threat-29890e382b59?source=rss----7b722bfd1b8d---4	infosecwriteups	tech;polyglot;cybersecurity;obfuscation;bug-bounty;penetration-testing;	1	2024-03-29	网络安全变色龙威胁
22359	Concentric AI unveils employee offboarding risk monitoring and reporting module	https://www.helpnetsecurity.com/2024/04/10/concentric-ai-employee-offboarding-risk-monitoring/	helpnetsecurity	news;Industry news;Concentric AI;	1	2024-04-10	与心心一致的大赦国际揭开雇员离上岸风险监测和报告模块
18834	CloudGrappler - A purpose-built tool designed for effortless querying of high-fidelity and single-event detections related to well-known threat actors in popular cloud environments such as AWS and Azure	http://www.kitploit.com/2024/04/cloudgrappler-purpose-built-tool.html	kitploit	tool;CloudGrappler;Python3;Scan;Scanning;	1	2024-04-08	CloudGraprler - 一种专门设计的工具,旨在不费力地查询与AWS和Azure等广受欢迎的云环境中众所周知的威胁行为者有关的高忠度和单一事件探测
18824	Home Depot Hammered by Supply Chain Data Breach	https://www.darkreading.com/cyberattacks-data-breaches/home-depot-hammered-by-supply-chain-data-breach	darkreading	news;	1	2024-04-08	被供应链数据突破所没收的家用垃圾桶
22362	Index Engines CyberSense 8.6 detects malicious activity	https://www.helpnetsecurity.com/2024/04/10/index-engines-cybersense-8-6/	helpnetsecurity	news;Industry news;Index Engines;	1	2024-04-10	网络警报8.6检测恶意活动
18820	StrikeReady Raises $12M for AI Security Command Platform	https://www.darkreading.com/application-security/strikeready-raises-12m-for-ai-security-command-platform-purpose-built-for-modern-soc-teams	darkreading	news;	1	2024-04-08	StrimeReady 提高1200美元,用于AI安全指挥平台
22360	New covert SharePoint data exfiltration techniques revealed	https://www.helpnetsecurity.com/2024/04/10/covert-sharepoint-data-exfiltration/	helpnetsecurity	news;Don't miss;Hot stuff;News;Data exfiltration;data theft;enterprise;logging;SharePoint;Varonis;	1	2024-04-10	暴露出新隐蔽的 SharePoint 数据数据泄漏技术
18825	Round 2: Change Healthcare Targeted in Second Ransomware Attack	https://www.darkreading.com/cyberattacks-data-breaches/round-2-change-healthcare-targeted-second-ransomware-attack	darkreading	news;	2	2024-04-08	第二回合:改变保健,针对第二轮雷作软件攻击
18826	The Fight for Cybersecurity Awareness	https://www.darkreading.com/cybersecurity-operations/fight-for-cybersecurity-awareness	darkreading	news;	1	2024-04-08	争取网络安全意识
22334	Flaws in 90,000+ LG WebOS TVs Let Attacker’s Completely take Over Devices	https://gbhackers.com/webos-tvs-let-attackers/	GBHacker	news;cyber security;Cyber Security News;	1	2024-04-10	90,000+LG WebOS TV 的条条让攻击者完全接管设备
18828	Software-Defined Vehicle Fleets Face a Twisty Road on Cybersecurity	https://www.darkreading.com/ics-ot-security/software-defined-vehicle-fleets-twisty-road-cybersecurity	darkreading	news;	1	2024-04-08	软件定义的车辆车队面对网络安全道路上的曲曲曲道路
22361	Eclypsium Automata discovers vulnerabilities in IT infrastructure	https://www.helpnetsecurity.com/2024/04/10/eclypsium-automata/	helpnetsecurity	news;Industry news;Eclypsium;	1	2024-04-10	Automata 发现信息技术基础设施的脆弱性
18813	Hackers deploy crypto drainers on thousands of WordPress sites	https://www.bleepingcomputer.com/news/security/hackers-deploy-crypto-drainers-on-thousands-of-wordpress-sites/	bleepingcomputer	news;Security;CryptoCurrency;	1	2024-04-08	黑客在数千个WordPress站点部署加密排水器
16565	注意！GenAI 模型存在接管风险	https://www.freebuf.com/news/397056.html	freebuf	news;资讯;	1	2024-04-07	注意！GenAI 模型存在接管风险
16705	HCI-Systems-Inc-	http://www.ransomfeed.it/index.php?page=post_details&id_post=14137	ransomfeed	ransom;ransomhub;	1	2024-04-06	HCI - 系统系统 - Inc -
22355	FreeBuf早报 | 上万台LG电视机容易被黑客控制；微信宣布打击租售微信账号行为	https://www.freebuf.com/news/397535.html	freebuf	news;资讯;	1	2024-04-10	FreeBuf早报 | 上万台LG电视机容易被黑客控制；微信宣布打击租售微信账号行为
22358	Cohesity teams up with Intel to integrate confidential computing into Data Cloud Services	https://www.helpnetsecurity.com/2024/04/10/cohesity-intel/	helpnetsecurity	news;Industry news;Cohesity;Intel;	1	2024-04-10	与英特尔公司联调小组,将机密计算纳入数据云服务
22342	CoralRaider勒索组织窃取亚洲金融机构数据事件解析	https://www.freebuf.com/articles/neopoints/397365.html	freebuf	news;观点;	1	2024-04-09	CoralRaider勒索组织窃取亚洲金融机构数据事件解析
26279	小米SU7顶配版原定价35万 	https://s.weibo.com/weibo?q=%23小米SU7顶配版原定价35万 %23	sina.weibo	hotsearch;weibo	1	2024-03-29	小米SU7顶配版原定价35万
16143	Best Privacy Browsers (2024): Brave, Safari, Ghostery, Firefox, DuckDuckGo	https://www.wired.com/story/privacy-browsers-duckduckgo-ghostery-brave/	wired	news;Security;Security / Security Advice;	1	2024-04-06	最佳隐私浏览器 (2024年): 勇敢、 法利、 鬼鬼、 火狐、 DuckDuckGo
16566	美国APT的全球流量监听系统（Turmoil监听与Turbine涡轮）讲解与分析	https://www.freebuf.com/news/397072.html	freebuf	news;资讯;	2	2024-04-07	美国APT的全球流量监听系统（Turmoil监听与Turbine涡轮）讲解与分析
19442	Exploring How Penetration Tests Are Classified – Pentesting Aspirant Guide 2024	https://gbhackers.com/penetration-tests/	GBHacker	news;Penetration Testing;What is;Cyber Security News;	3	2024-04-09	探索穿透试验如何分类化 — — Pentauration Aspirant 指南 2024
26280	小米SU7首发共9款颜色 	https://s.weibo.com/weibo?q=%23小米SU7首发共9款颜色 %23	sina.weibo	hotsearch;weibo	1	2024-03-28	小米SU7首发共9款颜色
26281	小米SU7首发评测 	https://s.weibo.com/weibo?q=%23小米SU7首发评测 %23	sina.weibo	hotsearch;weibo	1	2024-03-29	小米SU7首发评测
26282	小米su7 	https://s.weibo.com/weibo?q=%23小米su7 %23	sina.weibo	hotsearch;weibo	1	2024-03-25	小米su7
26283	小米人车家全生态全球首测 	https://s.weibo.com/weibo?q=%23小米人车家全生态全球首测 %23	sina.weibo	hotsearch;weibo	1	2024-02-23	小米人车家全生态全球首测
17309	一次代码审计中发现的小tips	https://xz.aliyun.com/t/14249	阿里先知实验室	news;	1	2024-04-05	一次代码审计中发现的小tips
16981	easchangesystems	http://www.ransomfeed.it/index.php?page=post_details&id_post=14141	ransomfeed	ransom;qilin;	1	2024-04-07	eAS 交换系统
17310	VirusTotal食用指南（非付费项目）	https://xz.aliyun.com/t/14250	阿里先知实验室	news;	1	2024-04-06	VirusTotal食用指南（非付费项目）
37	New Python-Based Snake Info Stealer Spreading Through Facebook Messages	https://thehackernews.com/2024/03/new-python-based-snake-info-stealer.html	feedburner	news;	1	2024-03-07	新建的以蛇为基地的 Python Infe Insteiner 通过Facebook 信息传播
17311	APK逆向分析-以某音频转文字工具为例	https://xz.aliyun.com/t/14252	阿里先知实验室	news;	1	2024-04-06	APK逆向分析-以某音频转文字工具为例
18879	Bitdefender Digital Identity Protection guards against web data leaks	https://www.helpnetsecurity.com/2024/04/08/bitdefender-digital-identity-protection-2/	helpnetsecurity	news;Industry news;Bitdefender;	1	2024-04-08	Bitdefender 数字身份保护警卫,防止网络数据泄漏
18881	XZ Utils backdoor: Detection tools, scripts, rules	https://www.helpnetsecurity.com/2024/04/08/detect-xz-backdoor/	helpnetsecurity	news;Don't miss;Hot stuff;News;backdoor;Binarly;Bitdefender;Elastic;GitHub;Linux;open source;supply chain compromise;	1	2024-04-08	XZ 后门工具:侦测工具、脚本、规则
17312	格式化字符串漏洞原理及其利用详解（附带例题讲解）	https://xz.aliyun.com/t/14253	阿里先知实验室	news;	3	2024-04-06	格式化字符串漏洞原理及其利用详解（附带例题讲解）
17307	浏览器凭据获取 -- Cookies && Password	https://xz.aliyun.com/t/14245	阿里先知实验室	news;	1	2024-04-04	浏览器凭据获取 -- Cookies && Password
4	New Backdoor Targeting European Officials Linked to Indian Diplomatic Events	https://thehackernews.com/2024/02/new-backdoor-targeting-european.html	feedburner	news;	1	2024-02-29	与印度外交活动有关的新的后门针对欧洲官员
18846	Australian Government Commits to Become a World-Leader in Cybersecurity by 2030	https://blog.knowbe4.com/australian-government-commits-world-leader-cybersecurity-by-2030	knowbe4	news;Phishing;Security Culture;	1	2024-04-08	澳大利亚政府承诺到2030年成为网络安全领域的世界领导者
18848	Tokyo Police Department Warns of Phishing Scam That Uses Phony Arrest Warrants	https://blog.knowbe4.com/tokyo-police-department-warns-phishing	knowbe4	news;Phishing;	1	2024-04-08	东京警察局使用假逮捕证的钓鱼法片警示警告
18850	AGENT TESLA Malware Steals login Credentials From Chrome & Firefox	https://gbhackers.com/agent-tesla-malware-steals-login-credentials-from-chrome-firefox/	GBHacker	news;Uncategorized;Cyber Security News;Malware;	1	2024-04-08	AGENT TESLA 恶意盗窃从铬和火焰中登录的证书
17296	一周网安优质PDF资源推荐丨FreeBuf知识大陆	https://www.freebuf.com/news/397104.html	freebuf	news;资讯;	1	2024-04-07	一周网安优质PDF资源推荐丨FreeBuf知识大陆
18853	Cisco IOS Vulnerability Allows DOS Attacks via Malicious Traffic	https://gbhackers.com/cisco-ios-vulnerability-dos-attacks/	GBHacker	news;CVE/vulnerability;Cyber Security News;Network Security;Cisco IOS Vulnerability;CVE-2024-20276;DOS;	1	2024-04-08	Cisco IOS 脆弱性允许监督事务司通过恶意交易进行袭击
18855	Threat Actors Deliver Malware via YouTube Video Game Cracks	https://gbhackers.com/hackers-deliver-malware-via-youtube-video-game-cracks/	GBHacker	news;Uncategorized;Cyber Security News;Malware;	1	2024-04-08	通过YouTube视频游戏快车交付恶意
18858	Veterinary Giant IT System Attacked by Hackers	https://gbhackers.com/veterinary-giant-attacked/	GBHacker	news;Cyber Attack;cyber security;Cyber Security News;	1	2024-04-08	被黑客攻击的兽医巨人信息技术系统
17143	GPT-5将在6月发布刷屏，为什么关键在于「红队测试」	https://www.freebuf.com/articles/397090.html	freebuf	news;文章;观点;	1	2024-04-07	GPT-5将在6月发布刷屏，为什么关键在于「红队测试」
18864	FreeBuf早报 | 黑客可使用AI幻觉传播恶意软件；入侵iPhone的破解工具采购价飙升	https://www.freebuf.com/articles/397166.html	freebuf	news;	3	2024-04-08	FreeBuf早报 | 黑客可使用AI幻觉传播恶意软件；入侵iPhone的破解工具采购价飙升
18885	SymphonyAI unveils SensaAI for Sanctions to detect hidden risk in unstructured data	https://www.helpnetsecurity.com/2024/04/08/symphonyai-sensaai-for-sanctions/	helpnetsecurity	news;Industry news;SymphonyAI;	1	2024-04-08	交响乐国际为SensaAI制裁机构揭幕,以发现未结构化数据中的隐性风险
17295	注销手机号等于出卖自己？三大运营商回应	https://www.freebuf.com/news/397101.html	freebuf	news;资讯;	1	2024-04-07	注销手机号等于出卖自己？三大运营商回应
17313	安全威胁情报的漏洞挖掘	https://xz.aliyun.com/t/14256	阿里先知实验室	news;	3	2024-04-07	安全威胁情报的漏洞挖掘
34	New Banking Trojan CHAVECLOAK Targets Brazilian Users via Phishing Tactics	https://thehackernews.com/2024/03/new-banking-trojan-chavecloak-targets.html	feedburner	news;	1	2024-03-11	新的银行业Trojan CHAVECCLOAK通过钓鱼策略针对巴西用户
18852	Chinese Hackers Using AI Tools To Influence Upcoming Elections	https://gbhackers.com/chinese-hackers-ai-election-influence/	GBHacker	news;Artificial Intelligence;Cyber Attack;cyber security;computer security;Cyber Security News;Malware;	4	2024-04-08	中国黑客利用AI工具影响即将举行的选举
5	New Silver SAML Attack Evades Golden SAML Defenses in Identity Systems	https://thehackernews.com/2024/02/new-silver-saml-attack-evades-golden.html	feedburner	news;	1	2024-02-29	身份系统中的金色SAML防御系统
17308	Arbitrary Alloc学习	https://xz.aliyun.com/t/14247	阿里先知实验室	news;	1	2024-04-05	Arbitrary Alloc学习
17158	Week in review: 73M customers affected by AT&T data leak, errors led to US govt inboxes compromise	https://www.helpnetsecurity.com/2024/04/07/week-in-review-73m-customers-affected-by-att-data-leak-errors-led-to-us-govt-inboxes-compromise/	helpnetsecurity	news;News;Week in review;	1	2024-04-07	每周审查:73M客户受AT&T数据泄漏影响,错误导致美国政府的箱箱妥协
18893	upresult_0.1-2024 Multiple-SQLi	https://www.nu11secur1ty.com/2024/04/upresult01-2024-multiple-sqli.html	nu11security	vuln;	1	2024-04-08	多个 SQLi 多SQLi
18886	Veriato introduces AI-driven predictive behavior analytics platform	https://www.helpnetsecurity.com/2024/04/08/veriato-irm/	helpnetsecurity	news;Industry news;Veriato;	1	2024-04-08	Veriato介绍AI驱动的预测行为分析平台
8688	EPA and White House Raise Alarm on Water Cybersecurity	https://securityboulevard.com/2024/03/water-cybersecurity-richixbw/	securityboulevard	news;Application Security;AppSec;Cyberlaw;Cybersecurity;Data Security;Deep Fake and Other Social Engineering Tactics;DevOps;DevSecOps;Digital Transformation;Editorial Calendar;Endpoint;Featured;Governance, Risk & Compliance;Humor;Identity & Access;Identity and Access Management;Incident Response;Industry Spotlight;Insider Threats;IOT;IoT & ICS Security;Most Read This Week;Network Security;News;Popular Post;Regulatory Compliance;Securing Open Source;Securing the Edge;Security at the Edge;Security Awareness;Security Boulevard (Original);Security Challenges and Opportunities of Remote Work;Security Operations;Social - Facebook;Social - LinkedIn;Social - X;Social Engineering;Spotlight;Threats & Breaches;Vulnerabilities;Zero-Trust;Critical Infrastructure;critical infrastructure assets;critical infrastructure attack;Critical Infrastructure Cyber security;Critical Infrastructure Cybersecurity;Drinking Water;Environmental Protection Agency;EPA;ICS;operational technologies;OT;public water systems;SB Blogwatch;wastewater;water;water distribution systems;Water industry;water infrastructure;White House;	1	2024-03-20	EPA和白宫对水网络安全警示
22384	Universities in New Mexico, Oklahoma respond to ransomware attacks	https://therecord.media/ransomware-new-mexico-highlands-east-central-oklahoma-universities	therecord	ransom;Cybercrime;News;	2	2024-04-10	俄克拉荷马州新墨西哥州新墨西哥州大学 对赎金软件袭击的反应
20314	IEC 60870-5-104协议解析&模糊测试的一些策略	https://xz.aliyun.com/t/14267	阿里先知实验室	news;	1	2024-04-08	IEC 60870-5-104协议解析&模糊测试的一些策略
22364	Malwarebytes Digital Footprint Portal offers insights into exposed passwords and personal data	https://www.helpnetsecurity.com/2024/04/10/malwarebytes-digital-footprint-portal/	helpnetsecurity	news;Industry news;Malwarebytes;	1	2024-04-10	Malwarebytes 数字脚印门户网站提供对暴露密码和个人数据的深入了解
22365	NICE Actimize enhances Integrated Fraud Management platform to help financial services prevent scams	https://www.helpnetsecurity.com/2024/04/10/nice-actimize-ifm-11/	helpnetsecurity	news;Industry news;NICE Actimize;	1	2024-04-10	NICE 推动加强综合欺诈管理平台,帮助金融服务防止欺诈
22366	Vultr Sovereign Cloud and Private Cloud delivers data control to nations and enterprises	https://www.helpnetsecurity.com/2024/04/10/vultr-sovereign-cloud-and-private-cloud/	helpnetsecurity	news;Industry news;Vultr;	1	2024-04-10	Vultr主权云和私人云向国家和企业提供数据控制
22393	'eXotic Visit' Spyware Campaign Targets Android Users in India and Pakistan	https://thehackernews.com/2024/04/exotic-visit-spyware-campaign-targets.html	feedburner	news;	2	2024-04-10	印度和巴基斯坦的Spyware运动目标用户和机器人用户
22397	Hands-on Review: Cynomi AI-powered vCISO Platform	https://thehackernews.com/2024/04/hands-on-review-cynomi-ai-powered-vciso.html	feedburner	news;	1	2024-04-10	实践审查:Cynomi AI-动力 VCISO平台
22399	Raspberry Robin Returns: New Malware Campaign Spreading Through WSF Files	https://thehackernews.com/2024/04/raspberry-robin-returns-new-malware.html	feedburner	news;	1	2024-04-10	Raspberry Robin 返回:通过 WSF 文件传播的新恶意运动
20308	遍历Windows操作系统的NDIS网络过滤驱动	https://xz.aliyun.com/t/14255	阿里先知实验室	news;	1	2024-04-07	遍历Windows操作系统的NDIS网络过滤驱动
20300	New Latrodectus loader steps in for Qbot	https://www.helpnetsecurity.com/2024/04/09/latrodectus-initial-access/	helpnetsecurity	news;Don't miss;Hot stuff;News;initial access broker;malware;Proofpoint;Team Cymru;	1	2024-04-09	Qbot 的新建 Latrodectus 装入步骤
19928	明早9点，羊城相聚 | FreeBuf 企业安全俱乐部·广州站	https://www.freebuf.com/fevents/397258.html	freebuf	news;活动;	1	2024-04-09	明早9点，羊城相聚 | FreeBuf 企业安全俱乐部·广州站
23037	Automata An Expert Researcher Never Sleeps	https://securityboulevard.com/2024/04/automata-an-expert-researcher-never-sleeps/	securityboulevard	news;Security Bloggers Network;Events & Webinars;Live Webinars;	1	2024-04-10	Automata 专家研究员 永远睡不着
22378	How to Stop Your Data From Being Used to Train AI	https://www.wired.com/story/how-to-stop-your-data-from-being-used-to-train-ai/	wired	news;Security;Security / Privacy;Business / Artificial Intelligence;	1	2024-04-10	如何停止您用于培训 AI 的数据 。
19659	Designing Micro-Segmentation for Enhanced Security with Jump Hosts	https://infosecwriteups.com/designing-micro-segmentation-for-enhanced-security-with-jump-hosts-1ee6b31f6d03?source=rss----7b722bfd1b8d---4	infosecwriteups	tech;cybersecurity;microsegmentation;bastion;bastion-host;cyber;	1	2024-04-09	设计带有跳主机的加强安全微型部分
20304	src-歪门邪道分享+支付漏洞挖掘	https://xz.aliyun.com/t/14251	阿里先知实验室	news;	3	2024-04-06	src-歪门邪道分享+支付漏洞挖掘
20339	From Marco Polo to Modern Mayhem: Why Identity Management Matters	https://securityboulevard.com/2024/04/from-marco-polo-to-modern-mayhem-why-identity-management-matters/	securityboulevard	news;Security Bloggers Network;	1	2024-04-09	从马尔科·波洛到现代破坏:为什么身份管理问题
20313	MCMS全面审计	https://xz.aliyun.com/t/14266	阿里先知实验室	news;	1	2024-04-08	MCMS全面审计
20307	玄机应急响应wp	https://xz.aliyun.com/t/14254	阿里先知实验室	news;	1	2024-04-06	玄机应急响应wp
22363	IT pros targeted with malicious Google ads for PuTTY, FileZilla	https://www.helpnetsecurity.com/2024/04/10/malvertising-putty-filezilla/	helpnetsecurity	news;Don't miss;Hot stuff;News;Google Search;malvertising;Malwarebytes;	1	2024-04-10	以恶意谷歌广告为攻击目标,
20310	车联网安全入门一：了解CAN总线及环境模拟	https://xz.aliyun.com/t/14262	阿里先知实验室	news;	1	2024-04-07	车联网安全入门一：了解CAN总线及环境模拟
22401	Researchers Uncover First Native Spectre v2 Exploit Against Linux Kernel	https://thehackernews.com/2024/04/researchers-uncover-first-native.html	feedburner	news;	1	2024-04-10	探索Linux Kernel
20312	Tomcat CVE-2023-41080 分析与复现	https://xz.aliyun.com/t/14264	阿里先知实验室	news;	3	2024-04-08	Tomcat CVE-2023-41080 分析与复现
20297	Darktrace ActiveAI Security Platform helps organizations shift focus to proactive cyber resilience	https://www.helpnetsecurity.com/2024/04/09/darktrace-activeai-security-platform/	helpnetsecurity	news;Industry news;Darktrace;	1	2024-04-09	活跃国际投资倡议安全平台帮助各组织将重点转向积极主动的网络复原力
22379	Trump Loyalists Kill Vote on US Wiretap Program	https://www.wired.com/story/section-702-vote-fails-trump-fisa/	wired	news;Security;Security / National Security;Security / Privacy;Politics / Policy;Politics / Politics News;	1	2024-04-10	朗普·洛洛爱主义者在美国无线电节目上 击杀选票
22380	CISA to expand automated malware analysis system beyond government agencies	https://therecord.media/cisa-malware-next-gen-automated-system-public	therecord	ransom;Malware;Government;Technology;News Briefs;News;Industry;	1	2024-04-10	CISA 将自动恶意软件分析系统扩大到政府机构以外的范围
22382	Section 702 surveillance powers legislation hits another roadblock in House	https://therecord.media/house-rule-fails-fisa-section-702-renewal	therecord	ransom;Privacy;Government;News Briefs;News;	1	2024-04-10	第702条监视权力立法第702条在众议院又撞上另一路障
26142	从业者称小米教会了车圈如何开发布会 	https://s.weibo.com/weibo?q=%23从业者称小米教会了车圈如何开发布会 %23	sina.weibo	hotsearch;weibo	1	2023-12-29	从业者称小米教会了车圈如何开发布会
26143	任泽平预测小米汽车 	https://s.weibo.com/weibo?q=%23任泽平预测小米汽车 %23	sina.weibo	hotsearch;weibo	1	2023-12-23	任泽平预测小米汽车
22248	D3 Security Releases “In the Wild 2024” Report with Analysis and Incident Response Playbooks for the 10 Most Prevalent Cyber Attack Techniques	https://securityboulevard.com/2024/04/d3-security-releases-in-the-wild-2024-report-with-analysis-and-incident-response-playbooks-for-the-10-most-prevalent-cyber-attack-techniques/	securityboulevard	news;DevOps;Security Bloggers Network;D3 Smart SOAR;In The Wild;MITRE ATT&CK;MITRE D3FEND;Reports;SOAR;	1	2024-04-10	D3 “Ward 2024”10种最最最先发制人网络攻击技术的“Ward 2024”报告和分析和事件应对手册
2537	HHS to Investigate Change’s Security in Wake of Crippling Cyberattack	https://securityboulevard.com/2024/03/hhs-to-investigate-changes-security-in-wake-of-crippling-cyberattack/	securityboulevard	news;Cloud Security;Cyberlaw;Cybersecurity;Data Security;Featured;Governance, Risk & Compliance;Incident Response;Industry Spotlight;Malware;Network Security;News;Security Awareness;Security Boulevard (Original);Social - Facebook;Social - LinkedIn;Social - X;Spotlight;Threats & Breaches;BlackCat ransomware;Health Care Security;HHS;UnitedHealth;	1	2024-03-13	HHS 调查网络攻击震醒后变化安全情况
14560	The Biggest Misconceptions of Zero-Trust	https://securityboulevard.com/2024/04/the-biggest-misconceptions-of-zero-trust/	securityboulevard	news;Security Bloggers Network;advice;Best Practices;Cybersecurity;lateral movement;microsegmentation;next gen security;security;Security Research;zero trust;	1	2024-04-02	零信任最大的误解
20065	Cloudflare partners with Booz Allen Hamilton to guide organizations under attack	https://www.helpnetsecurity.com/2024/04/09/cloudflare-booz-allen-hamilton-collaboration/	helpnetsecurity	news;Industry news;Booz Allen Hamilton;Cloudflare;	1	2024-04-09	与布兹·艾伦·汉密尔顿合作,指导受攻击组织
16067	Magecart Attackers Pioneer Persistent E-Commerce Backdoor	https://www.darkreading.com/cloud-security/magecart-attackers-pioneer-persistent-ecommerce-backdoor	darkreading	news;	1	2024-04-05	Mageccart攻击者先锋 持久性电子商务后门
20436	恶意通讯流量案例分析，恶意下载链路最终导致Async RAT木马受控	https://xz.aliyun.com/t/14269	阿里先知实验室	news;	1	2024-04-09	恶意通讯流量案例分析，恶意下载链路最终导致Async RAT木马受控
23046	Why a Cybersecurity Platform Beats Standalone Applications	https://securityboulevard.com/2024/04/why-a-cybersecurity-platform-beats-standalone-applications/	securityboulevard	news;Governance, Risk & Compliance;Security Bloggers Network;Blog;platform;security operations;	1	2024-04-10	为什么网络安全平台比独立应用更孤立
26144	何小鹏预祝小米SU7大卖 	https://s.weibo.com/weibo?q=%23何小鹏预祝小米SU7大卖 %23	sina.weibo	hotsearch;weibo	1	2024-03-28	何小鹏预祝小米SU7大卖
26146	余承东称鸿蒙生态属于每一位开发者 	https://s.weibo.com/weibo?q=%23余承东称鸿蒙生态属于每一位开发者 %23	sina.weibo	hotsearch;weibo	1	2024-01-18	余承东称鸿蒙生态属于每一位开发者
20035	Notepad++ Wants Your Help to Take Down the Parasite Website	https://gbhackers.com/notepad-down-parasite-website/	GBHacker	news;cyber security;Cyber Security News;	1	2024-04-09	Notpad++ 想要您帮助拆除 上线网站
20087	Attackers Using Obfuscation Tools to Deliver Multi-Stage Malware via Invoice Phishing	https://thehackernews.com/2024/04/attackers-using-obfuscation-tools-to.html	feedburner	news;	1	2024-04-09	使用模糊工具通过窃听电话传送多系统恶意攻击者
20034	Top Israeli Spy Chief Identity Exposed In A Privacy Mistake	https://gbhackers.com/israeli-spy-chief-privacy-breach/	GBHacker	news;Artificial Intelligence;cyber security;Data Breach;Intelligence Failure;Privacy Breach;	1	2024-04-09	以色列最顶级间谍在一次隐私错误中揭露的以色列最高间谍主要身份特征
26147	元PLUS荣耀版11.98万元起 	https://s.weibo.com/weibo?q=%23元PLUS荣耀版11.98万元起 %23	sina.weibo	hotsearch;weibo	1	2024-03-04	元PLUS荣耀版11.98万元起
26148	元梦之星崩了 	https://s.weibo.com/weibo?q=%23元梦之星崩了 %23	sina.weibo	hotsearch;weibo	1	2023-12-15	元梦之星崩了
26149	元气森林创始人称要向华为学习 	https://s.weibo.com/weibo?q=%23元气森林创始人称要向华为学习 %23	sina.weibo	hotsearch;weibo	1	2024-02-05	元气森林创始人称要向华为学习
26150	公考雷达崩了 	https://s.weibo.com/weibo?q=%23公考雷达崩了 %23	sina.weibo	hotsearch;weibo	1	2024-01-16	公考雷达崩了
26151	内部人士回应华为三折屏手机面世时间 	https://s.weibo.com/weibo?q=%23内部人士回应华为三折屏手机面世时间 %23	sina.weibo	hotsearch;weibo	1	2024-04-02	内部人士回应华为三折屏手机面世时间
26152	刘德华为什么不演反派这个梗没了 	https://s.weibo.com/weibo?q=%23刘德华为什么不演反派这个梗没了 %23	sina.weibo	hotsearch;weibo	1	2023-12-14	刘德华为什么不演反派这个梗没了
26375	小米集团涨超10% 	https://s.weibo.com/weibo?q=%23小米集团涨超10% %23	sina.weibo	hotsearch;weibo	1	2024-03-12	小米集团涨超10%
10705	PyPI Goes Quiet After Huge Malware Attack: 500+ Typosquat Fakes Found	https://securityboulevard.com/2024/03/pypi-suspended-500-fakes-richixbw/	securityboulevard	news;Analytics & Intelligence;API Security;AppSec;Cloud Security;Cybersecurity;Data Privacy;Data Security;Deep Fake and Other Social Engineering Tactics;DevOps;DevSecOps;Digital Transformation;Editorial Calendar;Featured;Governance, Risk & Compliance;Humor;Identity & Access;Identity and Access Management;Incident Response;Industry Spotlight;Insider Threats;Malware;Most Read This Week;News;Popular Post;Securing Open Source;Security Awareness;Security Boulevard (Original);Security Operations;Social - Facebook;Social - LinkedIn;Social - X;Social Engineering;Software Supply Chain Security;Spotlight;Threat Intelligence;Threats & Breaches;Vulnerabilities;Zero-Trust;code reuse;open source software supply chain security;PyPI;PyPI malicious packages;pypi vuln;pypi vulnerability;python;Python Malware;Python Packages;Python vulnerability;SB Blogwatch;secure software supply chain;software supply chain;software supply chain attack;software supply chain attacks;software supply chain hygiene;Software supply chain management;software supply chain risk;Software Supply Chain risks;software supply chain security;Software Supply Chain Security Risks;Software Supply Chain Security Weaknesses;typosquat;Typosquatting;typosquatting attacks;	1	2024-03-29	PyPPI 在巨大的恶意攻击后静静: 500+ Typosqat Fakes 找到
9776	China Steals Defense Secrets ‘on Industrial Scale’	https://securityboulevard.com/2024/03/china-steals-secrets-f5-connectwise-richixbw/	securityboulevard	news;Analytics & Intelligence;AppSec;Cloud Security;Cyberlaw;Cybersecurity;Data Privacy;Data Security;Deep Fake and Other Social Engineering Tactics;DevOps;DevSecOps;Editorial Calendar;Endpoint;Featured;Governance, Risk & Compliance;Humor;Identity & Access;Identity and Access Management;Incident Response;Industry Spotlight;Insider Threats;Malware;Mobile Security;Most Read This Week;Network Security;News;Popular Post;Regulatory Compliance;Securing Open Source;Securing the Cloud;Securing the Edge;Security at the Edge;Security Awareness;Security Boulevard (Original);Security Challenges and Opportunities of Remote Work;Security Operations;Social - Facebook;Social - LinkedIn;Social - X;Social Engineering;Software Supply Chain Security;Spotlight;Threat Intelligence;Threats & Breaches;Vulnerabilities;Zero-Trust;china;china espionage;China-linked Hackers;Chinese;Chinese Communists;chinese government;chinese hacker;Chinese hackers;Chinese Intelligence;Chinese state-sponsored hacking group;Chinese Threat Actors;ConnectWise;ConnectWise Vulnerabilities;CVE-2022-0185;CVE-2022-3052;CVE-2023-22518;CVE-2024-1709;Data Stolen By China;Dawn Calvary;f5;F5 BIG-IP;F5 BIG-IP vulnerability;Genesis Day;gov.uk;Mandiant;MSS;MSS Hackers;Peoples Republic of China;PRC;PRC Espionage;SB Blogwatch;ScreenConnect;Teng Snake;uk;UNC302;UNC5174;Uteus;Xiaoqiying;	4	2024-03-25	中国“在工业规模上”窃取国防机密
20415	Akamai Shield NS53 protects on-prem and hybrid DNS infrastructure	https://www.helpnetsecurity.com/2024/04/09/akamai-shield-ns53/	helpnetsecurity	news;Industry news;Akamai;	1	2024-04-09	Akamai盾NS53保护在孕期和混合DNS基础设施
20391	Targus Hacked: Attackers Gain Access to File Servers	https://gbhackers.com/targus-hacked/	GBHacker	news;Cyber Attack;Cyber Security News;cyber security;	1	2024-04-09	Targus Hacked: 攻击者获得对文件服务器的访问
20399	代码手术刀—自定义你的代码重构工具	https://www.freebuf.com/articles/others-articles/397042.html	freebuf	news;其他;	1	2024-04-07	代码手术刀—自定义你的代码重构工具
20383	Cyber Attack on Consulting Firm Exposes DOJ Data of 341,000 People	https://gbhackers.com/cyber-attack-consulting-firm/	GBHacker	news;Cyber Attack;cyber security;Cyber Security News;	1	2024-04-09	网络攻击咨询公司揭露司法部341 000人的数据
20631	CyberheistNews Vol 14 #15 [Heads Up] Your Apple Users Are Now Targeted With New MFA Attacks	https://blog.knowbe4.com/cyberheistnews-vol-14-15-heads-up-your-apple-users-are-now-targeted-with-new-mfa-attacks	knowbe4	news;Cybercrime;KnowBe4;	1	2024-04-09	网络新闻第14卷#15#15[上头]你的苹果用户现在成为新外务省袭击的目标
20635	Ahoi Attacks – New Attack Breaking VMs With Malicious Interrupts	https://gbhackers.com/ahoi-attacks-confidential-vms/	GBHacker	news;Cloud;CVE/vulnerability;Cyber Attack;Confidential Computing;Cybersecurity Vulnerabilities;	1	2024-04-09	Ahooi袭击 — — 与恶意干扰者进行的新攻打突破性伏特加
20670	Gurucul Data Optimizer provides control over real-time data transformation and routing	https://www.helpnetsecurity.com/2024/04/09/gurucul-data-optimizer/	helpnetsecurity	news;Industry news;Gurucul;	1	2024-04-09	Gurururcul 数据优化器对实时数据转换和路由进行控制
20676	TufinMate accelerates network access troubleshooting	https://www.helpnetsecurity.com/2024/04/09/tufinmate-accelerates-network-access-troubleshooting/	helpnetsecurity	news;Industry news;Tufin;	1	2024-04-09	TufinMate 加速网络访问排除故障
20709	Researchers Discover LG Smart TV Vulnerabilities Allowing Root Access	https://thehackernews.com/2024/04/researchers-discover-lg-smart-tv.html	feedburner	news;	1	2024-04-09	发现LG智能电视弱点,允许根接入
20721	The role of certificate lifecycle automation in enterprise environments	https://securityboulevard.com/2024/04/the-role-of-certificate-lifecycle-automation-in-enterprise-environments/	securityboulevard	news;Security Bloggers Network;	1	2024-04-09	证书使用周期自动化在企业环境中的作用
20612	Frameworks, Guidelines &amp; Bounties Alone Won't Defeat Ransomware	https://www.darkreading.com/vulnerabilities-threats/frameworks-guidelines-bounties-alone-wont-defeat-ransomware	darkreading	news;	2	2024-04-09	框架框架、 准则 & amp; 单元元件不会丢掉的 Ransomware
20733	RUBYCARP hackers linked to 10-year-old cryptomining botnet	https://www.bleepingcomputer.com/news/security/rubycarp-hackers-linked-to-10-year-old-cryptomining-botnet/	bleepingcomputer	news;Security;	1	2024-04-09	RUBYCARP黑客与10岁的加密机器人网有关联
20724	Microsoft fixes two Windows zero-days exploited in malware attacks	https://www.bleepingcomputer.com/news/microsoft/microsoft-fixes-two-windows-zero-days-exploited-in-malware-attacks/	bleepingcomputer	news;Microsoft;	1	2024-04-09	微软在恶意软件攻击中使用两个Windows零天时修补了两个Windows零天
20723	Microsoft April 2024 Patch Tuesday fixes 150 security flaws, 67 RCEs	https://www.bleepingcomputer.com/news/microsoft/microsoft-april-2024-patch-tuesday-fixes-150-security-flaws-67-rces/	bleepingcomputer	news;Microsoft;Security;	1	2024-04-09	2024年4月Microsoft 2024年4月 Patch 星期二修补150个安全缺陷,67个RCE
20747	New Jamf Tools Give Enterprise IT Security and Compliance Controls	https://www.darkreading.com/endpoint-security/new-jamf-tools-give-enterprise-it-security-and-compliance-controls	darkreading	news;	1	2024-04-09	新的Jamf工具为企业信息技术安全和合规控制提供企业信息技术安全和合规控制
20732	Over 90,000 LG Smart TVs may be exposed to remote attacks	https://www.bleepingcomputer.com/news/security/over-90-000-lg-smart-tvs-may-be-exposed-to-remote-attacks/	bleepingcomputer	news;Security;	1	2024-04-09	90 000多部LG智能电视机可能受到远程袭击
20746	ESET Launches a New Solution for Small Office/Home Office Businesses	https://www.darkreading.com/endpoint-security/eset-launches-a-new-solution-for-small-office-home-office-businesses	darkreading	news;	1	2024-04-09	ESET 为小型办公室/家庭办公室企业推出新的解决方案
20738	Proper DDoS Protection Requires Both Detective and Preventive Controls	https://www.darkreading.com/cloud-security/proper-ddos-protection-requires-both-detective-and-preventive-controls	darkreading	news;	1	2024-04-09	适当的DDoS保护要求侦探和预防控制
20725	Windows 10 KB5036892 update released with 23 new fixes, changes	https://www.bleepingcomputer.com/news/microsoft/windows-10-kb5036892-update-released-with-23-new-fixes-changes/	bleepingcomputer	news;Microsoft;	1	2024-04-09	Windows 10 KB5036892 更新已发布, 有23个新修正, 更改
20737	92K D-Link NAS Devices Open to Critical Command-Injection Bug	https://www.darkreading.com/cloud-security/92k-dlink-nas-critical-command-injection-bug	darkreading	news;	1	2024-04-09	92K D-Link NAS 设备向关键命令输入错误打开
20743	Ambitious Training Initiative Taps Talents of Blind and Visually Impaired	https://www.darkreading.com/cybersecurity-careers/ambitious-training-initiatve-taps-talents-of-blind-visually-impaired	darkreading	news;	1	2024-04-09	盲人和视视障人高超培训倡议
20748	EV Charging Stations Still Riddled With Cybersecurity Vulnerabilities	https://www.darkreading.com/ics-ot-security/ev-charging-stations-still-riddled-with-cybersecurity-vulnerabilities	darkreading	news;	1	2024-04-09	EV 充电站仍然与网络安全薄弱环节交织在一起
20726	Windows 11 KB5036893 update released with 29 changes, Moment 5 features	https://www.bleepingcomputer.com/news/microsoft/windows-11-kb5036893-update-released-with-29-changes-moment-5-features/	bleepingcomputer	news;Microsoft;Software;	1	2024-04-09	视窗 11 KB5036893 更新发布,29项更改,5项特点
20730	Implementing container security best practices using Wazuh	https://www.bleepingcomputer.com/news/security/implementing-container-security-best-practices-using-wazuh/	bleepingcomputer	news;Security;	1	2024-04-09	利用Wazuh实施集装箱安全最佳做法
20731	New SharePoint flaws help hackers evade detection when stealing files	https://www.bleepingcomputer.com/news/security/new-sharepoint-flaws-help-hackers-evade-detection-when-stealing-files/	bleepingcomputer	news;Security;Microsoft;	1	2024-04-09	新的 SharePoint 缺陷帮助黑客窃取文件时逃避发现
20729	GHC-SCW: Ransomware gang stole health data of 533,000 people	https://www.bleepingcomputer.com/news/security/ghc-scw-ransomware-gang-stole-health-data-of-533-000-people/	bleepingcomputer	news;Security;Healthcare;	2	2024-04-09	GHC-SCW:Ransomware帮盗窃533,000人的保健数据
20740	Veriato Launches Next Generation Insider Risk Management Solution	https://www.darkreading.com/cyber-risk/veriato-launches-next-generation-insider-risk-management-solution	darkreading	news;	1	2024-04-09	Veriato 启动下一代内部风险管理解决方案
20745	Why Liquid Cooling Systems Threaten Data Center Security &amp; Our Water Supply	https://www.darkreading.com/cybersecurity-operations/why-liquid-cooling-systems-threaten-data-center-security-water-supply	darkreading	news;	1	2024-04-09	为何液体冷却系统威胁威胁数据中心 安全 & amp; 我们的供水
20728	Critical Rust flaw enables Windows command injection attacks	https://www.bleepingcomputer.com/news/security/critical-rust-flaw-enables-windows-command-injection-attacks/	bleepingcomputer	news;Security;	1	2024-04-09	关键干枯缺陷使Windows命令注射攻击
14709	Chrome’s Incognito Mode Isn’t as Private as You Think — but Google’s Not Sorry	https://securityboulevard.com/2024/04/chrome-incognito-brown-v-google-richixbw/	securityboulevard	news;API Security;Application Security;AppSec;Cloud Security;Cyberlaw;Cybersecurity;Data Privacy;Deep Fake and Other Social Engineering Tactics;DevOps;DevSecOps;Editorial Calendar;Endpoint;Featured;Governance, Risk & Compliance;Humor;Identity & Access;Identity and Access Management;Industry Spotlight;Mobile Security;Most Read This Week;Network Security;News;Popular Post;Regulatory Compliance;Securing Open Source;Securing the Edge;Security at the Edge;Security Awareness;Security Boulevard (Original);Security Operations;Social - Facebook;Social - LinkedIn;Social - X;Social Engineering;Spotlight;Zero-Trust;adtech;Advertising;Advertising and AdTech;adverts;breach of privacy;browser;browser abuse;Chrome;cookie;Cookie Consent;cookieconsent;cookies;customer privacy;FLEDGE;FLoC;GOOG;google;Google Ad;Google AdSense;Google advertising;Google Chrome;Google Chrome Security;Incognito;Incognito Mode;Link History;Privacy;Privacy Sandbox;SB Blogwatch;Topics;tracking cookies;web cookie;	1	2024-04-02	但谷歌并不感到抱歉。
10166	Revealed: Facebook’s “Incredibly Aggressive” Alleged Theft of Snapchat App Data	https://securityboulevard.com/2024/03/ghostbusters-facebook-theft-snapchat-richixbw/	securityboulevard	news;Analytics & Intelligence;API Security;AppSec;Cloud Security;Cyberlaw;Cybersecurity;Data Privacy;Deep Fake and Other Social Engineering Tactics;DevOps;DevSecOps;Editorial Calendar;Endpoint;Featured;Governance, Risk & Compliance;Humor;Incident Response;Industry Spotlight;Malware;Mobile Security;Most Read This Week;Network Security;News;Popular Post;Regulatory Compliance;Securing the Edge;Security at the Edge;Security Awareness;Security Boulevard (Original);Security Challenges and Opportunities of Remote Work;Security Operations;Social - Facebook;Social - LinkedIn;Social - X;Social Engineering;Software Supply Chain Security;Spotlight;Threat Intelligence;Threats & Breaches;Vulnerabilities;Zero-Trust;Brian J. Dunne;class action;class action lawsuit;DeleteFacebook;facebook;facebook fine;free vpn app;Ghostbusters;IAPP;Man In The Middle;man in the middle attack;man in the middle attacks;Mark Zuckerberg;Meta;mitm;MitM Attack;mitm attacks;mitm tool;mitm tools;Onavo;Onavo VPN;SB Blogwatch;Snapchat;SSL Bump;VPN;	1	2024-03-27	公开:脸书的“令人难以相信的侵略性”据称盗窃Snapchat App数据
21132	Enabling Large File Transfers with PreVeil: A Comprehensive Solution	https://securityboulevard.com/2024/04/enabling-large-file-transfers-with-preveil-a-comprehensive-solution/	securityboulevard	news;Security Bloggers Network;	1	2024-04-09	启用 PreVeil 的大型文件传输: 全面解决方案
16169	FCC: Phone Network Bugs Must Be Fixed — But are SS7/Diameter Beyond Repair?	https://securityboulevard.com/2024/04/fcc-ss7-diameter-richixbw-2/	securityboulevard	news;Analytics & Intelligence;API Security;AppSec;Cloud Security;Cyberlaw;Cybersecurity;Data Privacy;Data Security;Deep Fake and Other Social Engineering Tactics;DevOps;DevSecOps;Digital Transformation;Editorial Calendar;Endpoint;Featured;Governance, Risk & Compliance;Humor;Identity & Access;Identity and Access Management;Incident Response;Industry Spotlight;Insider Threats;IOT;IoT & ICS Security;Mobile Security;Most Read This Week;Network Security;News;Popular Post;Regulatory Compliance;Securing Open Source;Securing the Cloud;Securing the Edge;Security at the Edge;Security Awareness;Security Boulevard (Original);Security Challenges and Opportunities of Remote Work;Security Operations;Social - Facebook;Social - LinkedIn;Social - X;Social Engineering;Software Supply Chain Security;Spotlight;Threat Intelligence;Threats & Breaches;Vulnerabilities;Zero-Trust;Big Telecom;carrier;Carriers;Diameter;digital telecom;fcc;FCC Failures;FCC Follies;FCC privacy rules;Federal Communications Commission;Federal Government;Location;location access risks;location data;Location data privacy;location history;location intelligence;location privacy;location sharing location tracking;location tracking;mobile carrier;mobile carrier vulnerability;Mobile carriers;Mobile Location Tracking;Mobile Tracking;Phone Carrier;RADIUS;roaming;Ron Wyden;SB Blogwatch;Sen. Ron Wyden;Smartphone Location Tracking;ss7;telco;Telecom;Telecom Cybersecurity;Telecom Industry;Telecom Industry Vulnerabilities;telecommunications;Telecommunications Security;telephone;telephones;U.S. Federal Communications Commission;wireless carrier;	1	2024-04-05	FCC:电话网络错误必须是固定的 — — 但SS7/Diater是否无法修复?
21135	Navigating Third-Party Cyber Risks in Healthcare: Insights from Recent Events	https://securityboulevard.com/2024/04/navigating-third-party-cyber-risks-in-healthcare-insights-from-recent-events/	securityboulevard	news;Security Bloggers Network;Axio Insights;healthcare;SEC Cyber Rules;	1	2024-04-09	管理保健中的第三方网络网络风险:近期事件展望
8249	TikTok ‘Ban’ — ByteDance CEO and EFF are BFFs	https://securityboulevard.com/2024/03/tiktok-ban-bytedance-eff-richixbw/	securityboulevard	news;AI and Machine Learning in Security;AI and ML in Security;Analytics & Intelligence;AppSec;Cloud Security;Cyberlaw;Cybersecurity;Data Privacy;Data Security;Deep Fake and Other Social Engineering Tactics;DevOps;DevSecOps;Editorial Calendar;Endpoint;Featured;Governance, Risk & Compliance;Humor;Identity & Access;Identity and Access Management;Incident Response;Industry Spotlight;Insider Threats;Malware;Mobile Security;Most Read This Week;Network Security;News;Popular Post;Regulatory Compliance;Securing the Cloud;Securing the Edge;Security at the Edge;Security Awareness;Security Boulevard (Original);Security Operations;Social - Facebook;Social - LinkedIn;Social - X;Social Engineering;Spotlight;Threat Intelligence;Threats & Breaches;Zero-Trust;Bytedance;china;chinese government;EFF;Electronic Frontier Foundation;Privacy;SB Blogwatch;Shou Zi Chew;social media;spyware;TikTok;TikTok Ban;	1	2024-03-18	TikTok TikTok `Ban ' ——字节Dance CEO和EFF是BFF
21644	XZ后门检测工具和脚本最新汇总	https://www.freebuf.com/sectool/397401.html	freebuf	news;工具;	1	2024-04-10	XZ后门检测工具和脚本最新汇总
21600	Roadmap to ISO 27001	https://infosecwriteups.com/roadmap-to-iso-27001-8a94188e9ec5?source=rss----7b722bfd1b8d---4	infosecwriteups	tech;iso-27001-certification;iso-27001-isms;iso-27001;iso-27001-standard;	1	2024-04-10	ISO 27001的路线图
21617	How to Use Cyber Threat Intelligence? 4 TI Categories to Learn SOC/DFIR Team	https://gbhackers.com/how-to-use-cyber-threat-intelligence/	GBHacker	news;Cyber Attack;cyber security;Cyber Security News;	1	2024-04-10	如何使用网络威胁情报?
8455	USENIX Security ’23 – Abderrahmen Amich, Birhanu Eshete, Vinod Yegneswaran, Nguyen Phong Hoang – DeResistor: Toward Detection-Resistant Probing for Evasion Of Internet Censorship	https://securityboulevard.com/2024/03/usenix-security-23-abderrahmen-amich-birhanu-eshete-vinod-yegneswaran-nguyen-phong-hoang-deresistor-toward-detection-resistant-probing-for-evasion-of-internet-censorship/	securityboulevard	news;Security Bloggers Network;Open Access Research;Security Research;USENIX;USENIX Security ’23;	1	2024-03-19	USENIX 安全 23 — — Abderrahmen Amich, Birhanu Eshete, Vinod Yegneswaran, Nguyen Phong Hoang — — 捍卫者:为逃避互联网审查而寻求侦察-较远探查
10473	Apple OTP FAIL: ‘MFA Bomb’ Warning — Locks Accounts, Wipes iPhones	https://securityboulevard.com/2024/03/mfa-bomb-apple-otp-richixbw/	securityboulevard	news;Analytics & Intelligence;API Security;AppSec;Cloud Security;Cyberlaw;Cybersecurity;Data Privacy;Data Security;Deep Fake and Other Social Engineering Tactics;DevOps;DevSecOps;Editorial Calendar;Endpoint;Featured;Governance, Risk & Compliance;Humor;Identity & Access;Identity and Access Management;Incident Response;Industry Spotlight;Mobile Security;Most Read This Week;Network Security;News;Popular Post;Securing the Cloud;Securing the Edge;Security at the Edge;Security Awareness;Security Boulevard (Original);Security Challenges and Opportunities of Remote Work;Security Operations;Social - Facebook;Social - LinkedIn;Social - X;Social Engineering;Spotlight;Threat Intelligence;Threats & Breaches;Vulnerabilities;Zero-Trust;2fa;2FA bypass;2FA Flaws;2FA phishing;2FA solution;2FA/MFA;Apple;apple bug;Apple Data Security;apple hack;apple hacker;Apple iCloud;Apple ID;Apple ID failure;Apple iOS;Apple iPad;Apple iPhone;bypass 2FA;MFA;MFA Bombing;mfa fatigue;MFA hacks;mfa protection;mfasecurity;Multi-Factor Authentication (MFA);OTP;OTP circumvention bot;OTP interception bot;phishing-resistant MFA;push otp;SB Blogwatch;TOTP;two-factor-authentication.2fa;	2	2024-03-28	Apple OTP FAIL: `MFA炸弹 ' 警告-锁账、擦拭iPhones iPhones
9977	Telegram Privacy Nightmare: Don’t Opt In to P2PL	https://securityboulevard.com/2024/03/telegram-privacy-nightmare-p2pl-richixbw/	securityboulevard	news;API Security;Application Security;AppSec;Cloud Security;Cyberlaw;Cybersecurity;Data Privacy;DevOps;DevSecOps;Editorial Calendar;Endpoint;Featured;Governance, Risk & Compliance;Humor;Identity & Access;Identity and Access Management;Industry Spotlight;Insider Threats;Mobile Security;Most Read This Week;Network Security;News;Popular Post;Regulatory Compliance;Securing the Cloud;Securing the Edge;Security at the Edge;Security Awareness;Security Boulevard (Original);Security Challenges and Opportunities of Remote Work;Social - Facebook;Social - LinkedIn;Social - X;Social Engineering;Spotlight;Threats & Breaches;Zero-Trust;2-step verification;2fa;2FA apps;2FA bypass;2FA Flaws;2FA/MFA;Access control and Identity Management;Cloud MFA;digital identity verification;iam;ID verification;MFA;mfa login;mfasecurity;Multi-Factor Authentication (MFA);P2P;SB Blogwatch;SMS;SMS messages;SMS Toll Fraud;Telegram;Telegram app;two-factor-authentication.2fa;Verify 2FA;	1	2024-03-26	电报隐私噩梦:不要选择 P2PL
22411	Safeguard Your Data and Financial Future This Tax Season	https://securityboulevard.com/2024/04/safeguard-your-data-and-financial-future-this-tax-season/	securityboulevard	news;Security Bloggers Network;Blog;Data Security Posture Management;strategy;	1	2024-04-10	保护你的数据和金融未来
22408	Phishing Detection and Response: What You Need to Know	https://securityboulevard.com/2024/04/phishing-detection-and-response-what-you-need-to-know/	securityboulevard	news;Security Bloggers Network;Threat Intelligence Insights;	1	2024-04-10	幻影探测和反应:你需要知道什么
22410	Raspberry Robin Malware Now Using Windows Script Files to Spread	https://securityboulevard.com/2024/04/raspberry-robin-malware-now-using-windows-script-files-to-spread/	securityboulevard	news;Cloud Security;Cybersecurity;Data Security;Endpoint;Featured;Malware;Network Security;News;Security Boulevard (Original);Social - Facebook;Social - LinkedIn;Social - X;Spotlight;Threat Intelligence;Threats & Breaches;Evasion Techniques;Raspberry Robin Worm;Windows;	1	2024-04-10	使用 Windows 脚本文件扩展
22414	USENIX Security ’23 – Exorcising “Wraith”: Protecting LiDAR-based Object Detector in Automated Driving System from Appearing Attacks	https://securityboulevard.com/2024/04/usenix-security-23-exorcising-wraith-protecting-lidar-based-object-detector-in-automated-driving-system-from-appearing-attacks/	securityboulevard	news;Security Bloggers Network;Open Research;Security Conferences;USENIX;USENIX Security ’23;	1	2024-04-10	USENIX 安全 23 - 驱散“Wraith”:保护自动驾驶系统里以LIDAR为基础的物体探测器,使其不露面攻击
22407	OWASP Top 10 for LLM Applications: A Quick Guide	https://securityboulevard.com/2024/04/owasp-top-10-for-llm-applications-a-quick-guide/	securityboulevard	news;Security Bloggers Network;	1	2024-04-10	OWASP 用于LLM应用的10大LLM10:快速指南
22409	Randall Munroe’s XKCD ‘Cursive Letters’	https://securityboulevard.com/2024/04/randall-munroes-xkcd-cursive-letters/	securityboulevard	news;Humor;Security Bloggers Network;Randall Munroe;Sarcasm;satire;XKCD;	1	2024-04-10	Randall Munroe 的 XKCD 缩略信
22406	Managing Secrets Security at any Scale: introducing the GitGuardian Secrets Management Needs Quiz	https://securityboulevard.com/2024/04/managing-secrets-security-at-any-scale-introducing-the-gitguardian-secrets-management-needs-quiz/	securityboulevard	news;DevOps;Security Bloggers Network;DevSecOps;	1	2024-04-10	管理任何规模的机密安全:介绍GitGuardian秘密管理需求 Quiz
22412	The Irrefutable Case for Customer-Native (In-Your-Cloud) DSPM	https://securityboulevard.com/2024/04/the-irrefutable-case-for-customer-native-in-your-cloud-dspm/	securityboulevard	news;Security Bloggers Network;Blog;Data Security Posture Management;Future of Data Security;	1	2024-04-10	The Irrefutable Case for Customer-Native (In-Your-Cloud) DSPM
22413	USENIX Security ’23 – Discovering Adversarial Driving Maneuvers against Autonomous Vehicles	https://securityboulevard.com/2024/04/usenix-security-23-discovering-adversarial-driving-maneuvers-against-autonomous-vehicles/	securityboulevard	news;Security Bloggers Network;Security Conferences;USENIX Secuirty '23;	1	2024-04-10	USENIX 安全 23 - 发现反自动驾驶汽车的反逆驾驶机
95	Bipartisan Members of Congress Introduce Enhanced Cybersecurity for SNAP Act to Secure Food Benefits Against Hackers and Thieves	https://www.darkreading.com/cyber-risk/bipartisan-members-of-congress-introduce-enhanced-cybersecurity-for-snap-act-to-secure-food-benefits-against-hackers-and-thieves	darkreading	news;	1	2024-03-07	国会两党议员为《国家营养保护法》引入强化网络安全,以确保对黑客和盗贼的食品利益
22682	Stopping security breaches by managing AppSec posture	https://www.helpnetsecurity.com/2024/04/11/managing-application-security-posture-video/	helpnetsecurity	news;Don't miss;Hot stuff;Video;application security;compliance;cybersecurity;human error;OpsMx;policy;software development;video;	1	2024-04-11	通过管理AppSec 姿态来制止违反安全规定的行为
4747	USENIX Security ’23 – “I Wouldn’t Want My Unsafe Code To Run My Pacemaker”: An Interview Study On The Use, Comprehension, And Perceived Risks Of Unsafe Rust	https://securityboulevard.com/2024/03/usenix-security-23-i-wouldnt-want-my-unsafe-code-to-run-my-pacemaker-an-interview-study-on-the-use-comprehension-and-perceived-risks-of-unsafe-rust/	securityboulevard	news;Security Bloggers Network;Open Access Research;Security Conferences;Security Research;USENIX;USENIX Security ’23;	1	2024-03-15	USENIX 安全 23 — — " 我不想让我的不安全规则来管理我的制动器 " :关于使用、理解和所察觉到的不安全鲁斯特风险的访谈研究
13988	Alert: Connectwise F5 Software Flaws Used To Breach Networks	https://securityboulevard.com/2024/04/alert-connectwise-f5-software-flaws-used-to-breach-networks/	securityboulevard	news;Security Bloggers Network;Chinese cyber espionage;Connectwise F5 software flaws;Custom hacking tools;CVE-2023-46747;CVE-2024-1709;cyber threat intelligence;Cybersecurity News;Cybersecurity Vulnerabilities;Exploitable Vulnerabilities;Mandiant report;Network security risks;State-backed hacking;UNC5174 threat actor;	1	2024-04-02	警示:用于破坏网络的连接F5软件法
22661	USRC春日破冰挖洞寻宝计划｜春耕有成，安全同行	https://www.freebuf.com/fevents/397588.html	freebuf	news;活动;	1	2024-04-10	USRC春日破冰挖洞寻宝计划｜春耕有成，安全同行
9005	Ransomware Group “RA World” Changes Its’ Name and Begins Targeting Countries Around the Globe	https://blog.knowbe4.com/ransomware-group-ra-changes-name-and-begins-targeting-countries-around-the-globe	knowbe4	news;Phishing;Ransomware;Security Culture;	2	2024-03-21	“RA World”Ransomware Group “RA World”改变了名称,开始在全球各地攻击目标国
24333	Apple: Mercenary spyware attacks target iPhone users in 92 countries	https://www.bleepingcomputer.com/news/security/apple-mercenary-spyware-attacks-target-iphone-users-in-92-countries/	bleepingcomputer	news;Security;Apple;Mobile;	2	2024-04-11	Apple: Mercenary Speaterware攻击92个国家的iPhone用户。
24325	Navigating Legal Challenges of Generative AI for the Board: A Strategic Guide	https://securityboulevard.com/2024/04/navigating-legal-challenges-of-generative-ai-for-the-board-a-strategic-guide/	securityboulevard	news;Security Bloggers Network;Blog;Topic;	1	2024-04-11	A. 指导理事会应对产生大赦国际的法律挑战:战略指南
24335	CISA makes its 'Malware Next-Gen' analysis system publicly available	https://www.bleepingcomputer.com/news/security/cisa-makes-its-malware-next-gen-analysis-system-publicly-available/	bleepingcomputer	news;Security;Government;	1	2024-04-11	CISA 公开其“马利件下金”分析系统
24340	How to automate up to 90% of IT offboarding tasks	https://www.bleepingcomputer.com/news/security/how-to-automate-up-to-90-percent-of-it-offboarding-tasks/	bleepingcomputer	news;Security;	1	2024-04-11	如何将90%的信息技术脱机任务自动化
24336	CISA orders agencies impacted by Microsoft hack to mitigate risks	https://www.bleepingcomputer.com/news/security/cisa-orders-agencies-impacted-by-microsoft-hack-to-mitigate-risks/	bleepingcomputer	news;Security;Microsoft;	1	2024-04-11	CISA 受微软黑客影响的机构受CISA 订单,以减少风险
24342	LastPass: Hackers targeted employee in failed deepfake CEO call	https://www.bleepingcomputer.com/news/security/lastpass-hackers-targeted-employee-in-failed-deepfake-ceo-call/	bleepingcomputer	news;Security;	1	2024-04-11	LastPass:Hackers在失败的深假CEO电话中锁定雇员
24345	Critical Rust Flaw Poses Exploit Threat in Specific Windows Use Cases	https://www.darkreading.com/application-security/critical-rust-flaw-poses-exploit-threat-in-specific-windows-use-cases	darkreading	news;	1	2024-04-11	特定窗口使用案件中危急的绿绿绿花 Poses 开发威胁
24343	Optics giant Hoya hit with $10 million ransomware demand	https://www.bleepingcomputer.com/news/security/optics-giant-hoya-hit-with-10-million-ransomware-demand/	bleepingcomputer	news;Security;	2	2024-04-11	光学巨人霍亚受到1 000万美元的赎金软件需求打击
24323	Awkward Adolescence: Increased Risks Among Immature Ransomware Operators	https://securityboulevard.com/2024/04/awkward-adolescence-increased-risks-among-immature-ransomware-operators/	securityboulevard	news;Security Bloggers Network;analysis;Blog;Cybersecurity;GRIT;GRIT Blog;Ransomware;	2	2024-04-11	令人尴尬的青少年:在不成熟的劳作软件操作员中风险增加
24344	OpenTable is adding your first name to previously anonymous reviews	https://www.bleepingcomputer.com/news/technology/opentable-is-adding-your-first-name-to-previously-anonymous-reviews/	bleepingcomputer	news;Technology;Security;	1	2024-04-11	Opentable 正在将您的名字添加到先前匿名的复查中
23919	Client-Side Exploitation: Poisoning WebDAV+URL+LNK to Deliver Malicious Payloads	https://gbhackers.com/poisoning-webdavurllnk/	GBHacker	news;Cyber Attack;cyber security;What is;computer security;Cyber Security News;Malware;	1	2024-04-11	客户利用客户利用:毒害WebDAV+URL+LNK以提供恶意有效载荷
24337	CISA says Sisense hack impacts critical infrastructure orgs	https://www.bleepingcomputer.com/news/security/cisa-says-sisense-hack-impacts-critical-infrastructure-orgs/	bleepingcomputer	news;Security;	1	2024-04-11	CISA说,Sissense黑客 影响关键基础设施
24341	Intel and Lenovo servers impacted by 6-year-old BMC flaw	https://www.bleepingcomputer.com/news/security/intel-and-lenovo-servers-impacted-by-6-year-old-bmc-flaw/	bleepingcomputer	news;Security;	1	2024-04-11	英特尔和列诺沃服务器受到6年的BMC缺陷影响
24352	Expired Redis Service Abused to Use Metasploit Meterpreter Maliciously	https://www.darkreading.com/cloud-security/outdated-redis-service-abused-to-spread-meterpreter-backdoor	darkreading	news;	1	2024-04-11	被滥用于使用 Metasploit Meterpreceter 恶意使用的过期 Redidied Service
24346	Knostic Raises $3.3M for Enterprise GenAI Access Control	https://www.darkreading.com/application-security/knostic-raises-3-3m-for-enterprise-genai-access-control	darkreading	news;	1	2024-04-11	Knostic 提高3 300万美元,用于企业GenAI访问控制
24380	Cohesity Extends Collaboration to Strengthen Cyber Resilience With IBM Investment in Cohesity	https://www.darkreading.com/vulnerabilities-threats/cohesity-extends-collaboration-to-strengthen-cyber-resilience-with-ibm-investment-in-cohesity	darkreading	news;	1	2024-04-11	协作扩大协作,加强网络复原力,IBM对协作的投资
24381	DPRK Exploits 2 MITRE Sub-Techniques: Phantom DLL Hijacking, TCC Abuse	https://www.darkreading.com/vulnerabilities-threats/dprk-exploits-mitre-sub-techniques-phantom-dll-hijacking-tcc-abuse	darkreading	news;	1	2024-04-11	朝鲜2 MITRE子技术:幻影DL劫机、TCC滥用
24384	Why MLBOMs Are Useful for Securing the AI/ML Supply Chain	https://www.darkreading.com/vulnerabilities-threats/mlboms-are-useful-for-securing-ai-ml-supply-chain	darkreading	news;	1	2024-04-11	为何MLBOMs对保障AI/ML供应链安全有用
10955	Reverse Engineering | CTF Newbies | Part 1	https://infosecwriteups.com/reverse-engineering-ctf-newbies-part-1-cbd0aa47a90d?source=rss----7b722bfd1b8d---4	infosecwriteups	tech;infosec;ctf-writeup;hackthebox;cybersecurity;reverse-engineering;	1	2024-03-29	反向工程 * CTF Newbies * 第一部分
24486	Considering an Under Attack-as-a-Service Model? Hold  Your Horses	https://securityboulevard.com/2024/04/considering-an-under-attack-as-a-service-model-hold-your-horses/	securityboulevard	news;Security Bloggers Network;account security;bot detection;	1	2024-04-11	考虑攻击为服务模式吗?
24487	Cybersecurity Market Faces Funding Downturn in Q1 2024	https://securityboulevard.com/2024/04/cybersecurity-market-faces-funding-downturn-in-q1-2024/	securityboulevard	news;Cybersecurity;Featured;News;Security Awareness;Security Boulevard (Original);Social - Facebook;Social - X;cybersecurity funding;Finances;Investment;IPO;Pinpoint Search Group;venture-capital;	1	2024-04-11	网络安全市场面临对2024年问题1下调的供资
22840	37% of publicly shared files expose personal information	https://www.helpnetsecurity.com/2024/04/11/publicly-shared-files-expose-personal-information/	helpnetsecurity	news;Don't miss;News;cloud;cybersecurity;data protection;data security;Metomic;privacy;report;	1	2024-04-11	37%的公开分享档案披露个人信息
2831	USENIX Security ’23 – Guangke Chen, Yedi Zhang, Zhe Zhao, Fu Song – QFA2SR: Query-Free Adversarial Transfer Attacks to Speaker Recognition Systems	https://securityboulevard.com/2024/03/usenix-security-23-guangke-chen-yedi-zhang-zhe-zhao-fu-song-qfa2sr-query-free-adversarial-transfer-attacks-to-speaker-recognition-systems/	securityboulevard	news;Security Bloggers Network;Open Access Research;Security Conferences;Security Research;USENIX;USENIX Security ’23;	1	2024-03-13	USENIX 安全 23 — — 陈光基、张叶迪、赵周、福松 — — QFA2SR: 向议长承认系统进行无自由反向转移攻击
24484	Apple Warns of ‘Mercenary Spyware Attacks’ on iPhone Users	https://securityboulevard.com/2024/04/apple-warns-of-mercenary-spyware-attacks-on-iphone-users/	securityboulevard	news;Cloud Security;Cybersecurity;Data Privacy;Data Security;Endpoint;Featured;Industry Spotlight;Malware;Mobile Security;Network Security;News;Security Awareness;Security Boulevard (Original);Social - Facebook;Social - LinkedIn;Social - X;Spotlight;Threat Intelligence;Apple iPhone;NSO Group;Pegasus Spyware;	2	2024-04-11	iPhone 用户的苹果“中等间谍攻击”的警告
24485	Are you prepared for Google’s 90-day validity period on TLS certificates?	https://securityboulevard.com/2024/04/are-you-prepared-for-googles-90-day-validity-period-on-tls-certificates/	securityboulevard	news;Security Bloggers Network;SBN News;	1	2024-04-11	您是否准备在 TLS 证书上接受 Google 的90天有效期 ?
24488	Defending AI Apps Against Abuse: A Real-World Case Study	https://securityboulevard.com/2024/04/defending-ai-apps-against-abuse-a-real-world-case-study/	securityboulevard	news;Security Bloggers Network;ai app security;AI Security;Cybersecurity;Featured Blog Post;	1	2024-04-11	维护大赦国际反对滥用的应用程序:真实世界案例研究
24934	New infosec products of the week: April 12, 2024	https://www.helpnetsecurity.com/2024/04/12/new-infosec-products-of-the-week-april-12-2024/	helpnetsecurity	news;Industry news;Akamai;Bitdefender;Index Engines;Siemens;Veriato;	1	2024-04-12	2024年4月12日 2024年4月12日
24976	How to Create a Cybersecurity Incident Response Plan	https://securityboulevard.com/2024/04/how-to-create-a-cybersecurity-incident-response-plan-2/	securityboulevard	news;Security Bloggers Network;Blog Posts;Compliance Operations;Cybersecurity;	1	2024-04-11	如何制定网络安全事件应急计划
24935	Why women struggle in the cybersecurity industry	https://www.helpnetsecurity.com/2024/04/12/women-cybersecurity-workplace-experiences/	helpnetsecurity	news;News;Aleria;cybersecurity;education;report;skill development;survey;WiCyS;	1	2024-04-12	为什么妇女在网络安全行业中挣扎
24978	NIPS Troubleshooting Steps for No Log	https://securityboulevard.com/2024/04/nips-troubleshooting-steps-for-no-log/	securityboulevard	news;Security Bloggers Network;Intrusion Protection;knowledge base;NIPS;	1	2024-04-12	NIPS 无日志的排除麻烦步骤
24980	Sisense Data Breach Notice for Hyperproof Customers	https://securityboulevard.com/2024/04/sisense-data-breach-notice-for-hyperproof-customers/	securityboulevard	news;Security Bloggers Network;Blog Posts;Hyperproof News;	1	2024-04-11	防高防高防超客户的Sissense数据违反通知
25217	Demystifying Array Injections	https://infosecwriteups.com/demystifying-array-injections-934042f50132?source=rss----7b722bfd1b8d---4	infosecwriteups	tech;arrays;web-security;hacking;cybersecurity;vulnerability;	1	2024-04-12	解密阵列喷射
25265	树莓罗宾变异，现在可通过 Windows 脚本文件传播	https://www.freebuf.com/news/397709.html	freebuf	news;资讯;	1	2024-04-12	树莓罗宾变异，现在可通过 Windows 脚本文件传播
25309	Sneaky Credit Card Skimmer Disguised as Harmless Facebook Tracker	https://thehackernews.com/2024/04/sneaky-credit-card-skimmer-disguised-as.html	feedburner	news;	1	2024-04-12	Sneakky信用卡卡, 伪装成“无害的Facebook追踪器”
24491	Randall Munroe’s XKCD  ‘Types of Eclipse Photo’	https://securityboulevard.com/2024/04/randall-munroes-xkcd-types-of-eclipse-photo/	securityboulevard	news;Security Bloggers Network;Randall Munroe;XKCD;	1	2024-04-11	Randall Munroe的 XKCD XKCD “日光照片类型”
24490	How to find AMI MegaRAC BMCs running lighttpd with runZero	https://securityboulevard.com/2024/04/how-to-find-ami-megarac-bmcs-running-lighttpd-with-runzero/	securityboulevard	news;Security Bloggers Network;	1	2024-04-11	如何找到AMI MegaRAC BMC 以运行为零运行的光点运行 BMC
26153	北京交管回应网传小米汽车送车牌 	https://s.weibo.com/weibo?q=%23北京交管回应网传小米汽车送车牌 %23	sina.weibo	hotsearch;weibo	1	2024-02-23	北京交管回应网传小米汽车送车牌
26154	华为 	https://s.weibo.com/weibo?q=%23华为 %23	sina.weibo	hotsearch;weibo	1	2024-04-08	华为
26156	华为2023年净利润870亿元 	https://s.weibo.com/weibo?q=%23华为2023年净利润870亿元 %23	sina.weibo	hotsearch;weibo	1	2024-03-29	华为2023年净利润870亿元
24715	Step by Step Complete Beginners guide of iOS penetration testing with corellium	https://infosecwriteups.com/step-by-step-complete-beginners-guide-of-ios-penetration-testing-with-corellium-2b9e9c6382c2?source=rss----7b722bfd1b8d---4	infosecwriteups	tech;mobile-pentesting;bug-bounty;corellium;ios-penetration-testing;pentesting;	1	2024-04-12	以步步制制制步步制完成初创者指南,用于使用核心进行iOS渗透测试
24873	Art of onscrollend | Demonstrating XSS through scroll events write-up	https://infosecwriteups.com/art-of-onscrollend-demonstrating-xss-through-scroll-events-write-up-d3b33afaaf64?source=rss----7b722bfd1b8d---4	infosecwriteups	tech;bug-bounty;bug-bounty-tips;xss-attack;cybersecurity;hacking;	1	2024-04-12	以滚动事件写作方式展示 XSS
24878	Introduction to Kerberos	https://infosecwriteups.com/introduction-to-kerberos-39a1922ec5ac?source=rss----7b722bfd1b8d---4	infosecwriteups	tech;active-directory;penetration-testing;red-team;kerberos-authentication;kerberos;	1	2024-04-12	克尔贝罗斯介绍
24879	Unlocking the Future of Internet with Named-Data Networking (NDN)	https://infosecwriteups.com/unlocking-the-future-of-internet-with-named-data-networking-ndn-6493b99d0000?source=rss----7b722bfd1b8d---4	infosecwriteups	tech;ndn;technology;named-data-network;cybersecurity;network;	1	2024-04-12	用命名数据联网(NDN)解锁互联网的未来
24880	Unlocking with Cryptography | CTF Newbies	https://infosecwriteups.com/unlocking-with-cryptography-ctf-newbies-bbe042dc97e4?source=rss----7b722bfd1b8d---4	infosecwriteups	tech;infosec;hackthebox-writeup;cryptography;ctf;hackthebox;	1	2024-04-12	解锁加密 CTF Newbies
24881	What is the effectiveness of bombarding sites?	https://infosecwriteups.com/what-is-the-effectiveness-of-bombarding-sites-f7308c094e9b?source=rss----7b722bfd1b8d---4	infosecwriteups	tech;ddos;cybersecurity;	1	2024-04-12	轰炸地点的效力如何?
24882	Why you should care about the xz exploit	https://infosecwriteups.com/why-you-should-care-about-the-xz-exploit-7144ca210160?source=rss----7b722bfd1b8d---4	infosecwriteups	tech;infosec;security;open-source;software-development;software;	1	2024-04-12	为什么要关心XZ的剥削
10482	Decade-old Linux ‘wall’ bug helps make fake SUDO prompts, steal passwords	https://www.bleepingcomputer.com/news/security/decade-old-linux-wall-bug-helps-make-fake-sudo-prompts-steal-passwords/	bleepingcomputer	news;Security;Linux;	1	2024-03-28	十年前的Linux“墙壁”错误帮助伪造SUDO提示,窃取密码
24874	Breaking Free: 26 Advanced Techniques to Escape Docker Containers	https://infosecwriteups.com/breaking-free-26-advanced-techniques-to-escape-docker-containers-530049816b55?source=rss----7b722bfd1b8d---4	infosecwriteups	tech;bug-bounty;cybersecurity;penetration-testing;kubernetes;docker;	1	2024-04-12	突破自由:26种先进技术,以躲避多克集装箱
24711	Cybersecurity 2024: How to Secure an Entry-Level Job as a Hacker!	https://infosecwriteups.com/cybersecurity-2024-how-to-secure-an-entry-level-job-as-a-hacker-05926a08aa24?source=rss----7b722bfd1b8d---4	infosecwriteups	tech;careers;hacking;jobs;cybersecurity;career-advice;	1	2024-04-12	网络安全 2024:如何确保进入职级的工作 作为一个黑客!
24875	CVE-2024–24576: A Critical Rust Vulnerability on Windows	https://infosecwriteups.com/cve-2024-24576-a-critical-rust-vulnerability-on-windows-4f0bb1a332e9?source=rss----7b722bfd1b8d---4	infosecwriteups	tech;cybersecurity;windows;rust;penetration-testing;bug-bounty;	3	2024-04-12	CVE-2024-24576:视窗的危急风险脆弱性
24876	Exploiting Generative AI Apps With Prompt Injection	https://infosecwriteups.com/exploiting-generative-ai-apps-with-prompt-injection-33b0ff1aa07a?source=rss----7b722bfd1b8d---4	infosecwriteups	tech;llm;machine-learning;cybersecurity;azure;ai;	1	2024-04-12	利用迅速喷射的利用产生人工智能应用
24877	How I Hacked Your Private Repository in GitHub (And Got JackShit)	https://infosecwriteups.com/how-i-hacked-your-private-repository-in-github-and-got-jackshit-cb7c342570b2?source=rss----7b722bfd1b8d---4	infosecwriteups	tech;microsoft;bug-bounty;github;security;cybersecurity;	1	2024-04-12	我在吉特胡卜把你私人储藏室弄坏了 并且拿到了杰克希特
25568	iPhoneSE4规格曝光	https://s.weibo.com/weibo?q=%23iPhoneSE4规格曝光%23	sina.weibo	hotsearch;weibo	2	2024-04-12	iPhoneSE4规格曝光
26157	华为4月11日发布车和PC类产品 	https://s.weibo.com/weibo?q=%23华为4月11日发布车和PC类产品 %23	sina.weibo	hotsearch;weibo	1	2024-04-07	华为4月11日发布车和PC类产品
26159	华为Mate60全球销量破3000万台 	https://s.weibo.com/weibo?q=%23华为Mate60全球销量破3000万台 %23	sina.weibo	hotsearch;weibo	1	2024-01-30	华为Mate60全球销量破3000万台
25569	王者荣耀酷洛米	https://s.weibo.com/weibo?q=%23王者荣耀酷洛米%23	sina.weibo	hotsearch;weibo	1	2024-04-12	王者荣耀酷洛米
25600	又一间谍软件“盯上”了苹果公司，波及到 92 个国家的 iPhone 用户	https://www.freebuf.com/news/397719.html	freebuf	news;资讯;	2	2024-04-12	又一间谍软件“盯上”了苹果公司，波及到 92 个国家的 iPhone 用户
26162	华为P70或不举办发布会直接上线销售 	https://s.weibo.com/weibo?q=%23华为P70或不举办发布会直接上线销售 %23	sina.weibo	hotsearch;weibo	1	2024-04-07	华为P70或不举办发布会直接上线销售
26163	华为P70渲染图曝光 	https://s.weibo.com/weibo?q=%23华为P70渲染图曝光 %23	sina.weibo	hotsearch;weibo	1	2024-01-09	华为P70渲染图曝光
26164	华为P70系列手机延期发布 	https://s.weibo.com/weibo?q=%23华为P70系列手机延期发布 %23	sina.weibo	hotsearch;weibo	1	2024-03-07	华为P70系列手机延期发布
26165	华为Pocket2 	https://s.weibo.com/weibo?q=%23华为Pocket2 %23	sina.weibo	hotsearch;weibo	1	2024-02-22	华为Pocket2
25144	Introducing the Aembit Kerberos Trust Provider	https://securityboulevard.com/2024/04/introducing-the-aembit-kerberos-trust-provider/	securityboulevard	news;Security Bloggers Network;KERBEROS;Product updates;trust providers;	1	2024-04-11	介绍Aembit Kerberos信托提供人
9650	Power-Generation--Engineering-and-Services-Company-PGESCo---pgescocom	http://www.ransomfeed.it/index.php?page=post_details&id_post=13908	ransomfeed	ransom;ransomhub;	1	2024-03-22	电力、工程、工程、服务、服务、公司、企业、企业、企业、企业、企业、企业、企业、企业、企业、企业、企业、企业、企业、企业、企业、企业、企业、企业、企业、企业、企业、企业、企业、企业、企业、企业、企业、企业、企业、企业、企业、企业、企业、企业、企业、企业、企业、企业、企业、企业、企业、企业、企业、企业、企业、企业、企业、企业、企业、企业、企业、企业、企业、企业、企业、企业、企业、企业、企业、企业、企业、企业、企业、企业、企业、企业、企业、企业、企业、企业、企业、企业、企业、企业、企业
22405	Watch This? Patch This! LG Fixes Smart TV Vulns	https://securityboulevard.com/2024/04/lg-smart-tv-update-richixbw/	securityboulevard	news;Analytics & Intelligence;API Security;Application Security;AppSec;Cybersecurity;Data Privacy;Data Security;Deep Fake and Other Social Engineering Tactics;Editorial Calendar;Endpoint;Featured;Governance, Risk & Compliance;Humor;Identity & Access;Identity and Access Management;Industry Spotlight;IOT;IoT & ICS Security;Most Read This Week;Network Security;News;Popular Post;Securing the Edge;Security at the Edge;Security Awareness;Security Boulevard (Original);Security Challenges and Opportunities of Remote Work;Social - Facebook;Social - LinkedIn;Social - X;Social Engineering;Spotlight;Threat Intelligence;Threats & Breaches;Vulnerabilities;Zero-Trust;BitDefender;bitdefender research;Consumer IoT;CVE-2023-6317;CVE-2023-6318;CVE-2023-6319;CVE-2023-6320;iot;LG;SB Blogwatch;Smart TV;Smart TV Security;Smart TV Vulnerability;Smart TVs;The ‘S’ in IoT stands for Security;TV;WebOS;	1	2024-04-10	看这个 修这个 修这个 LG修补智能电视Vulns
25075	政策解读 | 《金融业开源软件应用管理指南》	https://www.freebuf.com/articles/neopoints/397605.html	freebuf	news;观点;	1	2024-04-11	政策解读 | 《金融业开源软件应用管理指南》
25098	Strategies to cultivate collaboration between NetOps and SecOps	https://www.helpnetsecurity.com/2024/04/12/debby-briggs-netscout-netops-secops/	helpnetsecurity	news;Don't miss;Features;Hot stuff;News;artificial intelligence;automation;cloud;collaboration;cybersecurity;Netscout;opinion;strategy;	1	2024-04-12	培养网络观测站与保密点之间协作的战略
24489	Google Extends Generative AI Reach Deeper into Security	https://securityboulevard.com/2024/04/google-extends-generative-ai-reach-deeper-into-security/	securityboulevard	news;AI and ML in Security;Analytics & Intelligence;Cybersecurity;Featured;News;Security Boulevard (Original);Social - Facebook;Social - X;Threat Intelligence;AI;attack paths;gcp;Gemini;google;Google Chronicle;Google Cloud Platform;LLMs;	1	2024-04-11	Google 扩展创创A AI 更深入安全
8939	The AI Advantage: Mitigating the Security Alert Deluge in a Talent-Scarce Landscape	https://securityboulevard.com/2024/03/the-ai-advantage-mitigating-the-security-alert-deluge-in-a-talent-scarce-landscape/	securityboulevard	news;Analytics & Intelligence;Security Bloggers Network;AI;AI Cybersecurity;Artificial Intelligence;Blog;Context Aware AI;Data Overload;Ponemon;Self-Supervised AI;Third Wave AI;	1	2024-03-21	AI的优势:在高才华-刮痕风景中减少安全警报的险险情
25100	The next wave of mobile threats	https://www.helpnetsecurity.com/2024/04/12/planning-mobile-security-strategy-video/	helpnetsecurity	news;Don't miss;Hot stuff;Video;application security;BYOD;cybersecurity;digital transformation;Jamf;mobile security;remote working;strategy;threats;video;	1	2024-04-12	下一波移动威胁
25136	U.S. Federal Agencies Ordered to Hunt for Signs of Microsoft Breach and Mitigate Risks	https://thehackernews.com/2024/04/us-federal-agencies-ordered-to-hunt-for.html	feedburner	news;	1	2024-04-12	美国联邦机构下令追捕微软违反和降低风险的信号
2675	LastPass’ CIO vision for driving business strategy, innovation	https://www.helpnetsecurity.com/2024/03/13/asad-siddiqui-lastpass-cios-strategic-role/	helpnetsecurity	news;Don't miss;Features;Hot stuff;News;artificial intelligence;CIO;cybersecurity;data management;digital transformation;LastPass;opinion;privacy;regulation;strategy;tips;	1	2024-03-13	LastPass的首席信息干事关于推动商业战略、创新的愿景
24493	USENIX Security ’23 – You Can’t See Me: Physical Removal Attacks on LiDAR-based Autonomous Vehicles Driving Frameworks	https://securityboulevard.com/2024/04/usenix-security-23-you-cant-see-me-physical-removal-attacks-on-lidar-based-autonomous-vehicles-driving-frameworks/	securityboulevard	news;Security Bloggers Network;USENIX;USENIX Security ’23;	1	2024-04-11	USENIX 安全 23 — — 你看不到我:对基于LIDAR的自治车辆驾驶框架的有形驱逐攻击
9429	Apple M-Series FAIL: GoFetch Flaw Finds Crypto Keys	https://securityboulevard.com/2024/03/apple-m-gofetch-richixbw/	securityboulevard	news;Application Security;Cybersecurity;Data Privacy;Data Security;Deep Fake and Other Social Engineering Tactics;Editorial Calendar;Endpoint;Featured;Governance, Risk & Compliance;Humor;Incident Response;Industry Spotlight;Insider Threats;Malware;Mobile Security;Most Read This Week;News;Popular Post;Securing Open Source;Securing the Edge;Security at the Edge;Security Awareness;Security Boulevard (Original);Security Challenges and Opportunities of Remote Work;Social - Facebook;Social - LinkedIn;Social - X;Social Engineering;Software Supply Chain Security;Spotlight;Threats & Breaches;Vulnerabilities;Zero-Trust;Apple;apple bug;Apple Data Security;apple hack;apple hacker;Apple iOS;Apple iPad;ARM;cache;dmp;GoFetch;iPad;M1;M2;M3;Macintosh;macos;SB Blogwatch;	1	2024-03-22	苹果 M- 系列 FALL: GoFetch 法律查找加密密钥
24492	Simbian Unveils Generative AI Platform to Automate Cybersecurity Tasks	https://securityboulevard.com/2024/04/simbian-unveils-generative-ai-platform-to-automate-cybersecurity-tasks/	securityboulevard	news;AI and ML in Security;Cybersecurity;Featured;News;Security Boulevard (Original);Social - Facebook;Social - X;AI;Automation;generative AI;Large language models (LLMs);simbian;	1	2024-04-11	Simbian Unveils 为自动化网络安全任务创建的 AI 平台
2536	Google Splashes the Cash in Bug Bounty Bonanza: $59 Million to Date	https://securityboulevard.com/2024/03/google-bug-bounty-vrp-richixbw/	securityboulevard	news;API Security;AppSec;Cloud Security;Cybersecurity;Data Privacy;Data Security;DevOps;DevSecOps;Editorial Calendar;Endpoint;Featured;Governance, Risk & Compliance;Humor;Identity & Access;Identity and Access Management;Incident Response;Industry Spotlight;IOT;IoT & ICS Security;Mobile Security;Most Read This Week;Network Security;News;Popular Post;Securing Open Source;Securing the Cloud;Securing the Edge;Security at the Edge;Security Awareness;Security Boulevard (Original);Security Challenges and Opportunities of Remote Work;Security Operations;Social - Facebook;Social - LinkedIn;Social - X;Social Engineering;Software Supply Chain Security;Spotlight;Threats & Breaches;Vulnerabilities;Zero-Trust;alphabet;bounty;bug bounty;bug bounty program;bugbounty;ethical hacker;ethical hackers;ethical hacking;google;SB Blogwatch;Vulnerability Rewards Program (VRP);white hat;white hat hacker;white hat hackers;White Hat Security;White Hats;WhiteHat;whitehat hackers;WhiteHat Security;	1	2024-03-13	谷歌在Bug Bunty Bonanza 中冲洗现金:至今5 900万美元
25316	CISA: Russian Hackers Stole Emails Between U.S. Agencies and Microsoft	https://securityboulevard.com/2024/04/cisa-russian-hackers-stole-emails-between-u-s-agencies-and-microsoft/	securityboulevard	news;Cloud Security;Cybersecurity;Data Security;Featured;Identity & Access;Network Security;News;Security Boulevard (Original);Social - Facebook;Social - LinkedIn;Social - X;Spotlight;Threat Intelligence;Threats & Breaches;CISA Emergency Directive;Microsoft;Midnight Blizzard;Russian hackers;	3	2024-04-12	CISA: 俄罗斯黑客偷盗美国机构与微软之间的邮件
26228	姚安娜现身华为发布会 	https://s.weibo.com/weibo?q=%23姚安娜现身华为发布会 %23	sina.weibo	hotsearch;weibo	1	2024-02-23	姚安娜现身华为发布会
26229	媒体泄密小米汽车将赔三百万罚金 	https://s.weibo.com/weibo?q=%23媒体泄密小米汽车将赔三百万罚金 %23	sina.weibo	hotsearch;weibo	1	2023-12-17	媒体泄密小米汽车将赔三百万罚金
26231	字节红包	https://s.weibo.com/weibo?q=%23字节红包%23	sina.weibo	hotsearch;weibo	1	2024-02-07	字节红包
26232	字节跳动回应懂车帝将成独立公司 	https://s.weibo.com/weibo?q=%23字节跳动回应懂车帝将成独立公司 %23	sina.weibo	hotsearch;weibo	1	2024-01-10	字节跳动回应懂车帝将成独立公司
26234	字节跳动早期投资人严厉谴责抖音 	https://s.weibo.com/weibo?q=%23字节跳动早期投资人严厉谴责抖音 %23	sina.weibo	hotsearch;weibo	1	2024-01-05	字节跳动早期投资人严厉谴责抖音
26235	字节跳动辟谣推出中文版Sora 	https://s.weibo.com/weibo?q=%23字节跳动辟谣推出中文版Sora %23	sina.weibo	hotsearch;weibo	1	2024-02-20	字节跳动辟谣推出中文版Sora
26236	孙颖莎说眼泪是捍卫荣耀的泪 	https://s.weibo.com/weibo?q=%23孙颖莎说眼泪是捍卫荣耀的泪 %23	sina.weibo	hotsearch;weibo	1	2024-02-26	孙颖莎说眼泪是捍卫荣耀的泪
26237	官方回应阿里西藏全区公务员为一人献血 	https://s.weibo.com/weibo?q=%23官方回应阿里西藏全区公务员为一人献血 %23	sina.weibo	hotsearch;weibo	1	2023-11-29	官方回应阿里西藏全区公务员为一人献血
26240	客服回应小米SU7展车车门缝没对齐 	https://s.weibo.com/weibo?q=%23客服回应小米SU7展车车门缝没对齐 %23	sina.weibo	hotsearch;weibo	1	2024-03-28	客服回应小米SU7展车车门缝没对齐
26241	小爱同学被雷军喊崩了 	https://s.weibo.com/weibo?q=%23小爱同学被雷军喊崩了 %23	sina.weibo	hotsearch;weibo	1	2024-03-29	小爱同学被雷军喊崩了
26242	小爱将小米汽车识别为保时捷 	https://s.weibo.com/weibo?q=%23小爱将小米汽车识别为保时捷 %23	sina.weibo	hotsearch;weibo	1	2023-12-28	小爱将小米汽车识别为保时捷
26243	小米 	https://s.weibo.com/weibo?q=%23小米 %23	sina.weibo	hotsearch;weibo	1	2024-03-12	小米
26244	小米	https://s.weibo.com/weibo?q=%23小米%23	sina.weibo	hotsearch;weibo	1	2023-12-12	小米
26245	小米14Ultra欧洲定价近国内一倍 	https://s.weibo.com/weibo?q=%23小米14Ultra欧洲定价近国内一倍 %23	sina.weibo	hotsearch;weibo	1	2024-02-26	小米14Ultra欧洲定价近国内一倍
26246	小米14Ultra起售价6499元 	https://s.weibo.com/weibo?q=%23小米14Ultra起售价6499元 %23	sina.weibo	hotsearch;weibo	1	2024-02-22	小米14Ultra起售价6499元
26247	小米14Ultra进光量超苹果100% 	https://s.weibo.com/weibo?q=%23小米14Ultra进光量超苹果100% %23	sina.weibo	hotsearch;weibo	1	2024-02-19	小米14Ultra进光量超苹果100%
26248	小米14ultra 	https://s.weibo.com/weibo?q=%23小米14ultra %23	sina.weibo	hotsearch;weibo	1	2024-02-22	小米14ultra
26249	小米2023年营收2709.7亿 	https://s.weibo.com/weibo?q=%23小米2023年营收2709.7亿 %23	sina.weibo	hotsearch;weibo	1	2024-03-19	小米2023年营收2709.7亿
26250	小米Civi4Pro 	https://s.weibo.com/weibo?q=%23小米Civi4Pro %23	sina.weibo	hotsearch;weibo	1	2024-03-18	小米Civi4Pro
26251	小米Civi4Pro真香 	https://s.weibo.com/weibo?q=%23小米Civi4Pro真香 %23	sina.weibo	hotsearch;weibo	1	2024-03-21	小米Civi4Pro真香
26252	小米Civi4Pro首发第三代骁龙8s 	https://s.weibo.com/weibo?q=%23小米Civi4Pro首发第三代骁龙8s %23	sina.weibo	hotsearch;weibo	1	2024-03-18	小米Civi4Pro首发第三代骁龙8s
26253	小米Civi4Pro首发评测 	https://s.weibo.com/weibo?q=%23小米Civi4Pro首发评测 %23	sina.weibo	hotsearch;weibo	1	2024-03-21	小米Civi4Pro首发评测
26254	小米SU7 	https://s.weibo.com/weibo?q=%23小米SU7 %23	sina.weibo	hotsearch;weibo	1	2024-03-28	小米SU7
26255	小米SU7	https://s.weibo.com/weibo?q=%23小米SU7%23	sina.weibo	hotsearch;weibo	1	2024-03-28	小米SU7
26257	小米SU7价格 	https://s.weibo.com/weibo?q=%23小米SU7价格 %23	sina.weibo	hotsearch;weibo	1	2024-03-12	小米SU7价格
26258	小米SU7价格真香 	https://s.weibo.com/weibo?q=%23小米SU7价格真香 %23	sina.weibo	hotsearch;weibo	1	2024-03-28	小米SU7价格真香
26259	小米SU7价格预测 	https://s.weibo.com/weibo?q=%23小米SU7价格预测 %23	sina.weibo	hotsearch;weibo	1	2024-03-28	小米SU7价格预测
26260	小米SU7内饰 	https://s.weibo.com/weibo?q=%23小米SU7内饰 %23	sina.weibo	hotsearch;weibo	1	2024-03-28	小米SU7内饰
26263	小米SU7售价21.59万元起 	https://s.weibo.com/weibo?q=%23小米SU7售价21.59万元起 %23	sina.weibo	hotsearch;weibo	1	2024-03-28	小米SU7售价21.59万元起
26264	小米SU7在门店开启静态展示 	https://s.weibo.com/weibo?q=%23小米SU7在门店开启静态展示 %23	sina.weibo	hotsearch;weibo	1	2024-03-25	小米SU7在门店开启静态展示
26265	小米SU7官方实拍照首曝 	https://s.weibo.com/weibo?q=%23小米SU7官方实拍照首曝 %23	sina.weibo	hotsearch;weibo	1	2023-12-28	小米SU7官方实拍照首曝
26266	小米SU7成50万内最期待车型 	https://s.weibo.com/weibo?q=%23小米SU7成50万内最期待车型 %23	sina.weibo	hotsearch;weibo	1	2024-01-17	小米SU7成50万内最期待车型
26268	小米SU7智能座舱实车体验 	https://s.weibo.com/weibo?q=%23小米SU7智能座舱实车体验 %23	sina.weibo	hotsearch;weibo	1	2024-01-04	小米SU7智能座舱实车体验
26270	小米SU7真车实测 	https://s.weibo.com/weibo?q=%23小米SU7真车实测 %23	sina.weibo	hotsearch;weibo	1	2023-12-29	小米SU7真车实测
26271	小米SU7真车比图强 	https://s.weibo.com/weibo?q=%23小米SU7真车比图强 %23	sina.weibo	hotsearch;weibo	1	2024-03-25	小米SU7真车比图强
26272	小米SU7续航700公里起步 	https://s.weibo.com/weibo?q=%23小米SU7续航700公里起步 %23	sina.weibo	hotsearch;weibo	1	2024-03-27	小米SU7续航700公里起步
26273	小米SU7被曝设计缺陷 	https://s.weibo.com/weibo?q=%23小米SU7被曝设计缺陷 %23	sina.weibo	hotsearch;weibo	1	2024-04-07	小米SU7被曝设计缺陷
26274	小米SU7订单被加价数千元转让 	https://s.weibo.com/weibo?q=%23小米SU7订单被加价数千元转让 %23	sina.weibo	hotsearch;weibo	1	2024-03-29	小米SU7订单被加价数千元转让
26275	小米SU7评测 	https://s.weibo.com/weibo?q=%23小米SU7评测 %23	sina.weibo	hotsearch;weibo	1	2024-03-29	小米SU7评测
26286	小米公布SU7设计稿 	https://s.weibo.com/weibo?q=%23小米公布SU7设计稿 %23	sina.weibo	hotsearch;weibo	1	2024-01-22	小米公布SU7设计稿
26288	小米北京昌平智能工厂正式落成投产 	https://s.weibo.com/weibo?q=%23小米北京昌平智能工厂正式落成投产 %23	sina.weibo	hotsearch;weibo	1	2024-02-18	小米北京昌平智能工厂正式落成投产
26289	小米发布会 	https://s.weibo.com/weibo?q=%23小米发布会 %23	sina.weibo	hotsearch;weibo	1	2024-03-21	小米发布会
26290	小米发布会直播 	https://s.weibo.com/weibo?q=%23小米发布会直播 %23	sina.weibo	hotsearch;weibo	1	2024-03-28	小米发布会直播
26291	小米发文炮轰余承东 	https://s.weibo.com/weibo?q=%23小米发文炮轰余承东 %23	sina.weibo	hotsearch;weibo	1	2023-12-12	小米发文炮轰余承东
26292	小米回应冰冷的40亿 	https://s.weibo.com/weibo?q=%23小米回应冰冷的40亿 %23	sina.weibo	hotsearch;weibo	1	2023-12-01	小米回应冰冷的40亿
26293	小米回应无法退定金问题 	https://s.weibo.com/weibo?q=%23小米回应无法退定金问题 %23	sina.weibo	hotsearch;weibo	1	2024-03-29	小米回应无法退定金问题
26294	小米回应智能门锁半夜自己开门 	https://s.weibo.com/weibo?q=%23小米回应智能门锁半夜自己开门 %23	sina.weibo	hotsearch;weibo	1	2023-12-18	小米回应智能门锁半夜自己开门
26296	小米回应测试车逃费被罚 	https://s.weibo.com/weibo?q=%23小米回应测试车逃费被罚 %23	sina.weibo	hotsearch;weibo	1	2024-03-19	小米回应测试车逃费被罚
26297	小米回应试驾车爆胎视频 	https://s.weibo.com/weibo?q=%23小米回应试驾车爆胎视频 %23	sina.weibo	hotsearch;weibo	1	2024-03-29	小米回应试驾车爆胎视频
26298	小米回应雷军账号真实姓名刘伟 	https://s.weibo.com/weibo?q=%23小米回应雷军账号真实姓名刘伟 %23	sina.weibo	hotsearch;weibo	1	2024-01-12	小米回应雷军账号真实姓名刘伟
26299	小米官宣新发布会主讲人 	https://s.weibo.com/weibo?q=%23小米官宣新发布会主讲人 %23	sina.weibo	hotsearch;weibo	1	2024-02-21	小米官宣新发布会主讲人
26300	小米官宣汽车发布会 	https://s.weibo.com/weibo?q=%23小米官宣汽车发布会 %23	sina.weibo	hotsearch;weibo	1	2023-12-25	小米官宣汽车发布会
26301	小米官方辟谣澎湃OS是自研系统 	https://s.weibo.com/weibo?q=%23小米官方辟谣澎湃OS是自研系统 %23	sina.weibo	hotsearch;weibo	1	2024-01-22	小米官方辟谣澎湃OS是自研系统
26302	小米定金 	https://s.weibo.com/weibo?q=%23小米定金 %23	sina.weibo	hotsearch;weibo	1	2024-03-30	小米定金
26303	小米就某芯片公司事件辟谣 	https://s.weibo.com/weibo?q=%23小米就某芯片公司事件辟谣 %23	sina.weibo	hotsearch;weibo	1	2023-12-24	小米就某芯片公司事件辟谣
26304	小米平板 	https://s.weibo.com/weibo?q=%23小米平板 %23	sina.weibo	hotsearch;weibo	1	2024-02-22	小米平板
26305	小米平板上车 	https://s.weibo.com/weibo?q=%23小米平板上车 %23	sina.weibo	hotsearch;weibo	1	2023-12-28	小米平板上车
26306	小米开放式耳机 	https://s.weibo.com/weibo?q=%23小米开放式耳机 %23	sina.weibo	hotsearch;weibo	1	2024-04-08	小米开放式耳机
26309	小米智能门锁多次自动打开 	https://s.weibo.com/weibo?q=%23小米智能门锁多次自动打开 %23	sina.weibo	hotsearch;weibo	1	2023-12-18	小米智能门锁多次自动打开
26310	小米智驾目标今年进入行业第一阵营 	https://s.weibo.com/weibo?q=%23小米智驾目标今年进入行业第一阵营 %23	sina.weibo	hotsearch;weibo	1	2024-03-26	小米智驾目标今年进入行业第一阵营
26311	小米暴涨12.13% 	https://s.weibo.com/weibo?q=%23小米暴涨12.13% %23	sina.weibo	hotsearch;weibo	1	2024-03-29	小米暴涨12.13%
26312	小米汽车 	https://s.weibo.com/weibo?q=%23小米汽车 %23	sina.weibo	hotsearch;weibo	1	2023-12-17	小米汽车
26313	小米汽车	https://s.weibo.com/weibo?q=%23小米汽车%23	sina.weibo	hotsearch;weibo	1	2023-12-28	小米汽车
26314	小米汽车27分钟大定突破50000台 	https://s.weibo.com/weibo?q=%23小米汽车27分钟大定突破50000台 %23	sina.weibo	hotsearch;weibo	1	2024-03-28	小米汽车27分钟大定突破50000台
26315	小米汽车APP 	https://s.weibo.com/weibo?q=%23小米汽车APP %23	sina.weibo	hotsearch;weibo	1	2024-03-26	小米汽车APP
26316	小米汽车F码被炒至5万元 	https://s.weibo.com/weibo?q=%23小米汽车F码被炒至5万元 %23	sina.weibo	hotsearch;weibo	1	2024-03-29	小米汽车F码被炒至5万元
26318	小米汽车一晚收到1亿元定金 	https://s.weibo.com/weibo?q=%23小米汽车一晚收到1亿元定金 %23	sina.weibo	hotsearch;weibo	1	2024-03-29	小米汽车一晚收到1亿元定金
26319	小米汽车三名员工未经许可参与研讨会被辞退 	https://s.weibo.com/weibo?q=%23小米汽车三名员工未经许可参与研讨会被辞退 %23	sina.weibo	hotsearch;weibo	1	2023-12-19	小米汽车三名员工未经许可参与研讨会被辞退
26320	小米汽车三段自驾测试 	https://s.weibo.com/weibo?q=%23小米汽车三段自驾测试 %23	sina.weibo	hotsearch;weibo	1	2023-12-29	小米汽车三段自驾测试
26321	小米汽车上市24小时大定88898台 	https://s.weibo.com/weibo?q=%23小米汽车上市24小时大定88898台 %23	sina.weibo	hotsearch;weibo	1	2024-03-29	小米汽车上市24小时大定88898台
26322	小米汽车上架AppStore 	https://s.weibo.com/weibo?q=%23小米汽车上架AppStore %23	sina.weibo	hotsearch;weibo	1	2024-03-25	小米汽车上架AppStore
26323	小米汽车价格 	https://s.weibo.com/weibo?q=%23小米汽车价格 %23	sina.weibo	hotsearch;weibo	1	2023-12-28	小米汽车价格
26324	小米汽车保单价格曝光 	https://s.weibo.com/weibo?q=%23小米汽车保单价格曝光 %23	sina.weibo	hotsearch;weibo	1	2024-01-30	小米汽车保单价格曝光
26325	小米汽车发布会 	https://s.weibo.com/weibo?q=%23小米汽车发布会 %23	sina.weibo	hotsearch;weibo	1	2023-12-28	小米汽车发布会
26326	小米汽车发布会不发产品 	https://s.weibo.com/weibo?q=%23小米汽车发布会不发产品 %23	sina.weibo	hotsearch;weibo	1	2023-12-25	小米汽车发布会不发产品
26327	小米汽车向华为比亚迪致敬 	https://s.weibo.com/weibo?q=%23小米汽车向华为比亚迪致敬 %23	sina.weibo	hotsearch;weibo	1	2023-12-27	小米汽车向华为比亚迪致敬
26330	小米汽车回应 	https://s.weibo.com/weibo?q=%23小米汽车回应 %23	sina.weibo	hotsearch;weibo	1	2024-03-29	小米汽车回应
26332	小米汽车回应SU7大量订单被转让 	https://s.weibo.com/weibo?q=%23小米汽车回应SU7大量订单被转让 %23	sina.weibo	hotsearch;weibo	1	2024-03-30	小米汽车回应SU7大量订单被转让
26333	小米汽车回应提车日期 	https://s.weibo.com/weibo?q=%23小米汽车回应提车日期 %23	sina.weibo	hotsearch;weibo	1	2024-04-02	小米汽车回应提车日期
26335	小米汽车定价策略曝光 	https://s.weibo.com/weibo?q=%23小米汽车定价策略曝光 %23	sina.weibo	hotsearch;weibo	1	2024-02-23	小米汽车定价策略曝光
26336	小米汽车实现100%自动化在线检测 	https://s.weibo.com/weibo?q=%23小米汽车实现100%自动化在线检测 %23	sina.weibo	hotsearch;weibo	1	2024-04-01	小米汽车实现100%自动化在线检测
26337	小米汽车引发同行快速反应 	https://s.weibo.com/weibo?q=%23小米汽车引发同行快速反应 %23	sina.weibo	hotsearch;weibo	1	2024-04-01	小米汽车引发同行快速反应
26338	小米汽车性价比 	https://s.weibo.com/weibo?q=%23小米汽车性价比 %23	sina.weibo	hotsearch;weibo	1	2024-03-29	小米汽车性价比
26340	小米汽车技术发布会 	https://s.weibo.com/weibo?q=%23小米汽车技术发布会 %23	sina.weibo	hotsearch;weibo	1	2023-12-25	小米汽车技术发布会
26341	小米汽车收到退单及改配需求469例 	https://s.weibo.com/weibo?q=%23小米汽车收到退单及改配需求469例 %23	sina.weibo	hotsearch;weibo	1	2024-03-29	小米汽车收到退单及改配需求469例
26342	小米汽车最早二季度交付 	https://s.weibo.com/weibo?q=%23小米汽车最早二季度交付 %23	sina.weibo	hotsearch;weibo	1	2024-02-26	小米汽车最早二季度交付
26343	小米汽车电池安全极限测试 	https://s.weibo.com/weibo?q=%23小米汽车电池安全极限测试 %23	sina.weibo	hotsearch;weibo	1	2024-01-02	小米汽车电池安全极限测试
26344	小米汽车电池扛子弹 	https://s.weibo.com/weibo?q=%23小米汽车电池扛子弹 %23	sina.weibo	hotsearch;weibo	1	2024-01-02	小米汽车电池扛子弹
26346	小米汽车被曝出现多起退定投诉 	https://s.weibo.com/weibo?q=%23小米汽车被曝出现多起退定投诉 %23	sina.weibo	hotsearch;weibo	1	2024-03-29	小米汽车被曝出现多起退定投诉
26347	小米汽车要求供应商月产1万辆 	https://s.weibo.com/weibo?q=%23小米汽车要求供应商月产1万辆 %23	sina.weibo	hotsearch;weibo	1	2024-04-02	小米汽车要求供应商月产1万辆
26348	小米汽车试驾者驾龄需达2年 	https://s.weibo.com/weibo?q=%23小米汽车试驾者驾龄需达2年 %23	sina.weibo	hotsearch;weibo	1	2024-04-03	小米汽车试驾者驾龄需达2年
26349	小米汽车退定 	https://s.weibo.com/weibo?q=%23小米汽车退定 %23	sina.weibo	hotsearch;weibo	1	2024-03-29	小米汽车退定
26350	小米汽车送北京牌照失实 	https://s.weibo.com/weibo?q=%23小米汽车送北京牌照失实 %23	sina.weibo	hotsearch;weibo	1	2024-02-23	小米汽车送北京牌照失实
26351	小米汽车遭遇上百余名消费者投诉 	https://s.weibo.com/weibo?q=%23小米汽车遭遇上百余名消费者投诉 %23	sina.weibo	hotsearch;weibo	1	2024-03-30	小米汽车遭遇上百余名消费者投诉
26353	小米汽车销售称泄密要赔百万 	https://s.weibo.com/weibo?q=%23小米汽车销售称泄密要赔百万 %23	sina.weibo	hotsearch;weibo	1	2024-03-26	小米汽车销售称泄密要赔百万
26354	小米汽车销量 	https://s.weibo.com/weibo?q=%23小米汽车销量 %23	sina.weibo	hotsearch;weibo	1	2024-03-28	小米汽车销量
26355	小米汽车锁单量 	https://s.weibo.com/weibo?q=%23小米汽车锁单量 %23	sina.weibo	hotsearch;weibo	1	2024-04-01	小米汽车锁单量
26356	小米汽车门店回应SU7座椅包浆 	https://s.weibo.com/weibo?q=%23小米汽车门店回应SU7座椅包浆 %23	sina.weibo	hotsearch;weibo	1	2024-04-03	小米汽车门店回应SU7座椅包浆
26357	小米汽车颜值 	https://s.weibo.com/weibo?q=%23小米汽车颜值 %23	sina.weibo	hotsearch;weibo	1	2023-12-28	小米汽车颜值
26358	小米测试车被天津高速抓到逃费 	https://s.weibo.com/weibo?q=%23小米测试车被天津高速抓到逃费 %23	sina.weibo	hotsearch;weibo	1	2024-03-19	小米测试车被天津高速抓到逃费
26359	小米澎湃OS技术白皮书发布 	https://s.weibo.com/weibo?q=%23小米澎湃OS技术白皮书发布 %23	sina.weibo	hotsearch;weibo	1	2023-12-07	小米澎湃OS技术白皮书发布
26360	小米澎湃OS新logo 	https://s.weibo.com/weibo?q=%23小米澎湃OS新logo %23	sina.weibo	hotsearch;weibo	1	2023-12-27	小米澎湃OS新logo
26361	小米澎湃OS有点东西 	https://s.weibo.com/weibo?q=%23小米澎湃OS有点东西 %23	sina.weibo	hotsearch;weibo	1	2023-12-07	小米澎湃OS有点东西
26362	小米王化回应SU7试驾视频泄露 	https://s.weibo.com/weibo?q=%23小米王化回应SU7试驾视频泄露 %23	sina.weibo	hotsearch;weibo	1	2024-03-28	小米王化回应SU7试驾视频泄露
26363	小米终极辟谣 	https://s.weibo.com/weibo?q=%23小米终极辟谣 %23	sina.weibo	hotsearch;weibo	1	2024-01-05	小米终极辟谣
26364	小米网吧 	https://s.weibo.com/weibo?q=%23小米网吧 %23	sina.weibo	hotsearch;weibo	1	2023-12-08	小米网吧
26365	小米股票 	https://s.weibo.com/weibo?q=%23小米股票 %23	sina.weibo	hotsearch;weibo	1	2024-03-29	小米股票
26366	小米要造一辆什么样的车 	https://s.weibo.com/weibo?q=%23小米要造一辆什么样的车 %23	sina.weibo	hotsearch;weibo	1	2023-12-25	小米要造一辆什么样的车
26368	小米订单 	https://s.weibo.com/weibo?q=%23小米订单 %23	sina.weibo	hotsearch;weibo	1	2024-03-29	小米订单
26369	小米超级电机V8s超30000转 	https://s.weibo.com/weibo?q=%23小米超级电机V8s超30000转 %23	sina.weibo	hotsearch;weibo	1	2023-12-29	小米超级电机V8s超30000转
26370	小米超越苹果登顶中国第一 	https://s.weibo.com/weibo?q=%23小米超越苹果登顶中国第一 %23	sina.weibo	hotsearch;weibo	1	2024-01-22	小米超越苹果登顶中国第一
26371	小米跌出Q4中国智能手机市场前五 	https://s.weibo.com/weibo?q=%23小米跌出Q4中国智能手机市场前五 %23	sina.weibo	hotsearch;weibo	1	2024-01-25	小米跌出Q4中国智能手机市场前五
26372	小米车模 	https://s.weibo.com/weibo?q=%23小米车模 %23	sina.weibo	hotsearch;weibo	1	2024-03-28	小米车模
26373	小米辟谣网传汽车售价 	https://s.weibo.com/weibo?q=%23小米辟谣网传汽车售价 %23	sina.weibo	hotsearch;weibo	1	2024-01-03	小米辟谣网传汽车售价
26374	小米重回国产品牌第一 	https://s.weibo.com/weibo?q=%23小米重回国产品牌第一 %23	sina.weibo	hotsearch;weibo	1	2023-12-11	小米重回国产品牌第一
26383	开心消消乐崩了 	https://s.weibo.com/weibo?q=%23开心消消乐崩了 %23	sina.weibo	hotsearch;weibo	1	2024-02-18	开心消消乐崩了
26384	张万森	https://s.weibo.com/weibo?q=%23张万森%23	sina.weibo	hotsearch;weibo	1	2023-12-11	张万森
26385	张朝阳AWE第一站直奔华为展台 	https://s.weibo.com/weibo?q=%23张朝阳AWE第一站直奔华为展台 %23	sina.weibo	hotsearch;weibo	1	2024-03-14	张朝阳AWE第一站直奔华为展台
26386	张真源荣耀王者61星 	https://s.weibo.com/weibo?q=%23张真源荣耀王者61星 %23	sina.weibo	hotsearch;weibo	1	2024-02-07	张真源荣耀王者61星
26388	当事人丈夫否认阿里全体公务员为其妻献血 	https://s.weibo.com/weibo?q=%23当事人丈夫否认阿里全体公务员为其妻献血 %23	sina.weibo	hotsearch;weibo	1	2023-11-29	当事人丈夫否认阿里全体公务员为其妻献血
26390	微信崩了 	https://s.weibo.com/weibo?q=%23微信崩了 %23	sina.weibo	hotsearch;weibo	1	2024-04-01	微信崩了
26391	微博崩了 	https://s.weibo.com/weibo?q=%23微博崩了 %23	sina.weibo	hotsearch;weibo	1	2024-02-01	微博崩了
26392	懂车帝实测小米SU7 	https://s.weibo.com/weibo?q=%23懂车帝实测小米SU7 %23	sina.weibo	hotsearch;weibo	1	2024-03-29	懂车帝实测小米SU7
26393	成龙	https://s.weibo.com/weibo?q=%23成龙%23	sina.weibo	hotsearch;weibo	1	2024-03-18	成龙
26394	房地产	https://s.weibo.com/weibo?q=%23房地产%23	sina.weibo	hotsearch;weibo	1	2024-03-30	房地产
26395	手机卫星通信进入荣耀时刻 	https://s.weibo.com/weibo?q=%23手机卫星通信进入荣耀时刻 %23	sina.weibo	hotsearch;weibo	1	2024-01-11	手机卫星通信进入荣耀时刻
26396	抖音买商品拼多多发货 	https://s.weibo.com/weibo?q=%23抖音买商品拼多多发货 %23	sina.weibo	hotsearch;weibo	1	2024-03-15	抖音买商品拼多多发货
26397	拼多多	https://s.weibo.com/weibo?q=%23拼多多%23	sina.weibo	hotsearch;weibo	1	2023-11-30	拼多多
26398	拼多多2023年第四季度营收888.8亿元 	https://s.weibo.com/weibo?q=%23拼多多2023年第四季度营收888.8亿元 %23	sina.weibo	hotsearch;weibo	1	2024-03-20	拼多多2023年第四季度营收888.8亿元
26399	拼多多上的县长推荐 	https://s.weibo.com/weibo?q=%23拼多多上的县长推荐 %23	sina.weibo	hotsearch;weibo	1	2023-12-18	拼多多上的县长推荐
26400	拼多多人均创收1222万 	https://s.weibo.com/weibo?q=%23拼多多人均创收1222万 %23	sina.weibo	hotsearch;weibo	1	2023-11-30	拼多多人均创收1222万
26401	拼多多市值逼近阿里 	https://s.weibo.com/weibo?q=%23拼多多市值逼近阿里 %23	sina.weibo	hotsearch;weibo	1	2023-11-29	拼多多市值逼近阿里
26402	拼多多成中概股市值第一 	https://s.weibo.com/weibo?q=%23拼多多成中概股市值第一 %23	sina.weibo	hotsearch;weibo	1	2023-12-01	拼多多成中概股市值第一
26403	拼多多涨逾15% 	https://s.weibo.com/weibo?q=%23拼多多涨逾15% %23	sina.weibo	hotsearch;weibo	1	2024-03-20	拼多多涨逾15%
26404	拼多多版农业大摸底涨知识了 	https://s.weibo.com/weibo?q=%23拼多多版农业大摸底涨知识了 %23	sina.weibo	hotsearch;weibo	1	2024-01-16	拼多多版农业大摸底涨知识了
26405	拼多多美股市值超阿里 	https://s.weibo.com/weibo?q=%23拼多多美股市值超阿里 %23	sina.weibo	hotsearch;weibo	1	2023-11-30	拼多多美股市值超阿里
26406	推特崩了 	https://s.weibo.com/weibo?q=%23推特崩了 %23	sina.weibo	hotsearch;weibo	1	2023-12-21	推特崩了
26409	日本专家说小米汽车如同iPhone问世 	https://s.weibo.com/weibo?q=%23日本专家说小米汽车如同iPhone问世 %23	sina.weibo	hotsearch;weibo	2	2024-04-02	日本专家说小米汽车如同iPhone问世
26410	日本麦当劳也崩了 	https://s.weibo.com/weibo?q=%23日本麦当劳也崩了 %23	sina.weibo	hotsearch;weibo	1	2024-03-15	日本麦当劳也崩了
26411	时代少年团	https://s.weibo.com/weibo?q=%23时代少年团%23	sina.weibo	hotsearch;weibo	1	2024-02-01	时代少年团
26415	智界S7首发8大华为黑科技 	https://s.weibo.com/weibo?q=%23智界S7首发8大华为黑科技 %23	sina.weibo	hotsearch;weibo	1	2023-11-28	智界S7首发8大华为黑科技
26416	智联招聘崩了 	https://s.weibo.com/weibo?q=%23智联招聘崩了 %23	sina.weibo	hotsearch;weibo	1	2024-02-28	智联招聘崩了
26417	曝王者荣耀抖音直播禁令冰融 	https://s.weibo.com/weibo?q=%23曝王者荣耀抖音直播禁令冰融 %23	sina.weibo	hotsearch;weibo	1	2024-01-09	曝王者荣耀抖音直播禁令冰融
26418	有滴滴司机称8公里订单收费1540元 	https://s.weibo.com/weibo?q=%23有滴滴司机称8公里订单收费1540元 %23	sina.weibo	hotsearch;weibo	1	2023-11-28	有滴滴司机称8公里订单收费1540元
26419	杀妻谷歌工程师可能判死刑 	https://s.weibo.com/weibo?q=%23杀妻谷歌工程师可能判死刑 %23	sina.weibo	hotsearch;weibo	1	2024-01-23	杀妻谷歌工程师可能判死刑
26420	李国庆称排队等小米SU7 	https://s.weibo.com/weibo?q=%23李国庆称排队等小米SU7 %23	sina.weibo	hotsearch;weibo	1	2024-03-29	李国庆称排队等小米SU7
26421	李斌	https://s.weibo.com/weibo?q=%23李斌%23	sina.weibo	hotsearch;weibo	1	2024-03-28	李斌
26423	杜华为乐华年会策划cos局 	https://s.weibo.com/weibo?q=%23杜华为乐华年会策划cos局 %23	sina.weibo	hotsearch;weibo	1	2023-12-01	杜华为乐华年会策划cos局
26424	杜华为王一博发声 	https://s.weibo.com/weibo?q=%23杜华为王一博发声 %23	sina.weibo	hotsearch;weibo	1	2024-02-20	杜华为王一博发声
26425	极氪高管怼小米汽车 	https://s.weibo.com/weibo?q=%23极氪高管怼小米汽车 %23	sina.weibo	hotsearch;weibo	1	2024-02-28	极氪高管怼小米汽车
26426	汽车之家就泄密小米汽车内饰致歉 	https://s.weibo.com/weibo?q=%23汽车之家就泄密小米汽车内饰致歉 %23	sina.weibo	hotsearch;weibo	1	2024-03-21	汽车之家就泄密小米汽车内饰致歉
26427	沪上阿姨崩了 	https://s.weibo.com/weibo?q=%23沪上阿姨崩了 %23	sina.weibo	hotsearch;weibo	1	2024-03-20	沪上阿姨崩了
26428	海豚荣耀版	https://s.weibo.com/weibo?q=%23海豚荣耀版%23	sina.weibo	hotsearch;weibo	1	2024-02-23	海豚荣耀版
26429	消费者称遭遇小米汽车误锁单 	https://s.weibo.com/weibo?q=%23消费者称遭遇小米汽车误锁单 %23	sina.weibo	hotsearch;weibo	1	2024-03-29	消费者称遭遇小米汽车误锁单
26430	滴滴再次就服务异常致歉 	https://s.weibo.com/weibo?q=%23滴滴再次就服务异常致歉 %23	sina.weibo	hotsearch;weibo	1	2023-11-28	滴滴再次就服务异常致歉
26432	滴滴回应司机提现 	https://s.weibo.com/weibo?q=%23滴滴回应司机提现 %23	sina.weibo	hotsearch;weibo	1	2023-11-28	滴滴回应司机提现
26433	滴滴崩了 	https://s.weibo.com/weibo?q=%23滴滴崩了 %23	sina.weibo	hotsearch;weibo	1	2023-11-28	滴滴崩了
26434	滴滴崩了后有司机后台收入690亿 	https://s.weibo.com/weibo?q=%23滴滴崩了后有司机后台收入690亿 %23	sina.weibo	hotsearch;weibo	1	2023-11-28	滴滴崩了后有司机后台收入690亿
26435	滴滴打车	https://s.weibo.com/weibo?q=%23滴滴打车%23	sina.weibo	hotsearch;weibo	1	2023-11-28	滴滴打车
26436	滴滴派发补偿券 	https://s.weibo.com/weibo?q=%23滴滴派发补偿券 %23	sina.weibo	hotsearch;weibo	1	2023-11-29	滴滴派发补偿券
26437	滴滴称事故非网传遭受攻击 	https://s.weibo.com/weibo?q=%23滴滴称事故非网传遭受攻击 %23	sina.weibo	hotsearch;weibo	1	2023-11-29	滴滴称事故非网传遭受攻击
26438	滴滴系统崩溃其他平台爆单 	https://s.weibo.com/weibo?q=%23滴滴系统崩溃其他平台爆单 %23	sina.weibo	hotsearch;weibo	1	2023-11-28	滴滴系统崩溃其他平台爆单
26439	滴滴系统崩溃预计损失超4亿 	https://s.weibo.com/weibo?q=%23滴滴系统崩溃预计损失超4亿 %23	sina.weibo	hotsearch;weibo	1	2023-11-28	滴滴系统崩溃预计损失超4亿
26440	滴滴网约车等服务已恢复 	https://s.weibo.com/weibo?q=%23滴滴网约车等服务已恢复 %23	sina.weibo	hotsearch;weibo	1	2023-11-28	滴滴网约车等服务已恢复
26441	滴滴致歉补偿券领不了 	https://s.weibo.com/weibo?q=%23滴滴致歉补偿券领不了 %23	sina.weibo	hotsearch;weibo	1	2023-11-29	滴滴致歉补偿券领不了
26443	滴滴辟谣司机后台收入690亿 	https://s.weibo.com/weibo?q=%23滴滴辟谣司机后台收入690亿 %23	sina.weibo	hotsearch;weibo	1	2023-11-28	滴滴辟谣司机后台收入690亿
26444	烟火人家	https://s.weibo.com/weibo?q=%23烟火人家%23	sina.weibo	hotsearch;weibo	1	2024-02-28	烟火人家
26445	特斯拉 	https://s.weibo.com/weibo?q=%23特斯拉 %23	sina.weibo	hotsearch;weibo	1	2024-03-28	特斯拉
26446	特斯拉1月在韩国仅卖出1辆车 	https://s.weibo.com/weibo?q=%23特斯拉1月在韩国仅卖出1辆车 %23	sina.weibo	hotsearch;weibo	1	2024-02-07	特斯拉1月在韩国仅卖出1辆车
26447	特斯拉2023年交付量达181万辆 	https://s.weibo.com/weibo?q=%23特斯拉2023年交付量达181万辆 %23	sina.weibo	hotsearch;weibo	1	2024-01-02	特斯拉2023年交付量达181万辆
26448	特斯拉3个月降价3次 	https://s.weibo.com/weibo?q=%23特斯拉3个月降价3次 %23	sina.weibo	hotsearch;weibo	1	2024-03-01	特斯拉3个月降价3次
26449	特斯拉ModelY推出升级款 	https://s.weibo.com/weibo?q=%23特斯拉ModelY推出升级款 %23	sina.weibo	hotsearch;weibo	1	2024-02-01	特斯拉ModelY推出升级款
26450	特斯拉下线第600万辆汽车 	https://s.weibo.com/weibo?q=%23特斯拉下线第600万辆汽车 %23	sina.weibo	hotsearch;weibo	1	2024-03-30	特斯拉下线第600万辆汽车
26451	特斯拉中国今日涨价 	https://s.weibo.com/weibo?q=%23特斯拉中国今日涨价 %23	sina.weibo	hotsearch;weibo	1	2024-04-01	特斯拉中国今日涨价
26452	特斯拉交付首批电动皮卡 	https://s.weibo.com/weibo?q=%23特斯拉交付首批电动皮卡 %23	sina.weibo	hotsearch;weibo	1	2023-12-01	特斯拉交付首批电动皮卡
26454	特斯拉全美工厂工人涨薪 	https://s.weibo.com/weibo?q=%23特斯拉全美工厂工人涨薪 %23	sina.weibo	hotsearch;weibo	1	2024-01-12	特斯拉全美工厂工人涨薪
26455	特斯拉召回超160万辆车 	https://s.weibo.com/weibo?q=%23特斯拉召回超160万辆车 %23	sina.weibo	hotsearch;weibo	1	2024-01-05	特斯拉召回超160万辆车
26456	特斯拉四季度利润大跌40% 	https://s.weibo.com/weibo?q=%23特斯拉四季度利润大跌40% %23	sina.weibo	hotsearch;weibo	1	2024-01-25	特斯拉四季度利润大跌40%
26457	特斯拉回应Cybertruck淋雨后生锈 	https://s.weibo.com/weibo?q=%23特斯拉回应Cybertruck淋雨后生锈 %23	sina.weibo	hotsearch;weibo	1	2024-02-18	特斯拉回应Cybertruck淋雨后生锈
26458	特斯拉回应成都连撞11车事故 	https://s.weibo.com/weibo?q=%23特斯拉回应成都连撞11车事故 %23	sina.weibo	hotsearch;weibo	1	2023-11-27	特斯拉回应成都连撞11车事故
26459	特斯拉国产ModelY将涨价5000元 	https://s.weibo.com/weibo?q=%23特斯拉国产ModelY将涨价5000元 %23	sina.weibo	hotsearch;weibo	1	2024-03-20	特斯拉国产ModelY将涨价5000元
26460	特斯拉失控撞山致5人受伤 	https://s.weibo.com/weibo?q=%23特斯拉失控撞山致5人受伤 %23	sina.weibo	hotsearch;weibo	1	2023-12-26	特斯拉失控撞山致5人受伤
26461	特斯拉官方暗讽理想汽车 	https://s.weibo.com/weibo?q=%23特斯拉官方暗讽理想汽车 %23	sina.weibo	hotsearch;weibo	1	2023-12-29	特斯拉官方暗讽理想汽车
26463	特斯拉市值2天蒸发超3400亿元 	https://s.weibo.com/weibo?q=%23特斯拉市值2天蒸发超3400亿元 %23	sina.weibo	hotsearch;weibo	1	2024-03-15	特斯拉市值2天蒸发超3400亿元
26465	特斯拉市值一夜涨超2364亿 	https://s.weibo.com/weibo?q=%23特斯拉市值一夜涨超2364亿 %23	sina.weibo	hotsearch;weibo	1	2024-03-19	特斯拉市值一夜涨超2364亿
26466	特斯拉市值一夜蒸发1847亿 	https://s.weibo.com/weibo?q=%23特斯拉市值一夜蒸发1847亿 %23	sina.weibo	hotsearch;weibo	1	2024-03-15	特斯拉市值一夜蒸发1847亿
26467	特斯拉成新任贬值之王 	https://s.weibo.com/weibo?q=%23特斯拉成新任贬值之王 %23	sina.weibo	hotsearch;weibo	1	2024-03-14	特斯拉成新任贬值之王
26468	特斯拉机器人暴起伤人 	https://s.weibo.com/weibo?q=%23特斯拉机器人暴起伤人 %23	sina.weibo	hotsearch;weibo	1	2023-12-28	特斯拉机器人暴起伤人
26469	特斯拉涨价 	https://s.weibo.com/weibo?q=%23特斯拉涨价 %23	sina.weibo	hotsearch;weibo	1	2024-03-20	特斯拉涨价
26470	特斯拉瞒报工厂机器人袭击工人次数 	https://s.weibo.com/weibo?q=%23特斯拉瞒报工厂机器人袭击工人次数 %23	sina.weibo	hotsearch;weibo	1	2023-12-27	特斯拉瞒报工厂机器人袭击工人次数
26472	特斯拉股价大跌7.16% 	https://s.weibo.com/weibo?q=%23特斯拉股价大跌7.16% %23	sina.weibo	hotsearch;weibo	1	2024-03-05	特斯拉股价大跌7.16%
26473	特斯拉股价大跌超12% 	https://s.weibo.com/weibo?q=%23特斯拉股价大跌超12% %23	sina.weibo	hotsearch;weibo	1	2024-01-26	特斯拉股价大跌超12%
28720	Ray OS 2.6.3 Command Injection	https://packetstormsecurity.com/files/178034/rayos263-exec.txt	packetstorm	vuln;;	1	2024-04-12	Ray OS 2.6.3 指令注射
26475	特斯拉降价 	https://s.weibo.com/weibo?q=%23特斯拉降价 %23	sina.weibo	hotsearch;weibo	1	2024-01-12	特斯拉降价
26476	特斯拉降价无人在意 	https://s.weibo.com/weibo?q=%23特斯拉降价无人在意 %23	sina.weibo	hotsearch;weibo	1	2024-03-04	特斯拉降价无人在意
26477	特斯拉首席内饰设计师跳槽 	https://s.weibo.com/weibo?q=%23特斯拉首席内饰设计师跳槽 %23	sina.weibo	hotsearch;weibo	1	2024-02-29	特斯拉首席内饰设计师跳槽
26478	猎冰	https://s.weibo.com/weibo?q=%23猎冰%23	sina.weibo	hotsearch;weibo	1	2024-02-23	猎冰
26480	王一博现身小米园区 	https://s.weibo.com/weibo?q=%23王一博现身小米园区 %23	sina.weibo	hotsearch;weibo	1	2023-11-29	王一博现身小米园区
26481	王者荣耀 	https://s.weibo.com/weibo?q=%23王者荣耀 %23	sina.weibo	hotsearch;weibo	1	2023-11-30	王者荣耀
26483	王者荣耀上央视了 	https://s.weibo.com/weibo?q=%23王者荣耀上央视了 %23	sina.weibo	hotsearch;weibo	1	2024-01-02	王者荣耀上央视了
26484	王者荣耀云梦有灵CG 	https://s.weibo.com/weibo?q=%23王者荣耀云梦有灵CG %23	sina.weibo	hotsearch;weibo	1	2024-01-05	王者荣耀云梦有灵CG
26485	王者荣耀全新分路段位系统 	https://s.weibo.com/weibo?q=%23王者荣耀全新分路段位系统 %23	sina.weibo	hotsearch;weibo	1	2024-03-25	王者荣耀全新分路段位系统
26486	王者荣耀全明星赛直播 	https://s.weibo.com/weibo?q=%23王者荣耀全明星赛直播 %23	sina.weibo	hotsearch;weibo	1	2024-02-26	王者荣耀全明星赛直播
26487	王者荣耀刘慈欣平行世界 	https://s.weibo.com/weibo?q=%23王者荣耀刘慈欣平行世界 %23	sina.weibo	hotsearch;weibo	1	2024-01-22	王者荣耀刘慈欣平行世界
26489	王者荣耀大司命 	https://s.weibo.com/weibo?q=%23王者荣耀大司命 %23	sina.weibo	hotsearch;weibo	1	2024-03-21	王者荣耀大司命
26490	王者荣耀妲己	https://s.weibo.com/weibo?q=%23王者荣耀妲己%23	sina.weibo	hotsearch;weibo	1	2024-04-01	王者荣耀妲己
26491	王者荣耀孙尚香新皮肤 	https://s.weibo.com/weibo?q=%23王者荣耀孙尚香新皮肤 %23	sina.weibo	hotsearch;weibo	1	2024-02-04	王者荣耀孙尚香新皮肤
26492	王者荣耀小乔 	https://s.weibo.com/weibo?q=%23王者荣耀小乔 %23	sina.weibo	hotsearch;weibo	1	2024-02-06	王者荣耀小乔
26493	王者荣耀新赛季 	https://s.weibo.com/weibo?q=%23王者荣耀新赛季 %23	sina.weibo	hotsearch;weibo	1	2024-03-26	王者荣耀新赛季
26495	王者荣耀时代少年团直播官宣 	https://s.weibo.com/weibo?q=%23王者荣耀时代少年团直播官宣 %23	sina.weibo	hotsearch;weibo	1	2024-02-05	王者荣耀时代少年团直播官宣
26496	王者荣耀最佳天菜舞蹈挑战 	https://s.weibo.com/weibo?q=%23王者荣耀最佳天菜舞蹈挑战 %23	sina.weibo	hotsearch;weibo	1	2024-03-01	王者荣耀最佳天菜舞蹈挑战
26497	王者荣耀梅西皮肤 	https://s.weibo.com/weibo?q=%23王者荣耀梅西皮肤 %23	sina.weibo	hotsearch;weibo	1	2024-02-08	王者荣耀梅西皮肤
26498	王者荣耀灵宝市集 	https://s.weibo.com/weibo?q=%23王者荣耀灵宝市集 %23	sina.weibo	hotsearch;weibo	1	2024-02-07	王者荣耀灵宝市集
26499	王者荣耀爆改地铁 	https://s.weibo.com/weibo?q=%23王者荣耀爆改地铁 %23	sina.weibo	hotsearch;weibo	1	2024-02-04	王者荣耀爆改地铁
26500	王者荣耀版沈璃上线 	https://s.weibo.com/weibo?q=%23王者荣耀版沈璃上线 %23	sina.weibo	hotsearch;weibo	1	2024-03-27	王者荣耀版沈璃上线
26501	王者荣耀皮肤雨 	https://s.weibo.com/weibo?q=%23王者荣耀皮肤雨 %23	sina.weibo	hotsearch;weibo	1	2024-02-06	王者荣耀皮肤雨
26502	王者荣耀维护 	https://s.weibo.com/weibo?q=%23王者荣耀维护 %23	sina.weibo	hotsearch;weibo	1	2023-12-28	王者荣耀维护
26503	王者荣耀貂蝉 	https://s.weibo.com/weibo?q=%23王者荣耀貂蝉 %23	sina.weibo	hotsearch;weibo	1	2024-02-06	王者荣耀貂蝉
26505	王者荣耀限时点券 	https://s.weibo.com/weibo?q=%23王者荣耀限时点券 %23	sina.weibo	hotsearch;weibo	1	2024-02-07	王者荣耀限时点券
26507	王者荣耀龙年珍藏英雄 	https://s.weibo.com/weibo?q=%23王者荣耀龙年珍藏英雄 %23	sina.weibo	hotsearch;weibo	1	2024-01-30	王者荣耀龙年珍藏英雄
26508	王者荣耀龙限皮肤 	https://s.weibo.com/weibo?q=%23王者荣耀龙限皮肤 %23	sina.weibo	hotsearch;weibo	1	2024-02-04	王者荣耀龙限皮肤
26509	疑阿里被献血女子丈夫求助帖曝光 	https://s.weibo.com/weibo?q=%23疑阿里被献血女子丈夫求助帖曝光 %23	sina.weibo	hotsearch;weibo	1	2023-12-01	疑阿里被献血女子丈夫求助帖曝光
26510	百度	https://s.weibo.com/weibo?q=%23百度%23	sina.weibo	hotsearch;weibo	1	2024-01-29	百度
26511	百度地图	https://s.weibo.com/weibo?q=%23百度地图%23	sina.weibo	hotsearch;weibo	1	2024-03-20	百度地图
26512	百度宣布终止收购YY直播 	https://s.weibo.com/weibo?q=%23百度宣布终止收购YY直播 %23	sina.weibo	hotsearch;weibo	1	2024-01-02	百度宣布终止收购YY直播
26514	眼泪女王	https://s.weibo.com/weibo?q=%23眼泪女王%23	sina.weibo	hotsearch;weibo	1	2024-03-26	眼泪女王
26515	知网崩了 	https://s.weibo.com/weibo?q=%23知网崩了 %23	sina.weibo	hotsearch;weibo	1	2024-03-04	知网崩了
26516	童漠男人设崩了 	https://s.weibo.com/weibo?q=%23童漠男人设崩了 %23	sina.weibo	hotsearch;weibo	1	2024-01-02	童漠男人设崩了
26517	米哈游官宣启动鸿蒙原生应用开发 	https://s.weibo.com/weibo?q=%23米哈游官宣启动鸿蒙原生应用开发 %23	sina.weibo	hotsearch;weibo	1	2023-12-18	米哈游官宣启动鸿蒙原生应用开发
26518	米家崩了 	https://s.weibo.com/weibo?q=%23米家崩了 %23	sina.weibo	hotsearch;weibo	1	2024-02-21	米家崩了
26519	米粉期望小米汽车30万左右 	https://s.weibo.com/weibo?q=%23米粉期望小米汽车30万左右 %23	sina.weibo	hotsearch;weibo	1	2023-12-29	米粉期望小米汽车30万左右
26520	红腹锦鸡优雅人设崩了 	https://s.weibo.com/weibo?q=%23红腹锦鸡优雅人设崩了 %23	sina.weibo	hotsearch;weibo	1	2024-01-29	红腹锦鸡优雅人设崩了
26521	网传西藏阿里全体公务员为一女子献血 	https://s.weibo.com/weibo?q=%23网传西藏阿里全体公务员为一女子献血 %23	sina.weibo	hotsearch;weibo	1	2023-11-29	网传西藏阿里全体公务员为一女子献血
26522	网易云音乐崩了 	https://s.weibo.com/weibo?q=%23网易云音乐崩了 %23	sina.weibo	hotsearch;weibo	1	2024-03-14	网易云音乐崩了
26524	罗永浩指责荣耀任意门抄袭锤子 	https://s.weibo.com/weibo?q=%23罗永浩指责荣耀任意门抄袭锤子 %23	sina.weibo	hotsearch;weibo	1	2024-01-11	罗永浩指责荣耀任意门抄袭锤子
26526	罗永浩说小米威武 	https://s.weibo.com/weibo?q=%23罗永浩说小米威武 %23	sina.weibo	hotsearch;weibo	1	2024-03-29	罗永浩说小米威武
26527	美国金融大鳄回应比亚迪超特斯拉 	https://s.weibo.com/weibo?q=%23美国金融大鳄回应比亚迪超特斯拉 %23	sina.weibo	hotsearch;weibo	1	2024-02-01	美国金融大鳄回应比亚迪超特斯拉
26528	美法案要求字节165天内剥离TikTok 	https://s.weibo.com/weibo?q=%23美法案要求字节165天内剥离TikTok %23	sina.weibo	hotsearch;weibo	1	2024-03-06	美法案要求字节165天内剥离TikTok
26529	胡锡进称中华有为世界荣耀 	https://s.weibo.com/weibo?q=%23胡锡进称中华有为世界荣耀 %23	sina.weibo	hotsearch;weibo	1	2023-11-28	胡锡进称中华有为世界荣耀
26530	胡锡进称小米汽车应该被鼓励和认可 	https://s.weibo.com/weibo?q=%23胡锡进称小米汽车应该被鼓励和认可 %23	sina.weibo	hotsearch;weibo	1	2024-01-09	胡锡进称小米汽车应该被鼓励和认可
26531	腾讯云崩了 	https://s.weibo.com/weibo?q=%23腾讯云崩了 %23	sina.weibo	hotsearch;weibo	1	2024-04-08	腾讯云崩了
26532	腾讯小米为员工发开工红包 	https://s.weibo.com/weibo?q=%23腾讯小米为员工发开工红包 %23	sina.weibo	hotsearch;weibo	1	2024-02-18	腾讯小米为员工发开工红包
26533	腾讯市值跌没了一个小米 	https://s.weibo.com/weibo?q=%23腾讯市值跌没了一个小米 %23	sina.weibo	hotsearch;weibo	1	2023-12-23	腾讯市值跌没了一个小米
26534	腾讯接手字节跳动部分游戏业务 	https://s.weibo.com/weibo?q=%23腾讯接手字节跳动部分游戏业务 %23	sina.weibo	hotsearch;weibo	1	2024-03-14	腾讯接手字节跳动部分游戏业务
26535	花呗送特斯拉车主1000度电 	https://s.weibo.com/weibo?q=%23花呗送特斯拉车主1000度电 %23	sina.weibo	hotsearch;weibo	1	2024-01-19	花呗送特斯拉车主1000度电
26536	苹果拟将谷歌Gemini植入iPhone 	https://s.weibo.com/weibo?q=%23苹果拟将谷歌Gemini植入iPhone %23	sina.weibo	hotsearch;weibo	2	2024-03-18	苹果拟将谷歌Gemini植入iPhone
26538	荣耀2023全年国产手机第一 	https://s.weibo.com/weibo?q=%23荣耀2023全年国产手机第一 %23	sina.weibo	hotsearch;weibo	1	2024-01-25	荣耀2023全年国产手机第一
26539	荣耀Magic6 	https://s.weibo.com/weibo?q=%23荣耀Magic6 %23	sina.weibo	hotsearch;weibo	1	2024-01-08	荣耀Magic6
26540	荣耀Magic6动动嘴就能剪视频 	https://s.weibo.com/weibo?q=%23荣耀Magic6动动嘴就能剪视频 %23	sina.weibo	hotsearch;weibo	1	2024-01-04	荣耀Magic6动动嘴就能剪视频
26541	荣耀magic6价格 	https://s.weibo.com/weibo?q=%23荣耀magic6价格 %23	sina.weibo	hotsearch;weibo	1	2024-01-11	荣耀magic6价格
26542	荣耀保时捷 	https://s.weibo.com/weibo?q=%23荣耀保时捷 %23	sina.weibo	hotsearch;weibo	1	2024-01-11	荣耀保时捷
26543	荣耀保时捷要联合造车了吗 	https://s.weibo.com/weibo?q=%23荣耀保时捷要联合造车了吗 %23	sina.weibo	hotsearch;weibo	1	2023-12-12	荣耀保时捷要联合造车了吗
26544	荣耀保时捷设计官宣合作 	https://s.weibo.com/weibo?q=%23荣耀保时捷设计官宣合作 %23	sina.weibo	hotsearch;weibo	1	2023-12-14	荣耀保时捷设计官宣合作
26545	荣耀发布会 	https://s.weibo.com/weibo?q=%23荣耀发布会 %23	sina.weibo	hotsearch;weibo	1	2024-01-10	荣耀发布会
26546	荣耀发布首款保时捷设计折叠屏 	https://s.weibo.com/weibo?q=%23荣耀发布首款保时捷设计折叠屏 %23	sina.weibo	hotsearch;weibo	1	2024-01-11	荣耀发布首款保时捷设计折叠屏
26548	荣耀接棒华为海外市场高速增长 	https://s.weibo.com/weibo?q=%23荣耀接棒华为海外市场高速增长 %23	sina.weibo	hotsearch;weibo	1	2023-11-28	荣耀接棒华为海外市场高速增长
26550	荣耀杯S7 	https://s.weibo.com/weibo?q=%23荣耀杯S7 %23	sina.weibo	hotsearch;weibo	1	2024-01-27	荣耀杯S7
26551	荣耀笔记本 	https://s.weibo.com/weibo?q=%23荣耀笔记本 %23	sina.weibo	hotsearch;weibo	1	2024-03-18	荣耀笔记本
26552	荣耀首发1.8亿像素潜望长焦 	https://s.weibo.com/weibo?q=%23荣耀首发1.8亿像素潜望长焦 %23	sina.weibo	hotsearch;weibo	1	2024-01-11	荣耀首发1.8亿像素潜望长焦
26553	荣耀魔法OS的十大神奇功能 	https://s.weibo.com/weibo?q=%23荣耀魔法OS的十大神奇功能 %23	sina.weibo	hotsearch;weibo	1	2024-01-10	荣耀魔法OS的十大神奇功能
26554	萌娃叫不起爸爸大喊皇上驾崩了 	https://s.weibo.com/weibo?q=%23萌娃叫不起爸爸大喊皇上驾崩了 %23	sina.weibo	hotsearch;weibo	1	2024-01-18	萌娃叫不起爸爸大喊皇上驾崩了
26555	董宇辉带货华为 	https://s.weibo.com/weibo?q=%23董宇辉带货华为 %23	sina.weibo	hotsearch;weibo	1	2024-03-11	董宇辉带货华为
26556	西北工业大学校园应用启动鸿蒙化 	https://s.weibo.com/weibo?q=%23西北工业大学校园应用启动鸿蒙化 %23	sina.weibo	hotsearch;weibo	1	2024-03-21	西北工业大学校园应用启动鸿蒙化
26557	西藏阿里已对献血事件进行复查 	https://s.weibo.com/weibo?q=%23西藏阿里已对献血事件进行复查 %23	sina.weibo	hotsearch;weibo	1	2023-11-30	西藏阿里已对献血事件进行复查
26559	谷歌Gemini 	https://s.weibo.com/weibo?q=%23谷歌Gemini %23	sina.weibo	hotsearch;weibo	1	2023-12-07	谷歌Gemini
26561	谷歌中国籍工程师承认殴打妻子致死 	https://s.weibo.com/weibo?q=%23谷歌中国籍工程师承认殴打妻子致死 %23	sina.weibo	hotsearch;weibo	1	2024-01-23	谷歌中国籍工程师承认殴打妻子致死
26562	谷歌工程师杀妻悲剧发生之前 	https://s.weibo.com/weibo?q=%23谷歌工程师杀妻悲剧发生之前 %23	sina.weibo	hotsearch;weibo	1	2024-01-30	谷歌工程师杀妻悲剧发生之前
26563	谷歌工程师杀妻案嫌犯家人已回国 	https://s.weibo.com/weibo?q=%23谷歌工程师杀妻案嫌犯家人已回国 %23	sina.weibo	hotsearch;weibo	1	2024-02-07	谷歌工程师杀妻案嫌犯家人已回国
26564	豆瓣崩了 	https://s.weibo.com/weibo?q=%23豆瓣崩了 %23	sina.weibo	hotsearch;weibo	1	2023-12-06	豆瓣崩了
26565	贾跃亭点评小米汽车 	https://s.weibo.com/weibo?q=%23贾跃亭点评小米汽车 %23	sina.weibo	hotsearch;weibo	1	2024-04-01	贾跃亭点评小米汽车
26566	赵明称现在荣耀账户上有很多钱 	https://s.weibo.com/weibo?q=%23赵明称现在荣耀账户上有很多钱 %23	sina.weibo	hotsearch;weibo	1	2024-01-10	赵明称现在荣耀账户上有很多钱
26573	门店回应买保时捷送小米SU7 	https://s.weibo.com/weibo?q=%23门店回应买保时捷送小米SU7 %23	sina.weibo	hotsearch;weibo	1	2024-04-01	门店回应买保时捷送小米SU7
26574	问界M9首搭华为最强ARHUD 	https://s.weibo.com/weibo?q=%23问界M9首搭华为最强ARHUD %23	sina.weibo	hotsearch;weibo	1	2023-12-26	问界M9首搭华为最强ARHUD
26576	阴阳师	https://s.weibo.com/weibo?q=%23阴阳师%23	sina.weibo	hotsearch;weibo	1	2024-03-21	阴阳师
26577	阿维塔3亿送华为智驾 	https://s.weibo.com/weibo?q=%23阿维塔3亿送华为智驾 %23	sina.weibo	hotsearch;weibo	1	2024-03-30	阿维塔3亿送华为智驾
26578	阿里37.5亿美元收购菜鸟剩余股权 	https://s.weibo.com/weibo?q=%23阿里37.5亿美元收购菜鸟剩余股权 %23	sina.weibo	hotsearch;weibo	1	2024-03-26	阿里37.5亿美元收购菜鸟剩余股权
26579	阿里AI将接入各类安卓手机 	https://s.weibo.com/weibo?q=%23阿里AI将接入各类安卓手机 %23	sina.weibo	hotsearch;weibo	1	2024-03-28	阿里AI将接入各类安卓手机
26580	阿里CEO吴泳铭兼任淘天集团CEO 	https://s.weibo.com/weibo?q=%23阿里CEO吴泳铭兼任淘天集团CEO %23	sina.weibo	hotsearch;weibo	1	2023-12-20	阿里CEO吴泳铭兼任淘天集团CEO
26581	阿里云全线降价20% 	https://s.weibo.com/weibo?q=%23阿里云全线降价20% %23	sina.weibo	hotsearch;weibo	1	2024-02-29	阿里云全线降价20%
26582	阿里公务员 	https://s.weibo.com/weibo?q=%23阿里公务员 %23	sina.weibo	hotsearch;weibo	1	2023-11-29	阿里公务员
26583	阿里大文娱50亿投入港艺振兴计划 	https://s.weibo.com/weibo?q=%23阿里大文娱50亿投入港艺振兴计划 %23	sina.weibo	hotsearch;weibo	1	2024-03-11	阿里大文娱50亿投入港艺振兴计划
26584	阿里巴巴再回应出售饿了么传闻 	https://s.weibo.com/weibo?q=%23阿里巴巴再回应出售饿了么传闻 %23	sina.weibo	hotsearch;weibo	1	2024-02-08	阿里巴巴再回应出售饿了么传闻
26586	阿里巴巴大涨超7% 	https://s.weibo.com/weibo?q=%23阿里巴巴大涨超7% %23	sina.weibo	hotsearch;weibo	1	2024-01-24	阿里巴巴大涨超7%
26587	阿里巴巴第三财季营收2603.5亿元 	https://s.weibo.com/weibo?q=%23阿里巴巴第三财季营收2603.5亿元 %23	sina.weibo	hotsearch;weibo	1	2024-02-07	阿里巴巴第三财季营收2603.5亿元
26588	阿里市值重回电商一哥 	https://s.weibo.com/weibo?q=%23阿里市值重回电商一哥 %23	sina.weibo	hotsearch;weibo	1	2023-11-30	阿里市值重回电商一哥
26589	阿里控股电商公司裁员20% 	https://s.weibo.com/weibo?q=%23阿里控股电商公司裁员20% %23	sina.weibo	hotsearch;weibo	1	2024-01-10	阿里控股电商公司裁员20%
26590	阿里献血 	https://s.weibo.com/weibo?q=%23阿里献血 %23	sina.weibo	hotsearch;weibo	1	2023-11-30	阿里献血
26591	阿里献血事件小姑姑系退休工人 	https://s.weibo.com/weibo?q=%23阿里献血事件小姑姑系退休工人 %23	sina.weibo	hotsearch;weibo	1	2023-12-06	阿里献血事件小姑姑系退休工人
26592	阿里网络退出多家A股公司 	https://s.weibo.com/weibo?q=%23阿里网络退出多家A股公司 %23	sina.weibo	hotsearch;weibo	1	2023-12-04	阿里网络退出多家A股公司
26593	阿里达摩院裁撤量子实验室 	https://s.weibo.com/weibo?q=%23阿里达摩院裁撤量子实验室 %23	sina.weibo	hotsearch;weibo	1	2023-11-28	阿里达摩院裁撤量子实验室
26594	陈震再回应小米SU7测评争议 	https://s.weibo.com/weibo?q=%23陈震再回应小米SU7测评争议 %23	sina.weibo	hotsearch;weibo	1	2024-04-02	陈震再回应小米SU7测评争议
26595	陈震回应小米SU7测评争议 	https://s.weibo.com/weibo?q=%23陈震回应小米SU7测评争议 %23	sina.weibo	hotsearch;weibo	1	2024-03-30	陈震回应小米SU7测评争议
26596	陈震小米SU7测评 	https://s.weibo.com/weibo?q=%23陈震小米SU7测评 %23	sina.weibo	hotsearch;weibo	1	2024-03-29	陈震小米SU7测评
26597	雷军	https://s.weibo.com/weibo?q=%23雷军%23	sina.weibo	hotsearch;weibo	1	2023-12-25	雷军
26599	雷军回应对标特斯拉保时捷 	https://s.weibo.com/weibo?q=%23雷军回应对标特斯拉保时捷 %23	sina.weibo	hotsearch;weibo	1	2024-03-27	雷军回应对标特斯拉保时捷
26600	雷军回应小米为什么造车快 	https://s.weibo.com/weibo?q=%23雷军回应小米为什么造车快 %23	sina.weibo	hotsearch;weibo	1	2024-04-07	雷军回应小米为什么造车快
26601	雷军回应小米汽车多个传闻 	https://s.weibo.com/weibo?q=%23雷军回应小米汽车多个传闻 %23	sina.weibo	hotsearch;weibo	1	2024-03-14	雷军回应小米汽车多个传闻
26602	雷军回应小米汽车定价 	https://s.weibo.com/weibo?q=%23雷军回应小米汽车定价 %23	sina.weibo	hotsearch;weibo	1	2023-12-26	雷军回应小米汽车定价
26603	雷军回应小米造车慢 	https://s.weibo.com/weibo?q=%23雷军回应小米造车慢 %23	sina.weibo	hotsearch;weibo	1	2023-12-25	雷军回应小米造车慢
26604	雷军回应拦截小米SU7部分异常订单 	https://s.weibo.com/weibo?q=%23雷军回应拦截小米SU7部分异常订单 %23	sina.weibo	hotsearch;weibo	1	2024-04-01	雷军回应拦截小米SU7部分异常订单
26605	雷军奖励王腾小米su7 	https://s.weibo.com/weibo?q=%23雷军奖励王腾小米su7 %23	sina.weibo	hotsearch;weibo	1	2024-04-07	雷军奖励王腾小米su7
26607	雷军宣布小米SU7锁单量超4万 	https://s.weibo.com/weibo?q=%23雷军宣布小米SU7锁单量超4万 %23	sina.weibo	hotsearch;weibo	1	2024-04-03	雷军宣布小米SU7锁单量超4万
26608	雷军想让苹果用户也开小米汽车 	https://s.weibo.com/weibo?q=%23雷军想让苹果用户也开小米汽车 %23	sina.weibo	hotsearch;weibo	1	2023-12-28	雷军想让苹果用户也开小米汽车
26609	雷军担心小米汽车都不买更怕都来买 	https://s.weibo.com/weibo?q=%23雷军担心小米汽车都不买更怕都来买 %23	sina.weibo	hotsearch;weibo	1	2023-12-25	雷军担心小米汽车都不买更怕都来买
26610	雷军敲定小米定价只用了1小时 	https://s.weibo.com/weibo?q=%23雷军敲定小米定价只用了1小时 %23	sina.weibo	hotsearch;weibo	1	2024-03-29	雷军敲定小米定价只用了1小时
26612	雷军称将举办小米SU7首批交付仪式 	https://s.weibo.com/weibo?q=%23雷军称将举办小米SU7首批交付仪式 %23	sina.weibo	hotsearch;weibo	1	2024-04-02	雷军称将举办小米SU7首批交付仪式
26613	雷军称小米SU7肯定亏了 	https://s.weibo.com/weibo?q=%23雷军称小米SU7肯定亏了 %23	sina.weibo	hotsearch;weibo	1	2024-03-29	雷军称小米SU7肯定亏了
102	Delinea Debuts Privilege Control for Servers: Thwarting Stolen Credentials and Lateral Movement	https://www.darkreading.com/cyberattacks-data-breaches/delinea-debuts-privilege-control-for-servers-thwarting-stolen-credentials-and-lateral-movement	darkreading	news;	1	2024-03-05	服务器的 Delinea Debuts Privilge Privilge 控制:窃取被盗证书和横向移动
1457	Red Hat Security Advisory 2024-1241-03	https://packetstormsecurity.com/files/177532/RHSA-2024-1241-03.txt	packetstorm	vuln;;	1	2024-03-12	红色帽子安保咨询 2024-1241-03
181	How advances in AI are impacting business cybersecurity	https://www.helpnetsecurity.com/2024/03/12/interactive-ai-business-security/	helpnetsecurity	news;Don't miss;Expert analysis;Expert corner;Hot stuff;News;access control;artificial intelligence;cybersecurity;Forcepoint;opinion;policy;risk;	1	2024-03-12	AI 的进展如何影响企业网络安全
1539	Ethereum Is Making Itself Future Proof: What to Expect From the Ethereum Roadmap in 2024	https://buaq.net/go-227722.html	buaq	newscopy;	0	2024-03-13	Etheum是让自己成为未来的证据:从2024年Etheem路线图中期望什么?
1183	Tor’s new WebTunnel bridges mimic HTTPS traffic to evade censorship	https://www.bleepingcomputer.com/news/security/tors-new-webtunnel-bridges-mimic-https-traffic-to-evade-censorship/	bleepingcomputer	news;Security;	1	2024-03-12	Tor 新的WebTunnel桥模仿HTTPS的交通,以逃避审查
10029	Reinforcement learning is the path forward for AI integration into cybersecurity	https://www.helpnetsecurity.com/2024/03/26/ai-reinforcement-learning/	helpnetsecurity	news;Don't miss;Expert analysis;Expert corner;Hot stuff;News;artificial intelligence;CISO;cybersecurity;data;Groupe SEB;machine learning;opinion;predictions;SOC;	1	2024-03-26	强化学习是AI融入网络安全的道路
2653	Encina-Wastewater-Authority	http://www.ransomfeed.it/index.php?page=post_details&id_post=13720	ransomfeed	ransom;blackbyte;	1	2024-03-13	Encina-Wastewater-授权
10899	Cybercriminals play dirty: A look back at 10 cyber hits on the sporting world	https://www.welivesecurity.com/en/cybercrime/cybercriminals-play-dirty-10-cyber-hits-sporting-world/	eset	news;	1	2024-03-28	网络罪犯玩弄肮脏:回顾体育界的10次网络点击
26615	雷军称小米最恨品牌溢价 	https://s.weibo.com/weibo?q=%23雷军称小米最恨品牌溢价 %23	sina.weibo	hotsearch;weibo	1	2024-03-25	雷军称小米最恨品牌溢价
26616	雷军称小米正式成为一家车厂 	https://s.weibo.com/weibo?q=%23雷军称小米正式成为一家车厂 %23	sina.weibo	hotsearch;weibo	1	2024-04-03	雷军称小米正式成为一家车厂
26617	雷军称小米汽车有信心打开市场 	https://s.weibo.com/weibo?q=%23雷军称小米汽车有信心打开市场 %23	sina.weibo	hotsearch;weibo	1	2024-03-06	雷军称小米汽车有信心打开市场
26618	雷军称小米汽车要媲美保时捷特斯拉 	https://s.weibo.com/weibo?q=%23雷军称小米汽车要媲美保时捷特斯拉 %23	sina.weibo	hotsearch;weibo	1	2023-12-28	雷军称小米汽车要媲美保时捷特斯拉
26620	雷军称苹果用户买小米汽车是最好选择 	https://s.weibo.com/weibo?q=%23雷军称苹果用户买小米汽车是最好选择 %23	sina.weibo	hotsearch;weibo	1	2024-02-28	雷军称苹果用户买小米汽车是最好选择
26621	雷军给小米车主开车门 	https://s.weibo.com/weibo?q=%23雷军给小米车主开车门 %23	sina.weibo	hotsearch;weibo	1	2024-04-03	雷军给小米车主开车门
26622	雷军致敬车企仅华为未回应 	https://s.weibo.com/weibo?q=%23雷军致敬车企仅华为未回应 %23	sina.weibo	hotsearch;weibo	1	2023-12-29	雷军致敬车企仅华为未回应
26623	雷军说会开小米SU7上班 	https://s.weibo.com/weibo?q=%23雷军说会开小米SU7上班 %23	sina.weibo	hotsearch;weibo	1	2024-03-29	雷军说会开小米SU7上班
26625	雷军请网友帮小米汽车辟谣 	https://s.weibo.com/weibo?q=%23雷军请网友帮小米汽车辟谣 %23	sina.weibo	hotsearch;weibo	1	2024-01-03	雷军请网友帮小米汽车辟谣
26626	雷军谈小米汽车优势 	https://s.weibo.com/weibo?q=%23雷军谈小米汽车优势 %23	sina.weibo	hotsearch;weibo	1	2024-03-26	雷军谈小米汽车优势
26627	首批车主已经提到小米SU7 	https://s.weibo.com/weibo?q=%23首批车主已经提到小米SU7 %23	sina.weibo	hotsearch;weibo	1	2024-04-03	首批车主已经提到小米SU7
26628	马云内网回应拼多多市值逼近阿里 	https://s.weibo.com/weibo?q=%23马云内网回应拼多多市值逼近阿里 %23	sina.weibo	hotsearch;weibo	1	2023-11-29	马云内网回应拼多多市值逼近阿里
26630	马云成阿里最大单一股东 	https://s.weibo.com/weibo?q=%23马云成阿里最大单一股东 %23	sina.weibo	hotsearch;weibo	1	2024-01-24	马云成阿里最大单一股东
26632	马斯克回应特斯拉机器人伤人事件 	https://s.weibo.com/weibo?q=%23马斯克回应特斯拉机器人伤人事件 %23	sina.weibo	hotsearch;weibo	1	2023-12-28	马斯克回应特斯拉机器人伤人事件
26633	马斯克回应特斯拉美国市场份额超大众 	https://s.weibo.com/weibo?q=%23马斯克回应特斯拉美国市场份额超大众 %23	sina.weibo	hotsearch;weibo	1	2024-01-09	马斯克回应特斯拉美国市场份额超大众
26634	马斯克被曝与特斯拉董事一起吸毒 	https://s.weibo.com/weibo?q=%23马斯克被曝与特斯拉董事一起吸毒 %23	sina.weibo	hotsearch;weibo	1	2024-02-05	马斯克被曝与特斯拉董事一起吸毒
26635	高德打车崩了 	https://s.weibo.com/weibo?q=%23高德打车崩了 %23	sina.weibo	hotsearch;weibo	1	2024-01-29	高德打车崩了
26636	魅族CEO怼小米汽车 	https://s.weibo.com/weibo?q=%23魅族CEO怼小米汽车 %23	sina.weibo	hotsearch;weibo	1	2023-12-28	魅族CEO怼小米汽车
26637	魅族CEO沈子瑜质疑小米汽车审美 	https://s.weibo.com/weibo?q=%23魅族CEO沈子瑜质疑小米汽车审美 %23	sina.weibo	hotsearch;weibo	1	2023-12-29	魅族CEO沈子瑜质疑小米汽车审美
26638	魅族称要成为小米首位车主 	https://s.weibo.com/weibo?q=%23魅族称要成为小米首位车主 %23	sina.weibo	hotsearch;weibo	1	2023-12-28	魅族称要成为小米首位车主
26639	鸿蒙 	https://s.weibo.com/weibo?q=%23鸿蒙 %23	sina.weibo	hotsearch;weibo	1	2024-01-19	鸿蒙
26640	鸿蒙和MPV能整什么活 	https://s.weibo.com/weibo?q=%23鸿蒙和MPV能整什么活 %23	sina.weibo	hotsearch;weibo	1	2024-01-31	鸿蒙和MPV能整什么活
26643	麦当劳崩了 	https://s.weibo.com/weibo?q=%23麦当劳崩了 %23	sina.weibo	hotsearch;weibo	1	2024-01-24	麦当劳崩了
26644	黄景瑜我妈要百度你的电话 	https://s.weibo.com/weibo?q=%23黄景瑜我妈要百度你的电话 %23	sina.weibo	hotsearch;weibo	1	2024-03-27	黄景瑜我妈要百度你的电话
3614	Perception Point GPThreat Hunter allows cybersecurity experts to focus on in-depth investigations	https://www.helpnetsecurity.com/2024/03/14/perception-point-gpthreat-hunter/	helpnetsecurity	news;Industry news;Perception Point;	1	2024-03-14	GPThreat Hunter 感知点 GPThreat Hunter 让网络安全专家能够专注于深入调查
10128	Ransomware gang attacks the Big Issue, a street newspaper supporting the homeless	https://buaq.net/go-230669.html	buaq	newscopy;	0	2024-03-27	支持无家可归者的街头报纸《大问题》,
10415	17,000+ Microsoft Exchange Servers Vulnerable to Multiple Critical Vulnerabilities	https://gbhackers.com/microsoft-exchange-servers-vulnerable/	GBHacker	news;CVE/vulnerability;cyber security;Cyber Security News;Microsoft;Vulnerability;	1	2024-03-27	17 000+微软交换服务器
2538	JetBrains Says Rapid7’s Fast Release of Flaw Details Harmed Users	https://securityboulevard.com/2024/03/jetbrains-says-rapid7s-fast-release-of-flaw-details-harmed-users/	securityboulevard	news;Application Security;Cybersecurity;Data Security;DevOps;Featured;Network Security;News;Security Boulevard (Original);Social - Facebook;Social - LinkedIn;Social - X;Spotlight;Threat Intelligence;Vulnerabilities;coordinated vulnerability disclosure;JetBrains TeamCity;rapid7;security vulnerabilites;	1	2024-03-13	JeetBrains说快速7 快速释放Flaw详细信息受伤害用户
98	Silence Laboratories Raises $4.1M Funding to Enable Privacy Preserving Collaborative Computing	https://www.darkreading.com/cyber-risk/silence-laboratories-raises-4-1m-funding-to-enable-privacy-preserving-collaborative-computing	darkreading	news;	1	2024-03-07	静默实验室筹集了410万美元资金,以方便隐私保护协作计算
8418	A Critical Look at “Cyber security is a dark art”: The CISO as soothsayer	https://buaq.net/go-228872.html	buaq	newscopy;	0	2024-03-19	对“网络安全是一种黑暗的艺术”的批判性审视:CISO作为占卜者
10952	HTB Cyber Apocalypse CTF 2024 — Reversing	https://infosecwriteups.com/htb-cyber-apocalypse-ctf-2024-reversing-d9eb85c59ca9?source=rss----7b722bfd1b8d---4	infosecwriteups	tech;hackthebox;ctf-writeup;walkthrough;ctf;reverse-engineering;	1	2024-03-29	HTB 网络世界末日 CTF 2024 - 逆转
4620	Key MITRE ATT&CK techniques used by cyber attackers	https://www.helpnetsecurity.com/2024/03/15/2023-attck-techniques/	helpnetsecurity	news;News;attacks;cloud;credentials;cybersecurity;email;identity;ransomware;Red Canary;report;	1	2024-03-15	关键麻将ATT
10398	German cyber agency warns 17,000 Microsoft Exchange servers are vulnerable to critical bugs	https://therecord.media/germany-bsi-microsoft-exchange-vulnerability-warning	therecord	ransom;Cybercrime;News;News Briefs;Technology;	1	2024-03-27	德国网络机构警告17 000个微软交换服务器 易受重大虫虫的侵袭
17555	「决胜护网」指南：独家攻防技巧解密	https://www.freebuf.com/consult/397117.html	freebuf	news;咨询;	1	2024-04-07	「决胜护网」指南：独家攻防技巧解密
10469	Checkmarx Aligns With Wiz to Improve Application Security	https://securityboulevard.com/2024/03/checkmarx-aligns-with-wiz-to-improve-application-security/	securityboulevard	news;Analytics & Intelligence;Application Security;Cloud Security;Cybersecurity;Featured;Network Security;News;Security Boulevard (Original);Social - X;Spotlight;Threat Intelligence;Checkmarx;cloud workload protection;cnapp;Wiz;	1	2024-03-28	与 Wiz 的一勾镜对齐以提高应用程序安全性
10181	CISA tags Microsoft SharePoint RCE bug as actively exploited	https://www.bleepingcomputer.com/news/security/cisa-tags-microsoft-sharepoint-rce-bug-as-actively-exploited/	bleepingcomputer	news;Security;Microsoft;	1	2024-03-27	CISA 标记微软 SharePoint RCE 错误被积极开发
10185	Google: Spyware vendors behind 50% of zero-days exploited in 2023	https://www.bleepingcomputer.com/news/security/google-spyware-vendors-behind-50-percent-of-zero-days-exploited-in-2023/	bleepingcomputer	news;Security;Google;	1	2024-03-27	谷歌:Spyware供应商在2023年被剥削的零日的50%背后,
10422	INC Ransom stole 3TB of data from the National Health Service (NHS) of Scotland	https://buaq.net/go-230921.html	buaq	newscopy;	0	2024-03-28	INCRansom从苏格兰国家保健服务局(NHS)盗取了3TB的数据。
10400	Insurer unveils policy covering drivers from connected car hacks and data leaks	https://therecord.media/insurer-introduces-policy-covering-drivers-from-connected-car-hacks	therecord	ransom;Cybercrime;Industry;News;News Briefs;Technology;Privacy;	1	2024-03-27	保险人公布政策,涵盖来自相关汽车黑客和数据泄漏的司机
10432	Cisco Firepower Management Center <  6.6.7.1 Authenticated RCE	https://buaq.net/go-230936.html	buaq	newscopy;	0	2024-03-28	Cisco烟火管理中心 < 6.6.7.1 经认证的RCE
21795	Upcoming report on the state of cybersecurity in Croatia	https://www.helpnetsecurity.com/2024/04/10/upcoming-report-on-the-state-of-cybersecurity-in-croatia/	helpnetsecurity	news;Industry news;cybersecurity;Diverto;EU;Europe;report;	1	2024-04-10	即将提交的关于克罗地亚网络安全状况的报告
8650	AI: Friend or Foe? What's Behind Our Fear of Artificial Intelligence?	https://buaq.net/go-229112.html	buaq	newscopy;	0	2024-03-20	爱尔:朋友还是福?我们害怕人工智能背后是什么?
8873	Hackers Selling GlorySprout Malware with Anti-VM Features in underground Fourm for $300	https://gbhackers.com/glorysprout-malware/	GBHacker	news;Cyber AI;Cyber Crime;cyber security;computer security;Cyber Security News;Vulnerability;	1	2024-03-20	在地下4m的反VM特征的Malware 价格300美元
21969	Dracula Phishing Platform Targets Organizations Worldwide	https://securityboulevard.com/2024/04/dracula-phishing-platform-targets-organizations-worldwide/	securityboulevard	news;Careers;SBN News;Security Awareness;Security Bloggers Network;Advanced phishing techniques;Apple;countermeasures;Cyber Threats;cybercriminals;Cybersecurity;Cybersecurity News;Domain registration;Dracula phishing platform;Email spoofing;imessage;Malicious intent;Netcraft;online safety;Password reset protection;RCS protocol;security measures;SMS filters;User Awareness;	1	2024-04-10	Dracura Wishing平台目标组织
23684	Your Guide to Threat Detection and Response	https://securityboulevard.com/2024/04/your-guide-to-threat-detection-and-response/	securityboulevard	news;Security Bloggers Network;Cybersecurity;	1	2024-04-11	你的《威胁侦测和应对指南》
3414	Accelerating the Journey to PCI DSS 4.0 Compliance with ACI Worldwide	https://securityboulevard.com/2024/03/accelerating-the-journey-to-pci-dss-4-0-compliance-with-aci-worldwide/	securityboulevard	news;Data Security;Governance, Risk & Compliance;Security Bloggers Network;Compliance;data protection;SBN News;	1	2024-03-14	加快与世界AICI的遵守
26207	华为首家海外工厂将落地法国 	https://s.weibo.com/weibo?q=%23华为首家海外工厂将落地法国 %23	sina.weibo	hotsearch;weibo	1	2023-12-11	华为首家海外工厂将落地法国
26367	小米计划自建充电桩网络 	https://s.weibo.com/weibo?q=%23小米计划自建充电桩网络 %23	sina.weibo	hotsearch;weibo	1	2024-03-26	小米计划自建充电桩网络
10701	Getting rid of a 20+ year old known vulnerability: It’s like a PSA for Runtime Security	https://securityboulevard.com/2024/03/getting-rid-of-a-20-year-old-known-vulnerability-its-like-a-psa-for-runtime-security/	securityboulevard	news;Security Bloggers Network;cisa;CVE;MOVEit;runtime security;sql injection;	1	2024-03-29	摆脱20岁以上已知的脆弱性:就像运行时安全PSA
26219	吉利高管称小米汽车宣发过了 	https://s.weibo.com/weibo?q=%23吉利高管称小米汽车宣发过了 %23	sina.weibo	hotsearch;weibo	1	2023-12-28	吉利高管称小米汽车宣发过了
20856	Patch Tuesday Update – April 2024	https://securityboulevard.com/2024/04/patch-tuesday-update-april-2024/	securityboulevard	news;Security Bloggers Network;Vulnerabilities;Vulnerability Management;	1	2024-04-09	更新2024年4月 - 2024年4月
20858	USENIX Security ’23 – Jisoo Jang, Minsuk Kang, Dokyung Song –  ReUSB: Replay-Guided USB Driver Fuzzing	https://securityboulevard.com/2024/04/usenix-security-23-jisoo-jang-minsuk-kang-dokyung-song-reusb-replay-guided-usb-driver-fuzzing/	securityboulevard	news;Security Bloggers Network;Security Conferences;USENIX;USENIX Secuirty '23;	1	2024-04-09	USENIX 安全 23 — — Jisoo Jang, Minsuk Kang, Dokyung Song — — ReUSB:重放引导的USB司机模糊
22288	MedSec Launches Cybersecurity Program For Resource-Constrained Hospitals	https://www.darkreading.com/cybersecurity-operations/medsec-launches-cybersecurity-program-for-resource-constrained-hospitals	darkreading	news;	1	2024-04-10	资源受限医院网络安全方案
22289	National Security Agency Announces Dave Luber As Director of Cybersecurity	https://www.darkreading.com/cybersecurity-operations/national-security-agency-announces-dave-luber-as-director-of-cybersecurity	darkreading	news;	1	2024-04-10	国家安全局宣布Dave Luber为网络安全局局长
16070	How CISOs Can Make Cybersecurity a Long-Term Priority for Boards	https://www.darkreading.com/cyber-risk/how-cisos-can-make-cybersecurity-long-term-priority-for-boards	darkreading	news;	1	2024-04-04	CISOs如何使网络安全成为董事会的长期优先事项
22383	ODNI guidelines for handling commercially available data to be released ‘any day,’ DOD official says	https://therecord.media/odni-guidelines-for-handling-commercially-available-data-imminent	therecord	ransom;Government;Leadership;News;Privacy;	1	2024-04-10	国防部官方指出,
24651	Introducing the Customizable Dashboard layout, Wiz integration, and more	https://securityboulevard.com/2024/04/introducing-the-customizable-dashboard-layout-wiz-integration-and-more/	securityboulevard	news;Security Bloggers Network;	1	2024-04-11	引入可定制的磁板布局、 Wiz 集成等
12440	Partridge-Venture-Engineering	http://www.ransomfeed.it/index.php?page=post_details&id_post=14057	ransomfeed	ransom;blacksuit;	1	2024-04-01	车尾车尾车尾车尾车尾车尾车尾车尾车尾车尾车尾车尾车尾车尾车尾车尾车尾车尾车尾车尾车尾车尾车尾车尾车尾车尾车尾车尾车尾车尾车尾车尾车尾车尾车尾车尾车尾车尾车尾车尾车尾车尾车尾车尾车尾车尾车尾车尾车尾车尾车尾车尾车尾车尾车尾车尾车尾车尾车尾车尾车尾车尾车尾车
24713	Mastering Linux Commands: A Complete Guide for Beginners	https://infosecwriteups.com/mastering-linux-commands-a-complete-guide-for-beginners-dd5fb2bb2a7d?source=rss----7b722bfd1b8d---4	infosecwriteups	tech;command-line;bash;programming;shell;linux;	1	2024-04-12	掌握 Linux 命令:初学者完整指南
10945	Cloud_Enum - Multi-cloud OSINT Tool. Enumerate Public Resources In AWS, Azure, And Google Cloud	http://www.kitploit.com/2024/03/cloudenum-multi-cloud-osint-tool.html	kitploit	tool;Cloud_Enum;Fuzzing;GCP;GCPBucketBrute;Microsoft;OSINT;Scraping Penetration Testing;	1	2024-03-29	Cloud_Enum - 多云OSINT 工具。 在 AWS、 Azure 和 Google Cloud 中清点公共资源
18916	Here Comes the US GDPR: APRA, the American Privacy Rights Act	https://securityboulevard.com/2024/04/apra-us-gdpr-privacy-act-richixbw/	securityboulevard	news;Application Security;AppSec;Cloud Security;Cyberlaw;Cybersecurity;Data Privacy;Data Security;DevOps;DevSecOps;Editorial Calendar;Featured;Governance, Risk & Compliance;Humor;Industry Spotlight;Mobile Security;Most Read This Week;Network Security;News;Popular Post;Regulatory Compliance;Security Awareness;Security Boulevard (Original);Security Operations;Social - Facebook;Social - LinkedIn;Social - X;Spotlight;Threats & Breaches;Zero-Trust;American Data Privacy and Protection Act;APRA (American Privacy Rights Act);Cathy McMorris Rodgers;Consumer privacy rights;customer privacy;EU GDPR;GDPR;GDPR (General Data Protection Regulation);gdpr legislation;Maria Cantwell;Privacy;SB Blogwatch;	1	2024-04-08	美国GDPR来了: PRAA,美国隐私权法案
26227	如何看待小米被曝无法退定金问题 	https://s.weibo.com/weibo?q=%23如何看待小米被曝无法退定金问题 %23	sina.weibo	hotsearch;weibo	1	2024-03-29	如何看待小米被曝无法退定金问题
26233	字节跳动将关闭游戏朝夕光年 	https://s.weibo.com/weibo?q=%23字节跳动将关闭游戏朝夕光年 %23	sina.weibo	hotsearch;weibo	1	2023-11-27	字节跳动将关闭游戏朝夕光年
26239	官方称号召西藏阿里公务员献血无不正当因素 	https://s.weibo.com/weibo?q=%23官方称号召西藏阿里公务员献血无不正当因素 %23	sina.weibo	hotsearch;weibo	1	2023-11-29	官方称号召西藏阿里公务员献血无不正当因素
26261	小米SU7即将上台 	https://s.weibo.com/weibo?q=%23小米SU7即将上台 %23	sina.weibo	hotsearch;weibo	1	2023-12-28	小米SU7即将上台
26269	小米SU7标准版不支持城市NOA 	https://s.weibo.com/weibo?q=%23小米SU7标准版不支持城市NOA %23	sina.weibo	hotsearch;weibo	1	2024-04-07	小米SU7标准版不支持城市NOA
26285	小米公司胜诉海信Vidda被判道歉 	https://s.weibo.com/weibo?q=%23小米公司胜诉海信Vidda被判道歉 %23	sina.weibo	hotsearch;weibo	1	2024-03-27	小米公司胜诉海信Vidda被判道歉
26287	小米内部员工可优惠购车 	https://s.weibo.com/weibo?q=%23小米内部员工可优惠购车 %23	sina.weibo	hotsearch;weibo	1	2024-04-03	小米内部员工可优惠购车
26295	小米回应某厂水军被警方调查 	https://s.weibo.com/weibo?q=%23小米回应某厂水军被警方调查 %23	sina.weibo	hotsearch;weibo	1	2024-01-04	小米回应某厂水军被警方调查
26307	小米手机销量暴涨38%登顶国产第一 	https://s.weibo.com/weibo?q=%23小米手机销量暴涨38%登顶国产第一 %23	sina.weibo	hotsearch;weibo	1	2024-01-09	小米手机销量暴涨38%登顶国产第一
26317	小米汽车SU7四个配置版本疑似曝光 	https://s.weibo.com/weibo?q=%23小米汽车SU7四个配置版本疑似曝光 %23	sina.weibo	hotsearch;weibo	1	2024-03-28	小米汽车SU7四个配置版本疑似曝光
26328	小米汽车向员工发放F码 	https://s.weibo.com/weibo?q=%23小米汽车向员工发放F码 %23	sina.weibo	hotsearch;weibo	1	2024-03-29	小米汽车向员工发放F码
26331	小米汽车回应50万内没有对手 	https://s.weibo.com/weibo?q=%23小米汽车回应50万内没有对手 %23	sina.weibo	hotsearch;weibo	1	2024-01-08	小米汽车回应50万内没有对手
26382	应公布阿里公务员献血事件小姑姑身份 	https://s.weibo.com/weibo?q=%23应公布阿里公务员献血事件小姑姑身份 %23	sina.weibo	hotsearch;weibo	1	2023-11-30	应公布阿里公务员献血事件小姑姑身份
26389	当地回应西藏阿里全体公务员为女子献血 	https://s.weibo.com/weibo?q=%23当地回应西藏阿里全体公务员为女子献血 %23	sina.weibo	hotsearch;weibo	1	2023-11-29	当地回应西藏阿里全体公务员为女子献血
26407	支付宝宣布启动鸿蒙原生应用开发 	https://s.weibo.com/weibo?q=%23支付宝宣布启动鸿蒙原生应用开发 %23	sina.weibo	hotsearch;weibo	1	2023-12-08	支付宝宣布启动鸿蒙原生应用开发
26422	李斌称先看小米汽车价格再给新车定价 	https://s.weibo.com/weibo?q=%23李斌称先看小米汽车价格再给新车定价 %23	sina.weibo	hotsearch;weibo	1	2024-03-15	李斌称先看小米汽车价格再给新车定价
26431	滴滴员工称系统崩溃时内网也崩了 	https://s.weibo.com/weibo?q=%23滴滴员工称系统崩溃时内网也崩了 %23	sina.weibo	hotsearch;weibo	1	2023-11-29	滴滴员工称系统崩溃时内网也崩了
26442	滴滴费用异常会统一结算补偿 	https://s.weibo.com/weibo?q=%23滴滴费用异常会统一结算补偿 %23	sina.weibo	hotsearch;weibo	1	2023-11-28	滴滴费用异常会统一结算补偿
26453	特斯拉儿童版cybertruck将进入中国 	https://s.weibo.com/weibo?q=%23特斯拉儿童版cybertruck将进入中国 %23	sina.weibo	hotsearch;weibo	1	2023-12-28	特斯拉儿童版cybertruck将进入中国
26462	特斯拉宣布原价1.2万星空灰车漆免费 	https://s.weibo.com/weibo?q=%23特斯拉宣布原价1.2万星空灰车漆免费 %23	sina.weibo	hotsearch;weibo	1	2024-04-01	特斯拉宣布原价1.2万星空灰车漆免费
26471	特斯拉称门把手被冻住挥拳用力打即可 	https://s.weibo.com/weibo?q=%23特斯拉称门把手被冻住挥拳用力打即可 %23	sina.weibo	hotsearch;weibo	1	2023-11-28	特斯拉称门把手被冻住挥拳用力打即可
26474	特斯拉要求刹车失灵事件女车主赔偿500万 	https://s.weibo.com/weibo?q=%23特斯拉要求刹车失灵事件女车主赔偿500万 %23	sina.weibo	hotsearch;weibo	1	2023-11-27	特斯拉要求刹车失灵事件女车主赔偿500万
26479	猎冰总导演否认华为投钱 	https://s.weibo.com/weibo?q=%23猎冰总导演否认华为投钱 %23	sina.weibo	hotsearch;weibo	1	2024-02-22	猎冰总导演否认华为投钱
26494	王者荣耀时代少年团直播 	https://s.weibo.com/weibo?q=%23王者荣耀时代少年团直播 %23	sina.weibo	hotsearch;weibo	1	2024-02-06	王者荣耀时代少年团直播
26506	王者荣耀首个平行世界CG 	https://s.weibo.com/weibo?q=%23王者荣耀首个平行世界CG %23	sina.weibo	hotsearch;weibo	1	2024-01-23	王者荣耀首个平行世界CG
26513	百度将为国行iPhone16提供AI功能 	https://s.weibo.com/weibo?q=%23百度将为国行iPhone16提供AI功能 %23	sina.weibo	hotsearch;weibo	2	2024-03-25	百度将为国行iPhone16提供AI功能
26523	网易游戏与华为达成鸿蒙合作 	https://s.weibo.com/weibo?q=%23网易游戏与华为达成鸿蒙合作 %23	sina.weibo	hotsearch;weibo	1	2023-12-15	网易游戏与华为达成鸿蒙合作
26525	罗永浩称小米汽车很可能上演良币驱逐劣币 	https://s.weibo.com/weibo?q=%23罗永浩称小米汽车很可能上演良币驱逐劣币 %23	sina.weibo	hotsearch;weibo	1	2024-03-29	罗永浩称小米汽车很可能上演良币驱逐劣币
26537	苹果汽车曾考虑收购特斯拉 	https://s.weibo.com/weibo?q=%23苹果汽车曾考虑收购特斯拉 %23	sina.weibo	hotsearch;weibo	1	2024-03-07	苹果汽车曾考虑收购特斯拉
26549	荣耀新品屏幕研发投入超5亿 	https://s.weibo.com/weibo?q=%23荣耀新品屏幕研发投入超5亿 %23	sina.weibo	hotsearch;weibo	1	2024-03-18	荣耀新品屏幕研发投入超5亿
26560	谷歌中国工程师疑枪杀伴侣后自杀失败 	https://s.weibo.com/weibo?q=%23谷歌中国工程师疑枪杀伴侣后自杀失败 %23	sina.weibo	hotsearch;weibo	1	2024-01-19	谷歌中国工程师疑枪杀伴侣后自杀失败
26572	长城汽车魏建军称小米发布会名不虚传 	https://s.weibo.com/weibo?q=%23长城汽车魏建军称小米发布会名不虚传 %23	sina.weibo	hotsearch;weibo	1	2024-03-29	长城汽车魏建军称小米发布会名不虚传
26575	闲鱼现大量车主转卖旧车购买小米SU7 	https://s.weibo.com/weibo?q=%23闲鱼现大量车主转卖旧车购买小米SU7 %23	sina.weibo	hotsearch;weibo	1	2024-03-29	闲鱼现大量车主转卖旧车购买小米SU7
26585	阿里巴巴回应马云蔡崇信大幅增持 	https://s.weibo.com/weibo?q=%23阿里巴巴回应马云蔡崇信大幅增持 %23	sina.weibo	hotsearch;weibo	1	2024-01-24	阿里巴巴回应马云蔡崇信大幅增持
26598	雷军佩服只有特斯拉敢涨价 	https://s.weibo.com/weibo?q=%23雷军佩服只有特斯拉敢涨价 %23	sina.weibo	hotsearch;weibo	1	2024-03-20	雷军佩服只有特斯拉敢涨价
26606	雷军官宣3月28日小米SU7上市 	https://s.weibo.com/weibo?q=%23雷军官宣3月28日小米SU7上市 %23	sina.weibo	hotsearch;weibo	1	2024-03-12	雷军官宣3月28日小米SU7上市
26611	雷军称全力以赴把小米汽车干好干成 	https://s.weibo.com/weibo?q=%23雷军称全力以赴把小米汽车干好干成 %23	sina.weibo	hotsearch;weibo	1	2024-03-07	雷军称全力以赴把小米汽车干好干成
26614	雷军称小米从小就是被卷大的 	https://s.weibo.com/weibo?q=%23雷军称小米从小就是被卷大的 %23	sina.weibo	hotsearch;weibo	1	2023-12-28	雷军称小米从小就是被卷大的
26619	雷军称小米第一辆车研发投入超百亿 	https://s.weibo.com/weibo?q=%23雷军称小米第一辆车研发投入超百亿 %23	sina.weibo	hotsearch;weibo	1	2023-12-18	雷军称小米第一辆车研发投入超百亿
26631	马云蔡崇信大幅增持阿里巴巴 	https://s.weibo.com/weibo?q=%23马云蔡崇信大幅增持阿里巴巴 %23	sina.weibo	hotsearch;weibo	1	2024-01-23	马云蔡崇信大幅增持阿里巴巴
26642	鸿蒙系统即将走向独立 	https://s.weibo.com/weibo?q=%23鸿蒙系统即将走向独立 %23	sina.weibo	hotsearch;weibo	1	2023-12-14	鸿蒙系统即将走向独立
26994	真是炸裂！俄APT组织成功窃取美国政府通信数据和微软源代码	https://www.freebuf.com/news/397778.html	freebuf	news;资讯;	2	2024-04-12	真是炸裂！俄APT组织成功窃取美国政府通信数据和微软源代码
27000	Palo Alto Networks firewalls under attack, hotfixes incoming! (CVE-2024-3400)	https://www.helpnetsecurity.com/2024/04/12/cve-2024-3400/	helpnetsecurity	news;Don't miss;Hot stuff;News;exploit;firewall;Palo Alto Networks;Volexity;vulnerability;	3	2024-04-12	Palo Alto网络的防火墙遭到攻击,热修补器进入! (CVE-2024-3400)
26970	Midnight Blizzard’s Microsoft Corporate Email Hack Threatens Federal Agencies: CISA Warns	https://gbhackers.com/microsoft-corporate-email-hack/	GBHacker	news;cyber security;Cyber Security News;Microsoft;	1	2024-04-12	Blizzard的微软公司Email Hack威胁联邦机构:CISA Warns
26999	Cado Security teams up with Wiz to accelerate forensic investigations and minimize cloud threats	https://www.helpnetsecurity.com/2024/04/12/cado-security-wiz/	helpnetsecurity	news;Industry news;Cado Security;Wiz;	1	2024-04-12	卡多安全小组与Wiz Wiz一起加快法证调查和尽量减少云层威胁
27003	Palo Alto Networks enhances Cortex XSIAM to help SecOps teams identify cloud threats	https://www.helpnetsecurity.com/2024/04/12/palo-alto-networks-cortex-xsiam-platform/	helpnetsecurity	news;Industry news;Palo Alto Networks;	1	2024-04-12	Palo Alto网络加强Cortex XSIAM,帮助SecOps小组查明云威胁
27127	Cyber Attack Surge by 28%:Education Sector at High Risk	https://gbhackers.com/cyber-attack-surge-by-28/	GBHacker	news;Cyber Attack;cyber security;Cyber Security News;ransomware;Vulnerability;	1	2024-04-12	网络攻击暴增28%:教育高危部门
27166	Zscaler extends zero trust SASE and eliminates the need for firewall-based segmentation	https://www.helpnetsecurity.com/2024/04/12/zscaler-extends-zero-trust-sase-and-eliminates-the-need-for-firewall-based-segmentation/	helpnetsecurity	news;Industry news;Zscaler;	1	2024-04-12	Zassaller 扩展零信任 SASASE 并消除防火墙隔离的必要性
27170	js逆向-你要学会偷懒「使用工具」	https://xz.aliyun.com/t/14274	阿里先知实验室	news;	1	2024-04-10	js逆向-你要学会偷懒「使用工具」
27171	一篇文章带你搞懂蜜罐	https://xz.aliyun.com/t/14276	阿里先知实验室	news;	1	2024-04-10	一篇文章带你搞懂蜜罐
27204	XZ backdoor story – Initial analysis	https://securelist.com/xz-backdoor-story-part-1/112354/	securelist	news;Incidents;Backdoor;Cyber espionage;Linux;Malware;Malware Descriptions;Malware Technologies;SSH;XZ;Unix and macOS malware;	1	2024-04-12	XZ后门故事 — — 初步分析
27212	Our Security of AI Papers and Blogs Explained	https://securityboulevard.com/2024/04/our-security-of-ai-papers-and-blogs-explained/	securityboulevard	news;Security Bloggers Network;AI Security;securing-ai;	1	2024-04-11	我们的AI 论文和博客安全 解释
27318	金融监管总局发布《反保险欺诈工作办法（征求意见稿）》	https://www.freebuf.com/news/397772.html	freebuf	news;资讯;	1	2024-04-12	金融监管总局发布《反保险欺诈工作办法（征求意见稿）》
27336	CVE-2024-31224 RCE 分析	https://xz.aliyun.com/t/14283	阿里先知实验室	news;	3	2024-04-11	CVE-2024-31224 RCE 分析
27337	浅谈网络代理 proxy	https://xz.aliyun.com/t/14284	阿里先知实验室	news;	1	2024-04-12	浅谈网络代理 proxy
27381	Microsoft now testing app ads in Windows 11's Start menu	https://www.bleepingcomputer.com/news/microsoft/microsoft-now-testing-app-ads-in-windows-11s-start-menu/	bleepingcomputer	news;Microsoft;	1	2024-04-12	微软现在测试 Windows 11 的启动菜单中的应用程序广告
27382	Former AT&T customers get $6.3 million in data throttling refunds	https://www.bleepingcomputer.com/news/mobile/former-atandt-customers-get-63-million-in-data-throttling-refunds/	bleepingcomputer	news;Mobile;	1	2024-04-12	前AT&T客户获得630万美元的数据抽动退款
27383	Ex-Amazon engineer gets 3 years for hacking crypto exchanges	https://www.bleepingcomputer.com/news/security/ex-amazon-engineer-gets-3-years-for-hacking-crypto-exchanges/	bleepingcomputer	news;Security;	1	2024-04-12	前亚马孙工程师 入侵密码交换机 被判三年
27384	FBI warns of massive wave of road toll SMS phishing attacks	https://www.bleepingcomputer.com/news/security/fbi-warns-of-massive-wave-of-road-toll-sms-phishing-attacks/	bleepingcomputer	news;Security;	1	2024-04-12	联邦调查局警告说,有大批人因短讯网钓鱼攻击而丧生
27385	Firebird RAT creator and seller arrested in the U.S. and Australia	https://www.bleepingcomputer.com/news/security/firebird-rat-creator-and-seller-arrested-in-the-us-and-australia/	bleepingcomputer	news;Security;Legal;	1	2024-04-13	Firebird RAT 创造者和销售者在美国和澳大利亚被捕
27386	Hacker claims Giant Tiger data breach, leaks 2.8M records online	https://www.bleepingcomputer.com/news/security/hacker-claims-giant-tiger-data-breach-leaks-28m-records-online/	bleepingcomputer	news;Security;	1	2024-04-13	Hacker声称巨虎号数据被突破 网上泄漏了2.8M记录
27387	OpenTable won't add first names, photos to old reviews after backlash	https://www.bleepingcomputer.com/news/security/opentable-wont-add-first-names-photos-to-old-reviews-after-backlash/	bleepingcomputer	news;Security;	1	2024-04-14	Opentable 在反弹后不会在旧评论中添加名、 照片
27388	Palo Alto Networks warns of PAN-OS firewall zero-day used in attacks	https://www.bleepingcomputer.com/news/security/palo-alto-networks-warns-of-pan-os-firewall-zero-day-used-in-attacks/	bleepingcomputer	news;Security;	1	2024-04-12	Palo Alto网络警告攻击中使用的PAN-OS防火墙零天
27389	Palo Alto Networks zero-day exploited since March to backdoor firewalls	https://www.bleepingcomputer.com/news/security/palo-alto-networks-zero-day-exploited-since-march-to-backdoor-firewalls/	bleepingcomputer	news;Security;	1	2024-04-13	自3月以来被利用为后门防火墙的零天网络
27390	Roku warns 576,000 accounts hacked in new credential stuffing attacks	https://www.bleepingcomputer.com/news/security/roku-warns-576-000-accounts-hacked-in-new-credential-stuffing-attacks/	bleepingcomputer	news;Security;	1	2024-04-12	Roku警告576,000个账户,
27393	Medium bans AI-generated content from its paid Partner Program	https://www.bleepingcomputer.com/news/technology/medium-bans-ai-generated-content-from-its-paid-partner-program/	bleepingcomputer	news;Technology;Software;	1	2024-04-14	中等程度禁止大赦国际从其付费伙伴方案中产生内容
27397	CISA Issues Emergency Directive After Midnight Blizzard Microsoft Hits	https://www.darkreading.com/cyberattacks-data-breaches/cisa-emergency-directive-after-midnight-blizzard-microsoft-hits	darkreading	news;	1	2024-04-12	CISA 午夜Blizzard 微软点击后的问题紧急指令
27398	CISO Corner: Securing the AI Supply Chain; AI-Powered Security Platforms; Fighting for Cyber Awareness	https://www.darkreading.com/cybersecurity-operations/ciso-corner-securing-ai-supply-chain-ai-powered-security-platforms-cyber-awareness	darkreading	news;	1	2024-04-12	CISO角:确保AI供应链安全;AI授权的安全平台;为网络宣传而斗争
27399	The Race for AI-Powered Security Platforms Heats Up	https://www.darkreading.com/cybersecurity-operations/race-ai-powered-platforms-security-platforms	darkreading	news;	1	2024-04-12	争取AI授权的 安全平台热量上升的竞赛
27400	Knostic Brings Access Control to LLMs	https://www.darkreading.com/data-privacy/knostic-brings-access-control-to-llms	darkreading	news;	1	2024-04-11	Knnnostic 带来器使用LLMM 控制控制
27401	New Tool Shields Organizations From NXDOMAIN Attacks	https://www.darkreading.com/remote-workforce/akamai-boosts-dns	darkreading	news;	1	2024-04-12	NXDOMIAIN袭击中的新工具盾组织
27406	Critical Infrastructure Security: Observations From the Front Lines	https://www.darkreading.com/vulnerabilities-threats/critical-infrastructure-security-observations-from-front-lines	darkreading	news;	1	2024-04-12	关键基础设施安全:来自前线的观察
27409	 Public Browser Exploitation Training – Summer 2024 	https://blog.exodusintel.com/2024/04/12/public-browser-exploitation-training-summer-2024/	exodusintel	vuln; exodusintel ;This 4 day course is designed to provide students with both an overview of the current state of the browser attack surface and an in-depth; Read More ;	1	2024-04-12	公共浏览器剥削培训 - 2024年夏季
27410	 Public Mobile Exploitation Training – Summer 2024 	https://blog.exodusintel.com/2024/04/12/public-mobile-exploitation-training-summer-2024/	exodusintel	vuln; exodusintel ;This 4 day course is designed to provide students with both an overview of the Android attack surface and an in-depth understanding of advanced vulnerability; Read More ;	1	2024-04-12	公共流动开发培训 - 2024年夏季
27411	 Vulnerability Assessment Course – Summer 2024 	https://blog.exodusintel.com/2024/04/12/vulnerability-assessment-course-summer-2024/	exodusintel	vuln; exodusintel ;This course introduces vulnerability analysis and research with a focus on Ndays. We start with understanding security risks and discuss industry-standard metrics such as CVSS,; Read More ;	1	2024-04-12	脆弱性评估课程 - 2024年夏季
27413	Toolkit - The Essential Toolkit For Reversing, Malware Analysis, And Cracking	http://www.kitploit.com/2024/04/toolkit-essential-toolkit-for-reversing.html	kitploit	tool;Infosec;Infosec Reference;Malware Analysis;Reverse Engineering;Toolkit;	1	2024-04-14	工具包 -- -- 用于逆转、恶意分析和裂变的基本工具包
27415	Enhancing Digital Security: Strategies for Secret Detection and Management	https://infosecwriteups.com/enhancing-digital-security-strategies-for-secret-detection-and-management-f3c543c7e25c?source=rss----7b722bfd1b8d---4	infosecwriteups	tech;passwords;regex;entropy;infosec;github;	1	2024-04-13	加强数字安全:秘密侦查和管理战略
27417	Hijacking your JavaScript using prototype pollution	https://infosecwriteups.com/hijacking-your-javascript-using-prototype-pollution-8caeac16b13f?source=rss----7b722bfd1b8d---4	infosecwriteups	tech;cybersecurity;web-security;ethical-hacking;xss-attack;prototype-pollution;	1	2024-04-13	利用原型污染劫持你的JavaScript
27419	HTB — Bashed	https://infosecwriteups.com/htb-bashed-2e7c3915c81e?source=rss----7b722bfd1b8d---4	infosecwriteups	tech;technology;medium;hackthebox;learning;writing;	1	2024-04-14	HTB - 泥土
27420	TryHackMe CTF Collection Vol. 2	https://infosecwriteups.com/tryhackme-ctf-collection-vol-2-e570d487ebc3?source=rss----7b722bfd1b8d---4	infosecwriteups	tech;ctf;cybersecurity;ctf-walkthrough;tryhackme;ctf-writeup;	1	2024-04-13	TryHackMe CTF收藏第2卷
27423	XZ Backdoor —  Breaching Trust in Open-Source Collaborative Development	https://infosecwriteups.com/xz-backdoor-breaching-trust-in-open-source-collaborative-development-4b6510629b03?source=rss----7b722bfd1b8d---4	infosecwriteups	tech;information-security;cybersecurity;vulnerability;open-source;hacking;	1	2024-04-14	XZ 后门——对开放来源合作发展的潜在信任
27424	Cyber Attacks Could Cause Global Bank Runs	https://blog.knowbe4.com/cyber-attacks-could-cause-global-bank-runs	knowbe4	news;Cybersecurity;	1	2024-04-12	网络攻击可能导致全球银行运行
27425	U.S. Department of Health Alert: Hackers are Targeting IT Help Desks at Healthcare Organizations	https://blog.knowbe4.com/hackers-targeting-it-helpdesks-healthcare-organizations	knowbe4	news;Social Engineering;Phishing;	1	2024-04-12	美国卫生部卫生警报:黑客正在针对保健组织信息技术服务台
27426	[Heads Up] Global Cybercrime Hotspot Countries Revealed: Secure Your Defenses	https://blog.knowbe4.com/heads-up-global-cybercrime-hotspot-countries-revealed-secure-your-defenses	knowbe4	news;Russia;	1	2024-04-13	全球网络犯罪热点国家:安全防卫
27427	I don't have to say it, do I?	https://blog.knowbe4.com/i-dont-have-to-say-it-do-i	knowbe4	news;Social Engineering;	1	2024-04-13	我不必说,是吗?
27428	State-Sponsored Disinformation Campaigns Targeting Africa Driving Instability And Violence	https://blog.knowbe4.com/state-sponsored-disinformation-campaigns-targeting-africa-drives-instability	knowbe4	news;Social Engineering;Phishing;Ransomware;Security Culture;	1	2024-04-12	针对非洲造成不稳定和暴力的宣传运动
27429	UK Councils Under Cyber Attack: The Urgent Need for a Culture of Cybersecurity and Resilience	https://blog.knowbe4.com/uk-councils-under-cyber-attack-the-urgent-need-for-culture-of-cybersecurity	knowbe4	news;Social Engineering;Phishing;Ransomware;	1	2024-04-12	受到网络攻击的联合王国理事会:迫切需要建立网络安全和复原力文化
27434	DuckDuckGo Launches Privacy Pro: 3-in-1 service With VPN	https://gbhackers.com/duckduckgo-launches-privacy-pro/	GBHacker	news;cyber security;Cyber Security News;	1	2024-04-12	DuckDuckGo 启动隐私 Pro: 与 VPN 连接的三进一服务
27436	6-year-old Lighttpd Flaw Impacts Intel And Lenovo Servers	https://gbhackers.com/lighttpd-flaw-intel-lenovo-servers/	GBHacker	news;CVE/vulnerability;Cyber Security News;Network Security;cyber security;firmware;Supply Chain;	1	2024-04-12	6岁的Lighttpd Flaw 影响英特尔和Lenovo服务器
27439	Sisence Data Breach, CISA Urges To Reset Login Credentials	https://gbhackers.com/sisence-data-breach-cisa-reset-credentials/	GBHacker	news;Cyber Security News;Data Breach;Incident Response;cyber security;Supply Chain Attack;	1	2024-04-12	CISA 催促重定登录证书
27443	浅谈数据安全治理和分级分类实施	https://www.freebuf.com/articles/database/397780.html	freebuf	news;数据安全;	1	2024-04-12	浅谈数据安全治理和分级分类实施
27445	窃密木马借&quot;壁纸引擎&quot;传播，Steam &quot;再中招&quot;	https://www.freebuf.com/articles/paper/397690.html	freebuf	news;安全报告;	1	2024-04-11	窃密木马借"壁纸引擎"传播，Steam "再中招"
27458	一周网安优质PDF资源推荐丨FreeBuf知识大陆	https://www.freebuf.com/news/397807.html	freebuf	news;资讯;	1	2024-04-12	一周网安优质PDF资源推荐丨FreeBuf知识大陆
27460	Check Point boosts security in Harmony Email & Collaboration	https://www.helpnetsecurity.com/2024/04/12/check-point-email-security/	helpnetsecurity	news;Industry news;Check Point;	1	2024-04-12	检查点可增强和谐电子邮件和协作的安全性
27468	Week in review: Palo Alto Networks firewalls under attack, Microsoft patches two exploited zero-days	https://www.helpnetsecurity.com/2024/04/14/week-in-review-palo-alto-networks-firewalls-under-attack-microsoft-patches-two-exploited-zero-days/	helpnetsecurity	news;News;Week in review;	1	2024-04-14	审查周:帕洛阿尔托网络遭到攻击的防火墙,微软修补2个被利用的零日
27470	AMPLE BILLS 0.1 Multiple-SQLi	https://www.nu11secur1ty.com/2024/04/ample-bills-01-multiple-sqli.html	nu11security	vuln;	1	2024-04-13	AMPLE BILLS 0.1 多SQLi
27472	Change Healthcare Faces Another Ransomware Threat—and It Looks Credible	https://www.wired.com/story/change-healthcare-ransomhub-threat/	wired	news;Security;Security / Cyberattacks and Hacks;Security / Security News;	2	2024-04-12	“改变保健面面面”又一个Ransomware威胁,
27473	House Votes to Extend—and Expand—a Major US Spy Program	https://www.wired.com/story/house-section-702-vote/	wired	news;Security;Security / National Security;Security / Privacy;Politics / Policy;	1	2024-04-12	众议院投票扩大和扩大美国主要间谍方案
27474	How Israel Fended Off Iran's Drone and Missile Attack	https://www.wired.com/story/iran-israel-drone-attack-iron-dome/	wired	news;Security;Security / National Security;	3	2024-04-14	以色列如何逃离伊朗的无人机和导弹攻击
27475	Roku Breach Hits 567,000 Users	https://www.wired.com/story/roku-breach-hits-567000-users/	wired	news;Security;Security / Cyberattacks and Hacks;Security / National Security;Security / Privacy;Security / Security News;	1	2024-04-13	Roku Break Break Hits 567,000用户
27476	Space Force Is Planning a Military Exercise in Orbit	https://www.wired.com/story/space-force-military-exercise-satellite/	wired	news;Security;Security / National Security;Science / Space;	1	2024-04-13	计划在轨道上进行军事演习
27477	Hack The Box: Einladen Sherlock Walkthrough – Medium Diffucility	https://threatninja.net/2024/04/hack-the-box-einladen-sherlock-walkthrough-medium-diffucility/	threatninja	sectest;Sherlock Medium;	1	2024-04-12	黑盒:艾因拉登·夏洛克·路过 — — 中等易懂性
27479	US sanctions Hamas ‘cyber influence’ leader	https://therecord.media/al-qassam-abu-ubaida-sanctions-us-treasury	therecord	ransom;Government;News;	1	2024-04-12	美国制裁哈马斯“网络影响”领导人
27480	FISA Section 702 reauthorization passes in House on second try this week	https://therecord.media/fisa-section-702-house-floor-votes-again	therecord	ransom;Government;News;News Briefs;	1	2024-04-12	FISA第702条 重新授权本周第二试
27481	Current and former Polish officials face probe of alleged spyware abuse	https://therecord.media/poland-pegasus-spyware-government-investigation	therecord	ransom;Government;News;Privacy;	1	2024-04-12	波兰现任和前任官员面临被指称滥用间谍软件的质询
27482	Sisense customers seek answers after breach announcement	https://therecord.media/sisense-data-breach-customer-reaction	therecord	ransom;Industry;News;	1	2024-04-12	Sissense客户在违反通知后寻求答复
27483	Palo Alto Networks warns of zero-day in VPN product	https://therecord.media/vpn-zero-day-palo-alto-networks	therecord	ransom;Technology;Industry;News Briefs;News;	1	2024-04-12	Palo Alto 网络警告 VPN 产品为零日
27484	Code Keepers: Mastering Non-Human Identity Management	https://thehackernews.com/2024/04/code-keepers-mastering-non-human.html	feedburner	news;	1	2024-04-12	编码保管人:掌握非人类身份管理
27485	Ex-Security Engineer Jailed 3 Years for $12.3 Million Crypto Exchange Thefts	https://thehackernews.com/2024/04/ex-security-engineer-jailed-3-years-for.html	feedburner	news;	1	2024-04-13	前安保工程师因1 230万美元的加密交换被窃而入狱3年
27488	Hackers Deploy Python Backdoor in Palo Alto Zero-Day Attack	https://thehackernews.com/2024/04/hackers-deploy-python-backdoor-in-palo.html	feedburner	news;	1	2024-04-13	在Palo Alto零日攻击中部署黑客后门
27489	Iranian MuddyWater Hackers Adopt New C2 Tool 'DarkBeatC2' in Latest Campaign	https://thehackernews.com/2024/04/iranian-muddywater-hackers-adopt-new-c2.html	feedburner	news;	3	2024-04-12	伊朗Muddy Water Hackers在最新运动中采用新的 C2 工具“ DarkBeatC2 ”
27490	Popular Rust Crate liblzma-sys Compromised with XZ Utils Backdoor Files	https://thehackernews.com/2024/04/popular-rust-crate-liblzma-sys.html	feedburner	news;	1	2024-04-12	与 XZ 工具后门文件混杂
27494	U.S. Treasury Hamas Spokesperson for Cyber Influence Operations	https://thehackernews.com/2024/04/us-treasury-hamas-spokesperson-for.html	feedburner	news;	1	2024-04-13	美国财政部哈马斯网络影响行动发言人
27497	Balbix Guide to XZ Utils Backdoor	https://securityboulevard.com/2024/04/balbix-guide-to-xz-utils-backdoor/	securityboulevard	news;Security Bloggers Network;Vulnerabilities;asset inventory;CAASM;cyber resilience;Cybersecurity Risk Management;Vulnerability Management;	1	2024-04-12	XZ 后门工具的 Balbix 指南
27498	CISA Warns of Compromised Microsoft Accounts	https://securityboulevard.com/2024/04/cisa-warns-of-compromised-microsoft-accounts/	securityboulevard	news;Data Security;Security Bloggers Network;Threats & Breaches;account takeover;Active Directory;Cybersecurity;Data breaches;Regulation and Compliance;	1	2024-04-12	CISA 熔化微软账户的 Warns
27391	Telegram fixes Windows app zero-day used to launch Python scripts	https://www.bleepingcomputer.com/news/security/telegram-fixes-windows-app-zero-day-used-to-launch-python-scripts/	bleepingcomputer	news;Security;	1	2024-04-12	用于发射 Python 脚本的 Windows 应用程序零天
27392	UK flooded with forged stamps despite using barcodes — to prevent just that	https://www.bleepingcomputer.com/news/security/uk-flooded-with-forged-stamps-despite-using-barcodes-to-prevent-just-that/	bleepingcomputer	news;Security;	1	2024-04-13	英国尽管使用条形码, 却充斥着伪造邮票,
27404	CISA's Malware Analysis Platform Could Foster Better Threat Intel	https://www.darkreading.com/vulnerabilities-threats/cisa-s-new-malware-analysis-platform-could-enable-better-threat-intelligence	darkreading	news;	1	2024-04-12	CISA的恶意分析平台可以促进更好的威胁情报
27412	Porch-Pirate - The Most Comprehensive Postman Recon / OSINT Client And Framework That Facilitates The Automated Discovery And Exploitation Of API Endpoints And Secrets Committed To Workspaces, Collections, Requests, Users And Teams	http://www.kitploit.com/2024/04/porch-pirate-most-comprehensive-postman.html	kitploit	tool;Devsecops;Scanning;Secrets;	1	2024-04-12	Pirch-Pirch-Pirch-Pirch-最全面的邮后调查/OSINT客户和框架,便利自动发现和利用API终点点和工作空间秘密、收集、请求、用户和团队
27432	Alert! Palo Alto RCE Zero-day Vulnerability Actively Exploited in the Wild	https://gbhackers.com/alert-palo-alto-rce-zero-day-vulnerability-actively-exploited-in-the-wild/	GBHacker	news;CVE/vulnerability;Cyber Attack;Cyber Security News;cyber security;	1	2024-04-12	警告! Palo Alto RCE 零天脆弱性在野外被积极利用
27435	Hackers Employ Deepfake Technology To Impersonate as LastPass CEO	https://gbhackers.com/hackers-employ-deepfake-technology/	GBHacker	news;cyber security;Cyber Security News;	1	2024-04-12	Hackers 使用深假技术, 以 LastPass 首席执行官的身份出现
27454	FreeBuf早报 | 菲律宾科技部服务器遭黑客入侵；光学巨头 Hoya 遭勒索 1000 万美元	https://www.freebuf.com/news/397717.html	freebuf	news;资讯;	1	2024-04-12	FreeBuf早报 | 菲律宾科技部服务器遭黑客入侵；光学巨头 Hoya 遭勒索 1000 万美元
27464	CVE-2024-3400 exploited: Unit 42, Volexity share more details about the attacks	https://www.helpnetsecurity.com/2024/04/12/palo-alto-networks-firewalls-cve-2024-3400-exploited/	helpnetsecurity	news;Don't miss;Hot stuff;News;exploit;firewall;Palo Alto Networks;Volexity;vulnerability;	3	2024-04-12	CVE-2024-3400号被开采:第42号单元,易动性分享更多关于袭击详情
27478	Hack The Box: Hospital Machine Walkthrough – Medium Difficulty	https://threatninja.net/2024/04/hack-the-box-hospital-machine-walkthrough-medium-difficulty/	threatninja	sectest;Medium Machine;BurpSuite;Challenges;command injection;CVE-2023-35001;CVE-2023-36664;GhostScript-Command-Injection;HackTheBox;hashcat;Linux;python3;Windows;	1	2024-04-13	黑盒:医院机器走过 — 中度困难
27495	Zero-Day Alert: Critical Palo Alto Networks PAN-OS Flaw Under Active Attack	https://thehackernews.com/2024/04/zero-day-alert-critical-palo-alto.html	feedburner	news;	1	2024-04-12	" 零日警报 " : " 严酷的阿尔托网络 " ,PAN-OS Flaw
27499	Deciphering Metrics: From NCAA Women’s Basketball to Cyber Trends	https://securityboulevard.com/2024/04/deciphering-metrics-from-ncaa-womens-basketball-to-cyber-trends/	securityboulevard	news;Security Bloggers Network;	1	2024-04-14	分解度量:从NCAA妇女篮球到网络趋势
27500	How to Reduce the Risk of Using External AI Models in Your SDLC	https://securityboulevard.com/2024/04/how-to-reduce-the-risk-of-using-external-ai-models-in-your-sdlc/	securityboulevard	news;Security Bloggers Network;AppSec;Best Practices;Explainers;	1	2024-04-12	如何降低在你的SDLC中使用外部AI模型的风险
27501	How to track and stop CVE-2024-3400: Palo Alto Devices API Exploit Causing Critical Infrastructure and Enterprise Epidemics	https://securityboulevard.com/2024/04/how-to-track-and-stop-cve-2024-3400-palo-alto-devices-api-exploit-causing-critical-infrastructure-and-enterprise-epidemics/	securityboulevard	news;Security Bloggers Network;API security;	3	2024-04-13	如何追踪和阻止CVE-2024-3400:帕洛阿尔托装置 API 利用造成关键基础设施和企业流行病的爆炸
27502	NVD’s Backlog Triggers Public Response from Cybersec Leaders	https://securityboulevard.com/2024/04/nvds-backlog-triggers-public-response-from-cybersec-leaders/	securityboulevard	news;Security Bloggers Network;	1	2024-04-12	NVD的积压事件触发网络网塞领导人的公众反应
27503	The XZ backdoor: What security managers can learn	https://securityboulevard.com/2024/04/the-xz-backdoor-what-security-managers-can-learn/	securityboulevard	news;Careers;Malware;SBN News;Security Awareness;Security Bloggers Network;backdoor;CISO Suite;Cyber Security News;Home;malware attacks;Security News;Seed n soil posts;	1	2024-04-12	XZ后门:安全主管能学到什么
27504	USENIX Security ’23 – Fast IDentity Online with Anonymous Credentials (FIDO-AC)	https://securityboulevard.com/2024/04/usenix-security-23-fast-identity-online-with-anonymous-credentials-fido-ac/	securityboulevard	news;Security Bloggers Network;USENIX;USENIX Secuirty '23;	1	2024-04-12	USENIX 安全 23 - 具有匿名证书的快速身份号码在线(FIDO-AC)
27505	USENIX Security ’23 – How to Bind Anonymous Credentials to Humans	https://securityboulevard.com/2024/04/usenix-security-23-how-to-bind-anonymous-credentials-to-humans/	securityboulevard	news;Security Bloggers Network;Security Conferences;USENIX;USENIX Security ’23;	1	2024-04-14	USENIX 安全 ' 23 - 如何将匿名证明书交给人类
27506	What is Web Application Security Testing?	https://securityboulevard.com/2024/04/what-is-web-application-security-testing-2/	securityboulevard	news;Security Bloggers Network;Cyber Security;	1	2024-04-13	什么是网络应用安全测试?
27595	How Microsoft discovers and mitigates evolving attacks against AI guardrails	https://www.microsoft.com/en-us/security/blog/2024/04/11/how-microsoft-discovers-and-mitigates-evolving-attacks-against-ai-guardrails/	microsoft	news;	1	2024-04-11	微软如何发现和减轻对AI系统护卫铁路不断演变的袭击
27849	首篇报告！APT组织SideWinder(响尾蛇)积极对其后门武器WarHawk进行重构，样本逆向分析	https://xz.aliyun.com/t/14295	阿里先知实验室	news;	2	2024-04-15	首篇报告！APT组织SideWinder(响尾蛇)积极对其后门武器WarHawk进行重构，样本逆向分析
27862	Ransomware tracker: The latest figures [April 2024]	https://therecord.media/ransomware-tracker-the-latest-figures	therecord	ransom;Government;News;Cybercrime;	2	2024-04-15	Ransomware 跟踪器:最新数字 [2024年4月]
27959	FreeBuf 周报 | “暗网版微信”准备上市；D-Link NAS设备存严重RCE漏洞	https://www.freebuf.com/news/397781.html	freebuf	news;资讯;	3	2024-04-13	FreeBuf 周报 | “暗网版微信”准备上市；D-Link NAS设备存严重RCE漏洞
27929	微软4月安全更新多个产品高危漏洞通告	https://blog.nsfocus.net/microsoftapril-2/	绿盟	news;威胁通告;安全漏洞;漏洞防护;	3	2024-04-15	微软4月安全更新多个产品高危漏洞通告
27970	Expand your library with these cybersecurity books	https://www.helpnetsecurity.com/2024/04/15/cybersecurity-books-video/	helpnetsecurity	news;Video;books;cybersecurity;N2K;Stamus Networks;video;WithSecure;	1	2024-04-15	用这些网络安全书籍扩展您的图书馆
28084	CISA 就 Sisense 数据泄露事件发出警告	https://www.freebuf.com/news/397912.html	freebuf	news;资讯;	1	2024-04-15	CISA 就 Sisense 数据泄露事件发出警告
28094	Zarf: Open-source continuous software delivery on disconnected networks	https://www.helpnetsecurity.com/2024/04/15/zarf-open-source-continuous-software-delivery-on-disconnected-networks/	helpnetsecurity	news;Don't miss;News;DevSecOps;GitHub;open source;software;	1	2024-04-15	Zarf:在断开的网络上提供开放源源连续软件
28173	HTB CTF: Cracking Passwords with Hashcat	https://infosecwriteups.com/htb-ctf-cracking-passwords-with-hashcat-6a932514e5c8?source=rss----7b722bfd1b8d---4	infosecwriteups	tech;htb-academy-writeup;ctf-writeup;ctf-walkthrough;cybersecurity;hashcat;	1	2024-04-15	HTB CTF: 使用 Hashcat 破碎密码
28214	Geopolitical tensions escalate OT cyber attacks	https://www.helpnetsecurity.com/2024/04/15/andrew-ginter-waterfall-security-ot-cyber-attacks/	helpnetsecurity	news;Don't miss;Features;Hot stuff;News;attacks;CISO;critical infrastructure;cybersecurity;GISEC;government;ICS/SCADA;opinion;ransomware;strategy;threats;	1	2024-04-15	地缘政治紧张局势使OT网络攻击升级
28216	Exposing the top cloud security threats	https://www.helpnetsecurity.com/2024/04/15/global-businesses-top-cloud-security-threats-video/	helpnetsecurity	news;Don't miss;Hot stuff;Video;Aqua Security;artificial intelligence;cloud security;cybersecurity;threat;video;	1	2024-04-15	暴露顶层云层安全威胁
28217	How to protect IP surveillance cameras from Wi-Fi jamming	https://www.helpnetsecurity.com/2024/04/15/ip-surveillance-cameras/	helpnetsecurity	news;Don't miss;Expert analysis;Expert corner;Hot stuff;News;cybersecurity;IoT;Nabto;opinion;security cameras;smart home;surveillance;wireless;	1	2024-04-15	如何保护IP监控摄像头不受无线干扰
28540	LightSpy Malware Attacking Android and iOS Users	https://gbhackers.com/lightspy-malware/	GBHacker	news;Android;cyber security;Cyber Security News;iOS;Malware;	2	2024-04-15	攻击机器人和iOS用户
28545	This Startup Aims To Simplify End-to-End Cybersecurity, So Anyone Can Do It	https://gbhackers.com/this-startup-aims-to-simplify-end-to-end-cybersecurity-so-anyone-can-do-it/	GBHacker	news;Tech;	1	2024-04-14	这个启动目标旨在简化终端到终端网络安全, 所以任何人都可以做到这一点
28560	Cyera 获得 3 亿美元融资，以推动人工智能的安全应用	https://www.freebuf.com/news/397915.html	freebuf	news;资讯;	1	2024-04-15	Cyera 获得 3 亿美元融资，以推动人工智能的安全应用
28723	Debian Security Advisory 5656-1	https://packetstormsecurity.com/files/178037/dsa-5656-1.txt	packetstorm	vuln;;	1	2024-04-12	Debian安全咨询 5656-1
28724	Ubuntu Security Notice USN-6730-1	https://packetstormsecurity.com/files/178038/USN-6730-1.txt	packetstorm	vuln;;	1	2024-04-12	Ubuntu Ubuntu 安全通知 USN-6730-1
28729	Electron 安全与你我息息相关	https://paper.seebug.org/3146/	seebug	news;漏洞分析;经验心得;	1	2024-04-12	Electron 安全与你我息息相关
28730	GSM 内核 LPE 研究分析	https://paper.seebug.org/3148/	seebug	news;经验心得;二进制安全;	1	2024-04-12	GSM 内核 LPE 研究分析
28739	The Rising Threat of Social Media Harassment. Here’s How to Protect Yourself.	https://www.mcafee.com/blogs/internet-security/the-rising-threat-of-social-media-harassment-heres-how-to-protect-yourself/	mcafee	news;Internet Security;	1	2024-04-12	社会媒体骚扰威胁不断上升,
28740	How to Protect Your Streaming Accounts: Lessons from Roku’s Data Leak	https://www.mcafee.com/blogs/tips-tricks/how-to-protect-your-streaming-accounts/	mcafee	news;How To Guides and Tutorials;	1	2024-04-14	如何保护您的流流账户:从罗库的数据泄漏中汲取的教训
28741	Bigem Teknoloji - Sql Injection	https://cxsecurity.com/issue/WLB-2024040033	cxsecurity	vuln;	1	2024-04-14	Bigem Teknoloji - Sql 注射
28742	Ray OS 2.6.3 Command Injection	https://cxsecurity.com/issue/WLB-2024040032	cxsecurity	vuln;	1	2024-04-14	Ray OS 2.6.3 指令注射
28743	GUnet OpenEclass E-learning 3.15 File Upload / Command Execution	https://cxsecurity.com/issue/WLB-2024040021	cxsecurity	vuln;	1	2024-04-11	GUnet 开放类电子学习 3.15 文件上传/命令执行
28744	Concrete CMS 9.2.7 Cross Site Scripting / Open Redirect	https://cxsecurity.com/issue/WLB-2024040022	cxsecurity	vuln;	1	2024-04-11	混凝土 CMS 9.2.7 跨站点脚本/开放式中转
28745	Trimble TM4Web 22.2.0 Privilege Escalation / Access Code Disclosure	https://cxsecurity.com/issue/WLB-2024040023	cxsecurity	vuln;	1	2024-04-11	22.2.0 特权升级/准入法披露
28746	OX App Suite 7.10.6 Cross Site Scripting / Deserialization Issue	https://cxsecurity.com/issue/WLB-2024040024	cxsecurity	vuln;	1	2024-04-11	7.10.6 跨站点脚本/解密问题
28747	Fuxnet: Disabling Russia's Industrial Sensor And Monitoring Infrastructure	https://cxsecurity.com/issue/WLB-2024040025	cxsecurity	vuln;	3	2024-04-11	Fuxnet:摧毁俄罗斯工业传感器和监测基础设施
28748	AMPLE BILLS 0.1 Multiple-SQLi	https://cxsecurity.com/issue/WLB-2024040026	cxsecurity	vuln;	1	2024-04-14	AMPLE BILLS 0.1 多SQLi
28749	Blood Bank v1.0 Stored Cross Site Scripting (XSS)	https://cxsecurity.com/issue/WLB-2024040027	cxsecurity	vuln;	1	2024-04-14	血库 v1.0 存储的跨地点脚本(XSS)
28751	Wordpress Plugin Playlist for Youtube 1.32 Stored Cross-Site Scripting (XSS)	https://cxsecurity.com/issue/WLB-2024040029	cxsecurity	vuln;	1	2024-04-14	Youtube 1. 32 的 Wordpress 插件播放列表( XSS)
28752	MinIO <  2024-01-31T20-20-33Z Privilege Escalation	https://cxsecurity.com/issue/WLB-2024040030	cxsecurity	vuln;	1	2024-04-14	MINIO < 2024-01-31-31T20-20-33Z 特权升级
28753	Casdoor <  v1.331.0 /api/set-password CSRF	https://cxsecurity.com/issue/WLB-2024040031	cxsecurity	vuln;	1	2024-04-14	卡斯门 < v1.3311.0/api/set-password CSRF
28755	Access-Intelligence	http://www.ransomfeed.it/index.php?page=post_details&id_post=14224	ransomfeed	ransom;play;	1	2024-04-11	访问-情报机构
28756	ezeldsolutionscom	http://www.ransomfeed.it/index.php?page=post_details&id_post=14225	ransomfeed	ransom;darkvault;	1	2024-04-11	ezeld溶解器
28758	taskhoundcom	http://www.ransomfeed.it/index.php?page=post_details&id_post=14227	ransomfeed	ransom;darkvault;	1	2024-04-11	任务houndcom
28759	lankacomnet	http://www.ransomfeed.it/index.php?page=post_details&id_post=14228	ransomfeed	ransom;darkvault;	1	2024-04-11	lankacomnet( 兰卡comnet)
28760	adachikancom	http://www.ransomfeed.it/index.php?page=post_details&id_post=14229	ransomfeed	ransom;darkvault;	1	2024-04-11	阿达奇坎康
28761	agribazaarcom	http://www.ransomfeed.it/index.php?page=post_details&id_post=14230	ransomfeed	ransom;darkvault;	1	2024-04-11	农业集市
28762	wexercom	http://www.ransomfeed.it/index.php?page=post_details&id_post=14231	ransomfeed	ransom;darkvault;	1	2024-04-11	韦xercom
28763	Missouri-Electric-Cooperatives	http://www.ransomfeed.it/index.php?page=post_details&id_post=14232	ransomfeed	ransom;akira;	1	2024-04-11	密密苏里-电子合作社
28764	hawkremotecom	http://www.ransomfeed.it/index.php?page=post_details&id_post=14234	ransomfeed	ransom;darkvault;	1	2024-04-11	鹰式远程
28765	hirebuscom	http://www.ransomfeed.it/index.php?page=post_details&id_post=14235	ransomfeed	ransom;darkvault;	1	2024-04-11	雇用公司
28766	Community-Alliance	http://www.ransomfeed.it/index.php?page=post_details&id_post=14236	ransomfeed	ransom;incransom;	1	2024-04-11	社区联盟
28767	Henningson--Snoxell-Ltd	http://www.ransomfeed.it/index.php?page=post_details&id_post=14237	ransomfeed	ransom;incransom;	1	2024-04-11	亨宁森 - - - - - - -
28768	LS-Networks	http://www.ransomfeed.it/index.php?page=post_details&id_post=14238	ransomfeed	ransom;play;	1	2024-04-11	LS 网络
28769	MoldTech	http://www.ransomfeed.it/index.php?page=post_details&id_post=14239	ransomfeed	ransom;play;	1	2024-04-11	MoldTech 摩尔多瓦
28770	Theatrixx-Technologies	http://www.ransomfeed.it/index.php?page=post_details&id_post=14240	ransomfeed	ransom;play;	1	2024-04-11	戏剧-技术
28771	New-England-Wooden-Ware	http://www.ransomfeed.it/index.php?page=post_details&id_post=14241	ransomfeed	ransom;play;	1	2024-04-11	新英格兰-沃登-西部
28772	The-MBTW-Group	http://www.ransomfeed.it/index.php?page=post_details&id_post=14242	ransomfeed	ransom;play;	1	2024-04-11	MBTW小组
28773	Gimex	http://www.ransomfeed.it/index.php?page=post_details&id_post=14243	ransomfeed	ransom;raworld;	1	2024-04-12	Gimex 金石
28774	Victor-Fauconnier	http://www.ransomfeed.it/index.php?page=post_details&id_post=14244	ransomfeed	ransom;raworld;	1	2024-04-12	维克多- 福康尼尔
28775	Unes	http://www.ransomfeed.it/index.php?page=post_details&id_post=14245	ransomfeed	ransom;raworld;	1	2024-04-12	未出现
28776	Alch	http://www.ransomfeed.it/index.php?page=post_details&id_post=14246	ransomfeed	ransom;raworld;	1	2024-04-12	平平层
28777	SebH	http://www.ransomfeed.it/index.php?page=post_details&id_post=14247	ransomfeed	ransom;raworld;	1	2024-04-12	塞布哈省
28778	baheyabeautycom	http://www.ransomfeed.it/index.php?page=post_details&id_post=14249	ransomfeed	ransom;darkvault;	1	2024-04-12	baheyabeautycom
28779	Hernando-County	http://www.ransomfeed.it/index.php?page=post_details&id_post=14250	ransomfeed	ransom;rhysida;	1	2024-04-12	埃尔南多州
28666	Sisense breach	https://threats.wiz.io/all-incidents/sisense-breach	wizio	incident;	1	2024-04-12	蓄意违反
28667	step-by-step walkthrough of an x86 assembly stack frame in action (exploit dev series to come)	https://buaq.net/go-234212.html	buaq	newscopy;	0	2024-04-15	一步步通过x86 组装堆叠框架的动作( 开发 Dev 序列 )
28671	派早报：商务部推动数字消费提升、消费品以旧换新	https://buaq.net/go-234225.html	buaq	newscopy;	0	2024-04-15	派早报：商务部推动数字消费提升、消费品以旧换新
28672	美国政府与卡巴斯基的恩怨情仇：间谍活动、克格勃、国家安全局和爱德华·斯诺登的悠久历史	https://buaq.net/go-234227.html	buaq	newscopy;	0	2024-04-15	美国政府与卡巴斯基的恩怨情仇：间谍活动、克格勃、国家安全局和爱德华·斯诺登的悠久历史
28676	币圈大跌时的常见案例：有投资者爆仓后损失114万美元 几乎破产	https://buaq.net/go-234231.html	buaq	newscopy;	0	2024-04-15	币圈大跌时的常见案例：有投资者爆仓后损失114万美元 几乎破产
28680	App+1 | 功能强大的录屏与编辑工具，而且免费：Screenity	https://buaq.net/go-234235.html	buaq	newscopy;	0	2024-04-15	App+1 | 功能强大的录屏与编辑工具，而且免费：Screenity
28683	新发现，37% 的公开共享文件正在泄露敏感信息	https://buaq.net/go-234238.html	buaq	newscopy;	0	2024-04-15	新发现，37% 的公开共享文件正在泄露敏感信息
28684	解除付费墙扩展BPC再次收到DMCA被删库 继续更新但开源社区被摧毁	https://buaq.net/go-234242.html	buaq	newscopy;	0	2024-04-15	解除付费墙扩展BPC再次收到DMCA被删库 继续更新但开源社区被摧毁
28714	Red Hat Security Advisory 2024-1787-03	https://packetstormsecurity.com/files/178028/RHSA-2024-1787-03.txt	packetstorm	vuln;;	1	2024-04-12	2024-1787-03红色帽子安保咨询
28715	Red Hat Security Advisory 2024-1789-03	https://packetstormsecurity.com/files/178029/RHSA-2024-1789-03.txt	packetstorm	vuln;;	1	2024-04-12	2024-1789-03红色帽子安保咨询
28719	Ubuntu Security Notice USN-6727-2	https://packetstormsecurity.com/files/178033/USN-6727-2.txt	packetstorm	vuln;;	1	2024-04-12	Ubuntu Ubuntu 安全通知 USN-6727-2
28721	Ubuntu Security Notice USN-6729-1	https://packetstormsecurity.com/files/178035/USN-6729-1.txt	packetstorm	vuln;;	1	2024-04-12	Ubuntu Ubuntu 安全通知 USN-6729-1
28781	Robeson-County-Sheriffs-Office-	http://www.ransomfeed.it/index.php?page=post_details&id_post=14252	ransomfeed	ransom;ransomhub;	1	2024-04-12	罗伯逊县警长办公室
28782	Agate-Construction	http://www.ransomfeed.it/index.php?page=post_details&id_post=14253	ransomfeed	ransom;play;	1	2024-04-12	A门建筑
28783	Notions-Marketing	http://www.ransomfeed.it/index.php?page=post_details&id_post=14254	ransomfeed	ransom;hunters;	1	2024-04-12	贴现标记
28784	Jordanos-Inc	http://www.ransomfeed.it/index.php?page=post_details&id_post=14255	ransomfeed	ransom;hunters;	1	2024-04-12	约旦c
28785	Bojangles-International	http://www.ransomfeed.it/index.php?page=post_details&id_post=14256	ransomfeed	ransom;hunters;	1	2024-04-12	国际博琼格勒斯国际
28786	Snchez-Betances-Sifre--Muoz-Noya	http://www.ransomfeed.it/index.php?page=post_details&id_post=14257	ransomfeed	ransom;akira;	1	2024-04-12	桑切斯 - 贝坦斯 - 西弗瑞 - 穆斯 - 诺亚
28787	Feldstein--Stewart	http://www.ransomfeed.it/index.php?page=post_details&id_post=14258	ransomfeed	ransom;play;	1	2024-04-12	费尔德斯坦 - 斯特瓦特
28788	H-C	http://www.ransomfeed.it/index.php?page=post_details&id_post=14259	ransomfeed	ransom;play;	1	2024-04-12	H-C
28789	oraclecmscom	http://www.ransomfeed.it/index.php?page=post_details&id_post=14260	ransomfeed	ransom;lockbit3;	1	2024-04-12	orececemscom 缩略语
28790	thspcouk	http://www.ransomfeed.it/index.php?page=post_details&id_post=14261	ransomfeed	ransom;darkvault;	1	2024-04-12	thsspcouk 缩略语
28791	tommyclubcouk	http://www.ransomfeed.it/index.php?page=post_details&id_post=14262	ransomfeed	ransom;darkvault;	1	2024-04-12	汤姆·库布库克(Tom My clububcouk)
28792	Solano-County-Library-	http://www.ransomfeed.it/index.php?page=post_details&id_post=14263	ransomfeed	ransom;medusa;	1	2024-04-13	索拉诺 -考特 -利布拉里
28793	Alliance-Mercantile	http://www.ransomfeed.it/index.php?page=post_details&id_post=14264	ransomfeed	ransom;medusa;	1	2024-04-13	联盟 -- -- 雇佣军
28794	Novus-International	http://www.ransomfeed.it/index.php?page=post_details&id_post=14265	ransomfeed	ransom;medusa;	1	2024-04-13	十一、国际
28795	Toyota-Brazil	http://www.ransomfeed.it/index.php?page=post_details&id_post=14266	ransomfeed	ransom;hunters;	1	2024-04-13	丰田- 巴西
28797	Caxton-and-CTP-Publishers-and-Printers	http://www.ransomfeed.it/index.php?page=post_details&id_post=14268	ransomfeed	ransom;hunters;	1	2024-04-13	Caxton和CTP-Publishers和Printers 计算机和计算机
28798	NanoLumens	http://www.ransomfeed.it/index.php?page=post_details&id_post=14269	ransomfeed	ransom;hunters;	1	2024-04-13	纳米
28799	Integrated-Control	http://www.ransomfeed.it/index.php?page=post_details&id_post=14270	ransomfeed	ransom;hunters;	1	2024-04-13	综合控制
28800	Frederick-Wildman-and-Sons	http://www.ransomfeed.it/index.php?page=post_details&id_post=14271	ransomfeed	ransom;hunters;	1	2024-04-13	弗雷德里克·维尔德曼和松
28801	disbdcgov	http://www.ransomfeed.it/index.php?page=post_details&id_post=14272	ransomfeed	ransom;lockbit3;	1	2024-04-13	dibdcgov 省
28802	countryvillahealthcom	http://www.ransomfeed.it/index.php?page=post_details&id_post=14273	ransomfeed	ransom;lockbit3;	1	2024-04-13	国家卫生中心
28803	Omni-Hotels--Resorts--US	http://www.ransomfeed.it/index.php?page=post_details&id_post=14274	ransomfeed	ransom;daixin;	1	2024-04-14	奥姆尼-霍特尔斯-Resorts-US
28805	Jack-Doheny-Company	http://www.ransomfeed.it/index.php?page=post_details&id_post=14276	ransomfeed	ransom;hunters;	1	2024-04-14	杰克多尼公会
28806	Sevcom	http://www.ransomfeed.it/index.php?page=post_details&id_post=14277	ransomfeed	ransom;cloak;	1	2024-04-14	Sevcom 网络
28807	qintcombr	http://www.ransomfeed.it/index.php?page=post_details&id_post=14278	ransomfeed	ransom;darkvault;	1	2024-04-15	qintcombr
28808	ndpapercom	http://www.ransomfeed.it/index.php?page=post_details&id_post=14279	ransomfeed	ransom;lockbit3;	1	2024-04-15	后页纸
28722	Terratec dmx_6fire USB 1.23.0.02 Unquoted Service Path	https://packetstormsecurity.com/files/178036/terratecdmx6fireusb123002-unquotedpath.txt	packetstorm	vuln;;	1	2024-04-12	Terratec dmx_6fire USB 1.23.0.02 无引用服务路径
28738	A Finance Journalist Fell Victim to a $50K Vishing Scam – Are You Also at Risk?	https://www.mcafee.com/blogs/internet-security/a-finance-journalist-fell-victim-to-a-50k-vishing-scam-are-you-also-at-risk/	mcafee	news;Internet Security;	1	2024-04-11	金融记者在50K Vishing Scam的“50K Vishing Scam ” ( $50K Vishing Scam)中遭金融记者袭击的受害者 — — 你还有风险吗?
28750	Terratec dmx_6fire USB 1.23.0.02 Unquoted Service Path	https://cxsecurity.com/issue/WLB-2024040028	cxsecurity	vuln;	1	2024-04-14	Terratec dmx_6fire USB 1.23.0.02 无引用服务路径
28757	zanebenefitscom	http://www.ransomfeed.it/index.php?page=post_details&id_post=14226	ransomfeed	ransom;darkvault;	1	2024-04-11	zane bewellscom( zane effectscom) 和 zane effectscom( zane effectscom) 和 zane effectscom
28780	MCP-GROUP-Commercial-Contractor-Topeka	http://www.ransomfeed.it/index.php?page=post_details&id_post=14251	ransomfeed	ransom;blacksuit;	1	2024-04-12	MCP-GROUP-商业-承包商-Topeka
28796	Kablutronik-SRL	http://www.ransomfeed.it/index.php?page=post_details&id_post=14267	ransomfeed	ransom;hunters;	1	2024-04-13	卡布卢特罗尼克-SRL
28804	Traverse-City-Area-Public-Schools-	http://www.ransomfeed.it/index.php?page=post_details&id_post=14275	ransomfeed	ransom;medusa;	1	2024-04-14	Travers-City-Area-Public-schools-学校-城市-地区-公立学校-
28893	企业出海场景下的数据跨境合规思考	https://buaq.net/go-234246.html	buaq	newscopy;	0	2024-04-15	企业出海场景下的数据跨境合规思考
28896	SASE：保护数据安全的零信任范式	https://buaq.net/go-234249.html	buaq	newscopy;	0	2024-04-15	SASE：保护数据安全的零信任范式
28897	SD-WAN与SDP-SASE框架下数控分离最佳实践	https://buaq.net/go-234250.html	buaq	newscopy;	0	2024-04-15	SD-WAN与SDP-SASE框架下数控分离最佳实践
28902	Step-by-Step Buffer Overflow Exploitation (followup to the x86 assembly stack frame video)	https://buaq.net/go-234255.html	buaq	newscopy;	0	2024-04-15	分步制缓冲过流开发(X86组装堆叠框架视频的后续活动)
28903	移动应用安全合规动态：网信办、金管局发文强调数据安全  3月个人信息违规抽查结果出炉（第五期）	https://buaq.net/go-234256.html	buaq	newscopy;	0	2024-04-15	移动应用安全合规动态：网信办、金管局发文强调数据安全 3月个人信息违规抽查结果出炉（第五期）
28904	Arch Linux 2024 项目负责人选举结果	https://buaq.net/go-234261.html	buaq	newscopy;	0	2024-04-15	Arch Linux 2024 项目负责人选举结果
28905	280 万用户受影响！加拿大零售连锁巨头 GIANT TIGER 遭数据泄露	https://buaq.net/go-234262.html	buaq	newscopy;	0	2024-04-15	280 万用户受影响！加拿大零售连锁巨头 GIANT TIGER 遭数据泄露
28906	为什么我们容易受骗？	https://buaq.net/go-234264.html	buaq	newscopy;	0	2024-04-15	为什么我们容易受骗？
28907	我们如何感知苦味？	https://buaq.net/go-234265.html	buaq	newscopy;	0	2024-04-15	我们如何感知苦味？
28908	谷歌浏览器将提供麦克风/摄像头预览 在进行视频会议前提前看看自己	https://buaq.net/go-234266.html	buaq	newscopy;	0	2024-04-15	谷歌浏览器将提供麦克风/摄像头预览 在进行视频会议前提前看看自己
28909	微软继续发布注册表更新缓解英特尔CPU中的漏洞 启用后会降低性能	https://buaq.net/go-234267.html	buaq	newscopy;	0	2024-04-15	微软继续发布注册表更新缓解英特尔CPU中的漏洞 启用后会降低性能
28910	发布三天后iGBA模拟器被苹果下架 被指不仅为山寨版而且还有版权问题	https://buaq.net/go-234268.html	buaq	newscopy;	0	2024-04-15	发布三天后iGBA模拟器被苹果下架 被指不仅为山寨版而且还有版权问题
28911	微软将部分市场的Xbox订阅限制为13个月 应该是被薅羊毛薅怕了	https://buaq.net/go-234269.html	buaq	newscopy;	0	2024-04-15	微软将部分市场的Xbox订阅限制为13个月 应该是被薅羊毛薅怕了
28912	U.S. and Australian police arrested Firebird RAT author and operator	https://buaq.net/go-234271.html	buaq	newscopy;	0	2024-04-15	美国和澳大利亚警方逮捕了Firebirbird RAT的作者和操作员
28935	ShadowDragon Horizon enhancements help users conduct investigations from any device	https://www.helpnetsecurity.com/2024/04/15/shadowdragon-horizon/	helpnetsecurity	news;Industry news;ShadowDragon;	1	2024-04-15	阴影龙地平线增强帮助用户从任何设备中进行调查
28954	kruxton-1.0 FileUpload-RCE	https://www.nu11secur1ty.com/2024/04/kruxton-10-fileupload-rce.html	nu11security	vuln;	1	2024-04-15	kruxton- 1.0 文件上加载- RCE
29134	关键基础设施安全资讯周报20240415期	https://buaq.net/go-234273.html	buaq	newscopy;	0	2024-04-15	关键基础设施安全资讯周报20240415期
29135	《未成年人网络保护条例》的出台背景、关键特征与未来展望	https://buaq.net/go-234274.html	buaq	newscopy;	0	2024-04-15	《未成年人网络保护条例》的出台背景、关键特征与未来展望
29258	compagniedephalsbourgcom	http://www.ransomfeed.it/index.php?page=post_details&id_post=14281	ransomfeed	ransom;threeam;	1	2024-04-15	经济、社会、文化权利委员会
29264	Palo Alto Networks Releases Urgent Fixes for Exploited PAN-OS Vulnerability	https://thehackernews.com/2024/04/palo-alto-networks-releases-urgent.html	feedburner	news;	1	2024-04-15	Palo Alto网络释放被利用的PAN-OS脆弱性紧急解决办法
29281	“All your base are belong to us” – A probe into Chinese-connected devices in US networks	https://malpedia.caad.fkie.fraunhofer.de/library/073b7f79-9b6a-4efa-a902-cb3f90c5973a/	fraunhofer	incident;	4	2024-04-15	“你们所有的基地都属于我们 ” — — 调查美国网络中与中国连通的装置。
29282	Gafgyt Backdoor Analysis	https://malpedia.caad.fkie.fraunhofer.de/library/0c48b427-d712-4af1-be82-e58adee450c6/	fraunhofer	incident;	1	2024-04-15	Gafgyt 后门分析
29283	XZ Backdoor: How to check if your systems are affected	https://malpedia.caad.fkie.fraunhofer.de/library/1fe2caba-454c-4e97-904d-5320aa4ff507/	fraunhofer	incident;	1	2024-04-15	XZ 后门: 如何检查您的系统是否受到影响
29284	Latrodectus: This Spider Bytes Like Ice	https://malpedia.caad.fkie.fraunhofer.de/library/232adb98-e6fe-4736-8118-d11536949b71/	fraunhofer	incident;	1	2024-04-15	挂图 : 这个像冰一样的蜘蛛字节
29285	TLS Certificate For Threat Intelligence - Identifying MatanBuchus Domains Through Hardcoded Certificate Values	https://malpedia.caad.fkie.fraunhofer.de/library/23760c9c-bb2b-4642-98f3-9ba113703182/	fraunhofer	incident;	1	2024-04-15	TLS 威胁情报证书 - 通过硬编码证书值识别 MatanBuchus 域名
29286	Automating Pikabot’s String Deobfuscation	https://malpedia.caad.fkie.fraunhofer.de/library/454f93bd-5844-4201-99ed-59fc98027ed6/	fraunhofer	incident;	1	2024-04-15	自动化 Pikabot 的字符串脱腐脱
29287	XZ Utils Backdoor Research Report CVE-2024-3094	https://malpedia.caad.fkie.fraunhofer.de/library/4b6b579a-f3e9-4ad8-b37c-d12ddae41430/	fraunhofer	incident;	3	2024-04-15	CVE-2024-3094 CVE-2024-3094号后门研究报告
29288	Microsoft still unsure how hackers stole MSA key in 2023 Exchange attack	https://malpedia.caad.fkie.fraunhofer.de/library/4fc51487-4db1-4eea-985e-5d91caa1c69c/	fraunhofer	incident;	1	2024-04-15	微软仍然不确定黑客如何窃取2023年 汇兑袭击的 MSA钥匙
29289	[QuickNote] Phishing email distributes WarZone RAT via DBatLoader	https://malpedia.caad.fkie.fraunhofer.de/library/74ac2102-84b4-4d53-8616-e2214ae87cf6/	fraunhofer	incident;	1	2024-04-15	[快速注 搜索电子邮件通过DBat Loader分发战区RAT
29290	The New Version Of JsOutProx Is Attacking Financial Institutions In APAC And MENA Via GitLab Abuse	https://malpedia.caad.fkie.fraunhofer.de/library/7c56b505-b998-49d8-af2d-510b0c575d53/	fraunhofer	incident;	1	2024-04-15	在APAC和MENA中,JsoutProx攻击金融机构的新版本和MENA Via GitLab虐待
29291	Security Brief: TA547 Targets German Organizations with Rhadamanthys Stealer	https://malpedia.caad.fkie.fraunhofer.de/library/87be793d-4abd-45df-b747-d7900a52d45f/	fraunhofer	incident;	1	2024-04-15	安全简报:TA547针对有Rhadamanthys偷窃者的德国组织
29292	Earth Freybug Uses UNAPIMON for Unhooking Critical APIs	https://malpedia.caad.fkie.fraunhofer.de/library/99bb1f78-1ce0-4154-a1d6-fbadad0d49f0/	fraunhofer	incident;	1	2024-04-15	用于打开关键动保单的UNAPIMON
29293	IcedID – Technical Analysis of an IcedID Lightweight x64 DLL	https://malpedia.caad.fkie.fraunhofer.de/library/a2778bdd-6e9a-4ac2-a085-46a344ef55a5/	fraunhofer	incident;	1	2024-04-15	IcedID - IcedID 轻度重量x64 DLL的技术分析
29294	Cutting Edge, Part 4: Ivanti Connect Secure VPN Post-Exploitation Lateral Movement Case Studies	https://malpedia.caad.fkie.fraunhofer.de/library/aa67bb2d-9de1-4547-b13d-3eec4b99b090/	fraunhofer	incident;	1	2024-04-15	切切边缘,第4部分:Ivanti连接安全VPN VPN
29295	The Early Bird Catches the Worm: Darktrace’s Hunt for Raspberry Robin	https://malpedia.caad.fkie.fraunhofer.de/library/ca921151-b402-4e0f-a57e-e1408f196f98/	fraunhofer	incident;	1	2024-04-15	早期鸟类捕捉虫虫:黑暗追逐捕草莓罗宾
29296	DarkBeatC2: The Latest MuddyWater Attack Framework	https://malpedia.caad.fkie.fraunhofer.de/library/d049eabe-7960-4d7d-bf46-a8d51fe2aa58/	fraunhofer	incident;	1	2024-04-15	DarkBeatC2:最新的湿地水攻击框架
29297	eXotic Visit campaign: Tracing the footprints of Virtual Invaders	https://malpedia.caad.fkie.fraunhofer.de/library/d2b34dea-b17c-47ed-887b-2ed1bc11ec00/	fraunhofer	incident;	1	2024-04-15	eXoic访问运动:追踪虚拟入侵者的足迹
29298	Raspberry Robin and its new anti-emulation trick	https://malpedia.caad.fkie.fraunhofer.de/library/d3f8627f-48b9-4415-b81b-fcd1effb982c/	fraunhofer	incident;	1	2024-04-15	Raspberry Robin 及其新的反模仿技巧
29299	The Mystery of ‘Jia Tan,’ the XZ Backdoor Mastermind	https://malpedia.caad.fkie.fraunhofer.de/library/e9a6b98b-7daf-45b9-a3d8-82fbc9dc2b45/	fraunhofer	incident;	1	2024-04-15	XZ后门万能魔术师 " Jia Tan " 的神秘
29300	Unveiling the Fallout: Operation Cronos' Impact on LockBit Following Landmark Disruption	https://malpedia.caad.fkie.fraunhofer.de/library/ea8c9b5f-c404-4740-a28f-d8ca78d200c7/	fraunhofer	incident;	2	2024-04-15	消除污染:克罗诺斯行动对LockBit的冲击
29301	特斯拉全球裁员10%	https://s.weibo.com/weibo?q=%23特斯拉全球裁员10%%23	sina.weibo	hotsearch;weibo	1	2024-04-15	特斯拉全球裁员10%
29377	绿盟科技威胁周报（2024.04.08-2024.04.14）	https://buaq.net/go-234278.html	buaq	newscopy;	0	2024-04-15	绿盟科技威胁周报（2024.04.08-2024.04.14）
29378	绿盟科技威胁周报（2024.04.01-2024.04.07）	https://buaq.net/go-234279.html	buaq	newscopy;	0	2024-04-15	绿盟科技威胁周报（2024.04.01-2024.04.07）
29379	城市漫步指南：初见山西，记住大同	https://buaq.net/go-234280.html	buaq	newscopy;	0	2024-04-15	城市漫步指南：初见山西，记住大同
29380	Using the LockBit builder to generate targeted ransomware	https://buaq.net/go-234282.html	buaq	newscopy;	0	2024-04-15	利用洛克比建筑商制作有目标的赎金软件
29424	kruxton-1.0-Multiple-SQLi	https://www.nu11secur1ty.com/2024/04/kruxton-10-multiple-sqli.html	nu11security	vuln;	1	2024-04-15	kruxton- 1.0- 多元- SQLi
29352	LightSpy Hackers Indian Apple Device Users to Steal Sensitive Data	https://gbhackers.com/lightspy-hackers-steal/	GBHacker	news;Apple;cyber security;Cyber Security News;Malware;	1	2024-04-15	偷盗敏感数据的印度苹果设备用户
29376	受国家支持的黑客正积极利用Palo Alto Networks 防火墙零日漏洞	https://buaq.net/go-234277.html	buaq	newscopy;	0	2024-04-15	受国家支持的黑客正积极利用Palo Alto Networks 防火墙零日漏洞
29504	绿盟科技威胁周报（2024.04.01-2024.04.07）	https://blog.nsfocus.net/weeklyreport202414/	绿盟	news;威胁通告;周报;威胁防护;	1	2024-04-15	绿盟科技威胁周报（2024.04.01-2024.04.07）
29505	绿盟科技威胁周报（2024.04.08-2024.04.14）	https://blog.nsfocus.net/weeklyreport202415/	绿盟	news;威胁通告;周报;威胁防护;	1	2024-04-15	绿盟科技威胁周报（2024.04.08-2024.04.14）
29506	Chinese-Linked LightSpy iOS Spyware Targets South Asian iPhone Users	https://thehackernews.com/2024/04/chinese-linked-lightspy-ios-spyware.html	feedburner	news;	5	2024-04-15	以中文链接的 LightSpy iOS Spyware 瞄准南亚iPhone用户
29517	Using the LockBit builder to generate targeted ransomware	https://securelist.com/lockbit-3-0-based-custom-targeted-ransomware/112375/	securelist	news;Malware descriptions;Data Encryption;Incident response;LockBit;Malware;Malware Technologies;Ransomware;Targeted attacks;Trojan;APT (Targeted attacks);Windows malware;	3	2024-04-15	利用洛克比建筑商制作有目标的赎金软件
29519	Another CVE (PAN-OS Zero-Day), Another Reason to Consider Zero Trust	https://securityboulevard.com/2024/04/another-cve-pan-os-zero-day-another-reason-to-consider-zero-trust/	securityboulevard	news;Security Bloggers Network;	3	2024-04-13	另一个CVE(PAN-OS零日),考虑零信任的另一个理由
29524	Linux Backdoor Infection Scare, Massive Social Security Number Heist	https://securityboulevard.com/2024/04/linux-backdoor-infection-scare-massive-social-security-number-heist/	securityboulevard	news;Application Security;Data Security;DevOps;Security Bloggers Network;Threats & Breaches;backdoor;Cyber Security;Cybersecurity;Data breach;Data Privacy;Digital Privacy;Episodes;government;Government Contractor;Hacking;Information Security;Infosec;Linux;open source;pii;Podcast;Podcasts;Privacy;security;sensitive data;Social Security Numbers;technology;Weekly Edition;XZ Utils;	1	2024-04-15	Linux 后门感染护理,大规模社会保障编号
29525	Scale Your Security with vCISO as a Service	https://securityboulevard.com/2024/04/scale-your-security-with-vciso-as-a-service/	securityboulevard	news;Security Bloggers Network;Cyber Security;Staffing Services;vCISO;vCISO as a service;	1	2024-04-15	以 vCISO 服务为服务来缩放您的安全级别
29617	【年度典型案例】扫码就能领补贴？通知社保在线速办？当心是钓鱼骗局	https://buaq.net/go-234283.html	buaq	newscopy;	0	2024-04-15	【年度典型案例】扫码就能领补贴？通知社保在线速办？当心是钓鱼骗局
29618	360揭“伏特台风”真相，推出安全云防勒索解决方案	https://buaq.net/go-234284.html	buaq	newscopy;	0	2024-04-15	360揭“伏特台风”真相，推出安全云防勒索解决方案
29619	AfuseKt – 安卓端在线视频播放器：阿里云盘、Alist、WebDAV、Emby、Jellyfin，自带刮削、海报墙	https://buaq.net/go-234285.html	buaq	newscopy;	0	2024-04-15	AfuseKt – 安卓端在线视频播放器：阿里云盘、Alist、WebDAV、Emby、Jellyfin，自带刮削、海报墙
29620	多家德国组织遭受网络攻击	https://buaq.net/go-234286.html	buaq	newscopy;	0	2024-04-15	多家德国组织遭受网络攻击
29621	新发现，37% 的公开共享文件正在泄露敏感信息	https://buaq.net/go-234287.html	buaq	newscopy;	0	2024-04-15	新发现，37% 的公开共享文件正在泄露敏感信息
29622	CISA 就 Sisense 数据泄露事件发出警告	https://buaq.net/go-234288.html	buaq	newscopy;	0	2024-04-15	CISA 就 Sisense 数据泄露事件发出警告
29623	腾讯云公布4月8日大范围故障原因 升级API产生兼容性问题并产生循环依赖	https://buaq.net/go-234289.html	buaq	newscopy;	0	2024-04-15	腾讯云公布4月8日大范围故障原因 升级API产生兼容性问题并产生循环依赖
29624	Zambia arrests 77 people in swoop on “scam” call centre	https://buaq.net/go-234290.html	buaq	newscopy;	0	2024-04-15	赞比亚逮捕了77名在“scam”呼叫中心潜伏的人。
29625	Black Basta Team e gli attacchi ransomware a doppia estorsione	https://buaq.net/go-234291.html	buaq	newscopy;	0	2024-04-15	黑色Basta小组 塔塔奇胶片勒索器 杜皮亚神庙
29626	Chinese-Linked LightSpy iOS Spyware Targets South Asian iPhone Users	https://buaq.net/go-234292.html	buaq	newscopy;	0	2024-04-15	以中文链接的 LightSpy iOS Spyware 瞄准南亚iPhone用户
29627	Palo Alto Networks Releases Urgent Fixes for Exploited PAN-OS Vulnerability	https://buaq.net/go-234293.html	buaq	newscopy;	0	2024-04-15	Palo Alto网络释放被利用的PAN-OS脆弱性紧急解决办法
29668	针对一道CS面试题样本的详细分析	https://xz.aliyun.com/t/14296	阿里先知实验室	news;	1	2024-04-15	针对一道CS面试题样本的详细分析
29677	The US Government Has a Microsoft Problem	https://www.wired.com/story/the-us-government-has-a-microsoft-problem/	wired	news;Security;Security / Cyberattacks and Hacks;Security / National Security;Security / Security News;	1	2024-04-15	美国政府有微软问题
29763	Zero-Day Exploitation of Unauthenticated Remote Code Execution Vulnerability in GlobalProtect (CVE-2024-3400)	https://malpedia.caad.fkie.fraunhofer.de/library/04ff0d25-e979-44ca-88ac-9c60baede5ee/	fraunhofer	incident;	3	2024-04-15	零日利用全球保护中未经认证的远程法规执行脆弱性(CVE-2024-3400)
29765	Resolving Stack Strings with Capstone Disassembler & Unicorn in Python	https://malpedia.caad.fkie.fraunhofer.de/library/12b18035-5ded-44dd-b9dc-bb1f83509139/	fraunhofer	incident;	1	2024-04-15	Python 用Capstone 拆解器和独角兽解决堆叠字符串
29782	Threat Brief: Operation MidnightEclipse, Post-Exploitation Activity Related to CVE-2024-3400	https://malpedia.caad.fkie.fraunhofer.de/library/f3f1b3d4-1aad-47ce-881a-bff67c399a69/	fraunhofer	incident;	3	2024-04-15	威胁简介:与CVE-2024-3400有关的 " 午夜日光行动 " 、与CVE-2024-3400有关的 " 开发后活动 " 。
29783	小米回应汽车没有高级空调功能	https://s.weibo.com/weibo?q=%23小米回应汽车没有高级空调功能%23	sina.weibo	hotsearch;weibo	1	2024-04-15	小米回应汽车没有高级空调功能
29859	【论文速读】| CovRL：基于覆盖引导的强化学习对LLM基础变异进行JavaScript引擎模糊测试	https://www.freebuf.com/articles/network/397813.html	freebuf	news;网络安全;	1	2024-04-12	【论文速读】| CovRL：基于覆盖引导的强化学习对LLM基础变异进行JavaScript引擎模糊测试
29784	Microsoft lifts Windows 11 block on some Intel systems after 2 years	https://www.bleepingcomputer.com/news/microsoft/microsoft-lifts-windows-11-block-on-some-intel-systems-after-2-years/	bleepingcomputer	news;Microsoft;	1	2024-04-15	微软在两年后提升一些英特系统 Windows 11 区块
29860	什么？远控程序被黑客利用了？	https://www.freebuf.com/articles/system/397790.html	freebuf	news;系统安全;	1	2024-04-12	什么？远控程序被黑客利用了？
29861	渗透学习第三天：Beelzebub：1靶场复现	https://www.freebuf.com/articles/web/397700.html	freebuf	news;Web安全;	1	2024-04-11	渗透学习第三天：Beelzebub：1靶场复现
29875	codeql学习笔记分享1	https://www.freebuf.com/sectool/397748.html	freebuf	news;工具;	1	2024-04-12	codeql学习笔记分享1
29876	实现“代码可视化”需要了解的前置知识-编译器前端	https://www.freebuf.com/sectool/397793.html	freebuf	news;工具;	1	2024-04-12	实现“代码可视化”需要了解的前置知识-编译器前端
29881	A critical vulnerability in Delinea Secret Server allows auth bypass, admin access	https://www.helpnetsecurity.com/2024/04/15/delinea-secret-server-vulnerability/	helpnetsecurity	news;Don't miss;Hot stuff;News;access management;Delinea;enterprise;PoC;privileged accounts;vulnerability;vulnerability disclosure;	1	2024-04-15	Delinea 秘密服务器的极易感染性 允许使用人工授精绕行 管理员访问
29882	eBook: Why CISSP?	https://www.helpnetsecurity.com/2024/04/15/ebook-why-cissp/	helpnetsecurity	news;Don't miss;News;certification;ISC2;skill development;Whitepapers and webinars;	1	2024-04-15	eBook:为什么是CISSP?
29980	Timing is Everything: The Role of Just-in-Time Privileged Access in Security Evolution	https://thehackernews.com/2024/04/timing-is-everything-role-of-just-in.html	feedburner	news;	1	2024-04-15	时机是一切:在安全演进中 " 近时有特权进入 " 的作用
29994	Vulnerable Villain: When Hackers Get Hacked 	https://securityboulevard.com/2024/04/vulnerable-villain-when-hackers-get-hacked/	securityboulevard	news;Security Bloggers Network;Blog;research;	1	2024-04-15	易受到伤害的恶灵:当黑客被黑客利用时
29998	Slicing up DoNex with Binary Ninja	https://malpedia.caad.fkie.fraunhofer.de/library/0dd8198d-974d-4af8-beb2-12b7ea08f4da/	fraunhofer	incident;	1	2024-04-15	使用二进制忍者将 DoNex 切除
30004	XZ Utils Backdoor | Threat Actor Planned to Inject Further Vulnerabilities	https://malpedia.caad.fkie.fraunhofer.de/library/57d0fa81-05a9-4787-8fef-e725e6a900ca/	fraunhofer	incident;	1	2024-04-15	XZ 后门UTLs 后门UTLs 威胁行为者 计划注射更多脆弱性
30005	Leak of Epsilon Stealer's source code	https://malpedia.caad.fkie.fraunhofer.de/library/610ad0a7-9530-4fd0-aa63-1f0c121230eb/	fraunhofer	incident;	1	2024-04-15	Eppsilon 偷窃者源代码的泄漏
30006	Rat King Configuration Parser	https://malpedia.caad.fkie.fraunhofer.de/library/70067313-4627-4527-8b9a-cd1e4e0afd08/	fraunhofer	incident;	1	2024-04-15	Rat King 配置剖析器
30014	Tracking Malicious Infrastructure With DNS Records - Vultur Banking Trojan	https://malpedia.caad.fkie.fraunhofer.de/library/e1a14366-bb10-439f-962e-602fc6d4cba9/	fraunhofer	incident;	1	2024-04-15	利用DNS记录追踪恶意基础设施 -- -- Vultur银行行队
30016	小米SU7碰撞测试	https://s.weibo.com/weibo?q=%23小米SU7碰撞测试%23	sina.weibo	hotsearch;weibo	1	2024-04-15	小米SU7碰撞测试
30026	Palo Alto Networks fixes zero-day exploited to backdoor firewalls	https://www.bleepingcomputer.com/news/security/palo-alto-networks-fixes-zero-day-exploited-to-backdoor-firewalls/	bleepingcomputer	news;Security;	1	2024-04-15	Palo Alto网络修补用于后门防火墙的零天防火墙
30041	Frameless-Bitb - A New Approach To Browser In The Browser (BITB) Without The Use Of Iframes, Allowing The Bypass Of Traditional Framebusters Implemented By Login Pages Like Microsoft And The Use With Evilginx	http://www.kitploit.com/2024/04/frameless-bitb-new-approach-to-browser.html	kitploit	tool;Frameless-Bitb;Scanners;Scripts;Subdomains;VMware;Windows;	1	2024-04-15	无框架- Bitb - 浏览器浏览器( BITB) 没有使用 Iframes 的新浏览器新方法, 允许使用像 Microsoft 这样的登录页和 与 Vilginx 一起使用 。
30079	派评 | 近期值得关注的 App	https://buaq.net/go-234303.html	buaq	newscopy;	0	2024-04-15	派评 | 近期值得关注的 App
30080	2024阿里云ctf-web-chain17学习	https://buaq.net/go-234304.html	buaq	newscopy;	0	2024-04-15	2024阿里云ctf-web-chain17学习
30081	Nuevo máster en Burp Professional para Hacking web	https://buaq.net/go-234307.html	buaq	newscopy;	0	2024-04-15	Nuevo máster en Burp 专业助理
30082	继美国后香港批准比特币/以太坊现货ETF 增强香港加密货币市场的吸引力	https://buaq.net/go-234309.html	buaq	newscopy;	0	2024-04-15	继美国后香港批准比特币/以太坊现货ETF 增强香港加密货币市场的吸引力
30083	Le aziende italiane peccano nella sicurezza degli ambienti OT	https://buaq.net/go-234310.html	buaq	newscopy;	0	2024-04-15	Le aziende italiane peccano nella sicurezza degli ambienti OT
30084	Timing is Everything: The Role of Just-in-Time Privileged Access in Security Evolution	https://buaq.net/go-234311.html	buaq	newscopy;	0	2024-04-15	时机是一切:在安全演进中 " 近时有特权进入 " 的作用
30085	Threat actors exploited Palo Alto Pan-OS issue to deploy a Python Backdoor	https://buaq.net/go-234313.html	buaq	newscopy;	0	2024-04-15	威胁行为体利用Palo Alto Pan-OS问题部署Python后门
30086	The 30-Day .NET Challenge - Day 24: How to Avoid Exceptions in Flow Control	https://buaq.net/go-234314.html	buaq	newscopy;	0	2024-04-15	30天网络挑战-24天:如何避免流动控制中的例外
30087	Intellectual Property Rights (IPR) in Crypto: Is Everything Free and Open?	https://buaq.net/go-234315.html	buaq	newscopy;	0	2024-04-15	《加密知识产权:一切是否自由开放?
30088	Vulnerable Villain: When Hackers Get Hacked	https://buaq.net/go-234321.html	buaq	newscopy;	0	2024-04-15	易受到伤害的恶灵:当黑客被黑客利用时
30089	【漏洞通告】Palo Alto Networks PAN-OS 命令注入漏洞CVE-2024-3400	https://buaq.net/go-234322.html	buaq	newscopy;	0	2024-04-15	【漏洞通告】Palo Alto Networks PAN-OS 命令注入漏洞CVE-2024-3400
30090	阿里云CTF2024-暴力ENOTYOURWORLD题解	https://buaq.net/go-234323.html	buaq	newscopy;	0	2024-04-15	阿里云CTF2024-暴力ENOTYOURWORLD题解
30091	知名防火墙厂商曝满分RCE漏洞，Palo Alto Networks警告漏洞正被利用	https://buaq.net/go-234324.html	buaq	newscopy;	0	2024-04-15	知名防火墙厂商曝满分RCE漏洞，Palo Alto Networks警告漏洞正被利用
30092	下一个系统开发高手就是你	https://buaq.net/go-234326.html	buaq	newscopy;	0	2024-04-15	下一个系统开发高手就是你
30119	Privacera  adds access control and data filtering functionality for Vector DB/RAG	https://www.helpnetsecurity.com/2024/04/15/privacera-ai-governance/	helpnetsecurity	news;Industry news;Privacera;	1	2024-04-15	Privacera为矢量 DB/RAG增加出入控制和数据过滤功能
30219	Enhancing Security and Reducing Costs with Advanced Zero Trust Implementation	https://securityboulevard.com/2024/04/enhancing-security-and-reducing-costs-with-advanced-zero-trust-implementation/	securityboulevard	news;Security Bloggers Network;Blog;Topic;	1	2024-04-15	加强安全和降低费用,采用 " 零信任 " 先进实施
30379	How Do You Manage Your Social Media Privacy?	https://www.mcafee.com/blogs/internet-security/how-do-you-manage-your-social-media-privacy/	mcafee	news;Internet Security;	1	2024-04-15	您如何管理社会媒体隐私?
30428	jeyesfluidcouk	http://www.ransomfeed.it/index.php?page=post_details&id_post=14282	ransomfeed	ransom;lockbit3;	1	2024-04-15	jewies fluidcouk (日元) (日元)
30429	Biggs-Cardosa-Associates	http://www.ransomfeed.it/index.php?page=post_details&id_post=14284	ransomfeed	ransom;blacksuit;	1	2024-04-15	Biggs-Cardosa协会
30430	The-Post-and-Courier	http://www.ransomfeed.it/index.php?page=post_details&id_post=14285	ransomfeed	ransom;blacksuit;	1	2024-04-15	后与后与后
30431	Best-Reward-Federal-Credit-Union	http://www.ransomfeed.it/index.php?page=post_details&id_post=14286	ransomfeed	ransom;akira;	1	2024-04-15	最佳奖励 -- -- 联邦 -- -- 信贷 -- -- 联盟
30432	LYON-TERMINAL	http://www.ransomfeed.it/index.php?page=post_details&id_post=14287	ransomfeed	ransom;8base;	1	2024-04-15	中 期 中 期 中 期 中 期
30436	AI Copilot: Launching Innovation Rockets, But Beware of the Darkness Ahead	https://thehackernews.com/2024/04/ai-copilot-launching-innovation-rockets.html	feedburner	news;	1	2024-04-15	AI : 发射创新火箭,但请注意黑暗前方
30442	Muddled Libra Shifts Focus to SaaS and Cloud for Extortion and Data Theft Attacks	https://thehackernews.com/2024/04/muddled-libra-shifts-focus-to-saas-and.html	feedburner	news;	1	2024-04-15	将焦点改为SaaS和云,用于勒索和数据盗窃攻击
30482	华为P70	https://s.weibo.com/weibo?q=%23华为P70%23	sina.weibo	hotsearch;weibo	1	2024-04-15	华为P70
30486	Chipmaker Nexperia confirms breach after ransomware gang leaks data	https://www.bleepingcomputer.com/news/security/chipmaker-nexperia-confirms-breach-after-ransomware-gang-leaks-data/	bleepingcomputer	news;Security;	2	2024-04-15	芯片制造者Nexeria确认 在赎金软件 黑帮泄漏数据后违约
30488	Crypto miner arrested for skipping on $3.5 million in cloud server bills	https://www.bleepingcomputer.com/news/security/crypto-miner-arrested-for-skipping-on-35-million-in-cloud-server-bills/	bleepingcomputer	news;Security;CryptoCurrency;Legal;	1	2024-04-15	加密矿工因在云端服务器账单上跳过350万美元而被捕
30587	Jenkins 2.441 Local File Inclusion	https://packetstormsecurity.com/files/178047/jenkins2441-lfi.txt	packetstorm	vuln;;	1	2024-04-15	Jenkins 2.441 本地档案融入
30588	Red Hat Security Advisory 2024-1803-03	https://packetstormsecurity.com/files/178048/RHSA-2024-1803-03.txt	packetstorm	vuln;;	1	2024-04-15	红帽子安保咨询 2024-1803-03
30589	Red Hat Security Advisory 2024-1804-03	https://packetstormsecurity.com/files/178049/RHSA-2024-1804-03.txt	packetstorm	vuln;;	1	2024-04-15	红帽子安保咨询2024-1804-03
30590	Django REST Framework SimpleJWT 5.3.1 Information Disclosure	https://packetstormsecurity.com/files/178050/drfwsjwt531-disclose.txt	packetstorm	vuln;;	1	2024-04-15	Django REST框架简单JWT 5.3.1 信息披露
30591	Moodle 3.10.1 SQL Injection	https://packetstormsecurity.com/files/178051/moodle3101-sql.txt	packetstorm	vuln;;	1	2024-04-15	Moodle 3.10.1 SQL 注射
30592	Red Hat Security Advisory 2024-1812-03	https://packetstormsecurity.com/files/178052/RHSA-2024-1812-03.txt	packetstorm	vuln;;	1	2024-04-15	红帽子安保咨询2024-1812-03
30593	PrusaSlicer 2.6.1 Arbitrary Code Execution	https://packetstormsecurity.com/files/178053/prusaslicer261-exec.txt	packetstorm	vuln;;	1	2024-04-15	2.6.1 任意处决
30594	Debian Security Advisory 5657-1	https://packetstormsecurity.com/files/178054/dsa-5657-1.txt	packetstorm	vuln;;	1	2024-04-15	Debian安全咨询 5657-1
30595	AMPLE BILLS 0.1 SQL injection	https://packetstormsecurity.com/files/178055/amplebills01-sql.txt	packetstorm	vuln;;	1	2024-04-15	AMPLE BILLS 0.1 SQL 注入
30596	WBCE 1.6.0 SQL Injection	https://packetstormsecurity.com/files/178056/wbce160-sql.txt	packetstorm	vuln;;	1	2024-04-15	WBCE 1.6.0 SQL 注射
30492	New SteganoAmor attacks use steganography to target 320 orgs globally	https://www.bleepingcomputer.com/news/security/new-steganoamor-attacks-use-steganography-to-target-320-orgs-globally/	bleepingcomputer	news;Security;	1	2024-04-15	新的SteganoAmor攻击在全球320个目标对象使用血清成像法
30495	Ransomware gang starts leaking alleged stolen Change Healthcare data	https://www.bleepingcomputer.com/news/security/ransomware-gang-starts-leaking-alleged-stolen-change-healthcare-data/	bleepingcomputer	news;Security;	2	2024-04-15	Ransomware帮开始泄漏 指称被盗的更改医疗数据
30498	Cisco Duo's Multifactor Authentication Service Breached	https://www.darkreading.com/cyberattacks-data-breaches/cisco-duo-multifactor-authentication-service-breached	darkreading	news;	1	2024-04-15	Cisco Duo 的多要素认证服务
30500	Roku Mandates 2FA for Customers After Credential-Stuffing Compromise	https://www.darkreading.com/cyberattacks-data-breaches/roku-mandates-2fa-for-customers-after-credential-stuffing-compromise	darkreading	news;	1	2024-04-15	Roku 授权2FA, 用于在持证后进行交易的客户
30501	Web3 Game Developers Targeted in Crypto Theft Scheme	https://www.darkreading.com/cyberattacks-data-breaches/russian-actor-targets-web3-game-developers-with-infostealers	darkreading	news;	1	2024-04-15	Web3 在加密搜索计划中锁定的游戏开发者
30503	Defense Award Launches Purdue Project to Strengthen Cyber-Physical Systems	https://www.darkreading.com/cybersecurity-operations/defense-award-launches-purdue-project-to-strengthen-cyber-physical-systems	darkreading	news;	1	2024-04-15	加强网络物理系统项目
30505	Iran-Backed Hackers Blast Out Threatening Texts to Israelis	https://www.darkreading.com/endpoint-security/iran-backed-hackers-blast-out-threatening-texts-to-israelis	darkreading	news;	3	2024-04-15	向以色列人发出的伊朗黑客黑客爆炸威胁短信
30509	Microsoft Wants You to Watch What It Says, Not What It Does	https://www.darkreading.com/vulnerabilities-threats/microsoft-wants-you-to-watch-what-it-says-not-what-it-does	darkreading	news;	1	2024-04-15	Microsoft Wants You to Watch What It Says, Not What It Does
30523	You Really Are Being Surveilled All the Time	https://blog.knowbe4.com/you-really-are-being-surveilled-all-the-time	knowbe4	news;Phishing;	1	2024-04-15	你真的一直都在被救赎
30526	Hacker Customize LockBit 3.0 Ransomware to Attack Orgs Worldwide	https://gbhackers.com/hacker-customize-lockbit-3-0-ransomware-to-attack-orgs-worldwide/	GBHacker	news;Cyber Attack;Cyber Crime;cyber security;Cyber Security News;Malware;	3	2024-04-15	Hacker 定制 LockBit 3. 0 用于攻击全球猎兽的Ransomware
30530	Microsoft .NET, .NET Framework, & Visual Studio Vulnerable To RCE Attacks	https://gbhackers.com/microsoft-net-rce-vulnerability/	GBHacker	news;CVE/vulnerability;Cyber Security News;Microsoft;CVE-2024-21409;Microsoft security;Remote code execution;	1	2024-04-15	微软.NET、.NET框架、以及易受RCE攻击的视觉演播室
30535	New SteganoAmor attacks use steganography to target 320 orgs globally	https://buaq.net/go-234415.html	buaq	newscopy;	0	2024-04-16	新的SteganoAmor攻击在全球320个目标对象使用血清成像法
30536	Cisco: Hacker breached multifactor authentication message provider on April 1	https://buaq.net/go-234416.html	buaq	newscopy;	0	2024-04-16	Cisco: 4月1日, Hacker 违反多要素认证信件提供商
30537	Amid Escalating Iran-Israel Conflict, Understanding the Hybrid Nature of Cyber Threats	https://buaq.net/go-234417.html	buaq	newscopy;	0	2024-04-16	理解网络威胁的混合性质
30538	Amazon AWS Glue Database Password Disclosure	https://buaq.net/go-234422.html	buaq	newscopy;	0	2024-04-16	Amazon AWS 粘胶数据库密码披露
30539	OpenClinic GA 5.247.01 Path Traversal (Authenticated)	https://buaq.net/go-234423.html	buaq	newscopy;	0	2024-04-16	OpenClinic GA 5.247.01 Traversal 路径(经核准)
30540	PrusaSlicer 2.6.1 Arbitrary Code Execution	https://buaq.net/go-234424.html	buaq	newscopy;	0	2024-04-16	2.6.1 任意处决
30541	AMPLE BILLS 0.1 SQL injection	https://buaq.net/go-234425.html	buaq	newscopy;	0	2024-04-16	AMPLE BILLS 0.1 SQL 注入
30542	kruxton-1.0-Multiple-SQLi	https://buaq.net/go-234426.html	buaq	newscopy;	0	2024-04-16	kruxton- 1.0- 多元- SQLi
30544	Jenkins 2.441 Local File Inclusion	https://buaq.net/go-234428.html	buaq	newscopy;	0	2024-04-16	Jenkins 2.441 本地档案融入
30545	Cisco Duo warns telephony supplier data breach exposed MFA SMS logs	https://buaq.net/go-234429.html	buaq	newscopy;	0	2024-04-16	Cisco Duo警告电话供应商数据被破解时,
30546	Nebraska man allegedly defrauded cloud providers of millions via cryptojacking	https://buaq.net/go-234437.html	buaq	newscopy;	0	2024-04-16	据称内布拉斯加人通过窃听密码 诈骗了数百万的云源
30547	Ransomware gang starts leaking alleged stolen Change Healthcare data	https://buaq.net/go-234438.html	buaq	newscopy;	0	2024-04-16	Ransomware帮开始泄漏 指称被盗的更改医疗数据
30548	Moodle 3.10.1 SQL Injection	https://buaq.net/go-234440.html	buaq	newscopy;	0	2024-04-16	Moodle 3.10.1 SQL 注射
30550	What Game Art Styles Will Dominate the Mobile Industry in 2024?	https://buaq.net/go-234442.html	buaq	newscopy;	0	2024-04-16	2024年,什么游戏艺术风格 将终结移动工业?
30551	Using T-tests for Abnormal Data in AB Testing	https://buaq.net/go-234443.html	buaq	newscopy;	0	2024-04-16	在AB 测试中使用异常数据的 T 测试
30552	Exploring the Intersection of Data Science and Cyber Security: Insights and Applications	https://buaq.net/go-234444.html	buaq	newscopy;	0	2024-04-16	探讨数据科学和网络安全交叉问题:观察和应用
30554	D3 Security at RSAC 2024: Streamline Your Security Operations with Smart SOAR	https://buaq.net/go-234449.html	buaq	newscopy;	0	2024-04-16	RSAC 2024年RSAC的D3安保:以智能SOAR精简您的安保行动
30557	OWASP发布10大开源软件风险清单	https://www.freebuf.com/articles/network/397888.html	freebuf	news;网络安全;	1	2024-04-14	OWASP发布10大开源软件风险清单
30584	Red Hat Security Advisory 2024-1800-03	https://packetstormsecurity.com/files/178044/RHSA-2024-1800-03.txt	packetstorm	vuln;;	1	2024-04-15	红色帽子安保咨询2024-1800-03
30585	Red Hat Security Advisory 2024-1801-03	https://packetstormsecurity.com/files/178045/RHSA-2024-1801-03.txt	packetstorm	vuln;;	1	2024-04-15	红色帽子安保咨询 2024-1801-03
30586	Red Hat Security Advisory 2024-1802-03	https://packetstormsecurity.com/files/178046/RHSA-2024-1802-03.txt	packetstorm	vuln;;	1	2024-04-15	红色帽子安保咨询 2024-1802-03
30597	Kruxton 1.0 Shell Upload	https://packetstormsecurity.com/files/178057/kruxton10-shell.txt	packetstorm	vuln;;	1	2024-04-15	Kruxton 1.0 壳牌上传
30598	Kruxton 1.0 SQL Injection	https://packetstormsecurity.com/files/178058/kruxton10-sql.txt	packetstorm	vuln;;	1	2024-04-15	Kruxton 1.0 SQL 注射
30600	Debian Security Advisory 5658-1txt	https://packetstormsecurity.com/files/178060/dsa-5658-1txt	packetstorm	vuln;;	1	2024-04-15	Debian安保咨询 5658-1Txt
30601	WordPress WP Video Playlist 1.1.1 Cross Site Scripting	https://packetstormsecurity.com/files/178061/wpvideoplaylist111-xss.txt	packetstorm	vuln;;	1	2024-04-15	Wordpress WP 视频播放列表 1.1.1 跨站点脚本
30602	GLPI 10.x.x Remote Command Execution	https://packetstormsecurity.com/files/178062/glpi10-exec.tgz	packetstorm	vuln;;	1	2024-04-15	GLPI 10.x.x 远程指令执行
30603	Ubuntu Security Notice USN-6731-1	https://packetstormsecurity.com/files/178063/USN-6731-1.txt	packetstorm	vuln;;	1	2024-04-15	Ubuntu Untuntu 安全通知 USN-6731-1
30604	OpenSSH 8 Password Backdoor	https://packetstormsecurity.com/files/178064/openssh8_trojanned.zip	packetstorm	vuln;;	1	2024-04-15	OpenSSH 8 密码后门
30605	Debian Security Advisory 5659-1	https://packetstormsecurity.com/files/178065/dsa-5659-1.txt	packetstorm	vuln;;	1	2024-04-15	Debian安全咨询 5659-1
30606	American Fuzzy Lop plus plus 4.20c	https://packetstormsecurity.com/files/178066/AFLplusplus-4.20c.tar.gz	packetstorm	vuln;;	1	2024-04-15	美国模糊Lop+4.20c
30608	Amazon AWS Glue Database Password Disclosure	https://packetstormsecurity.com/files/178068/SA-20240411-0.txt	packetstorm	vuln;;	1	2024-04-15	Amazon AWS 粘胶数据库密码披露
30628	Jenkins 2.441 Local File Inclusion	https://cxsecurity.com/issue/WLB-2024040035	cxsecurity	vuln;	1	2024-04-15	Jenkins 2.441 本地档案融入
30636	Moodle 3.10.1 SQL Injection	https://cxsecurity.com/issue/WLB-2024040034	cxsecurity	vuln;	1	2024-04-15	Moodle 3.10.1 SQL 注射
30637	Django REST Framework SimpleJWT 5.3.1 Information Disclosure	https://cxsecurity.com/issue/WLB-2024040036	cxsecurity	vuln;	1	2024-04-15	Django REST框架简单JWT 5.3.1 信息披露
30638	kruxton-1.0-Multiple-SQLi	https://cxsecurity.com/issue/WLB-2024040037	cxsecurity	vuln;	1	2024-04-15	kruxton- 1.0- 多元- SQLi
30639	AMPLE BILLS 0.1 SQL injection	https://cxsecurity.com/issue/WLB-2024040038	cxsecurity	vuln;	1	2024-04-15	AMPLE BILLS 0.1 SQL 注入
30640	PrusaSlicer 2.6.1 Arbitrary Code Execution	https://cxsecurity.com/issue/WLB-2024040039	cxsecurity	vuln;	1	2024-04-15	2.6.1 任意处决
30642	Amazon AWS Glue Database Password Disclosure	https://cxsecurity.com/issue/WLB-2024040041	cxsecurity	vuln;	1	2024-04-15	Amazon AWS 粘胶数据库密码披露
30674	Deacon-Jones	http://www.ransomfeed.it/index.php?page=post_details&id_post=14283	ransomfeed	ransom;dragonforce;	1	2024-04-15	执事 - Jones
30679	RB-Woodcraft-Inc	http://www.ransomfeed.it/index.php?page=post_details&id_post=14288	ransomfeed	ransom;8base;	1	2024-04-15	RB Wooddraft-Inc 汽车
30680	GPI-Corporate	http://www.ransomfeed.it/index.php?page=post_details&id_post=14289	ransomfeed	ransom;8base;	1	2024-04-15	GPI-公司
30681	SOA-Architecture	http://www.ransomfeed.it/index.php?page=post_details&id_post=14290	ransomfeed	ransom;8base;	1	2024-04-15	SOA-建筑设计
30682	ASMFC-Atlantic-States-Marine-Fisheries-Commission	http://www.ransomfeed.it/index.php?page=post_details&id_post=14291	ransomfeed	ransom;8base;	1	2024-04-15	ASMFC-大西洋-大西洋-大西洋-大西洋-国家-海洋-渔业委员会
30683	The-Souza-Agency-Inc	http://www.ransomfeed.it/index.php?page=post_details&id_post=14292	ransomfeed	ransom;8base;	1	2024-04-15	苏萨机构间信息中心
30684	LEMODOR	http://www.ransomfeed.it/index.php?page=post_details&id_post=14293	ransomfeed	ransom;8base;	1	2024-04-15	利比里亚
30685	Council-for-Relationships	http://www.ransomfeed.it/index.php?page=post_details&id_post=14294	ransomfeed	ransom;8base;	1	2024-04-15	理事会关系理事会
30686	The-Royal-Family-of-Great-Britain	http://www.ransomfeed.it/index.php?page=post_details&id_post=14295	ransomfeed	ransom;snatch;	1	2024-04-15	皇家家庭大英国
30687	bigtoeyoga	http://www.ransomfeed.it/index.php?page=post_details&id_post=14296	ransomfeed	ransom;darkvault;	1	2024-04-15	大东乌戈加
30688	regulatormarinecom	http://www.ransomfeed.it/index.php?page=post_details&id_post=14297	ransomfeed	ransom;cactus;	1	2024-04-15	规管海事委员会
30709	Ex-Security Engineer Gets Three Years in Prison for $12 Million Crypto Hacks	https://securityboulevard.com/2024/04/ex-security-engineer-gets-three-years-in-prison-for-12-million-crypto-hacks/	securityboulevard	news;Cyberlaw;Cybersecurity;Data Security;Featured;Industry Spotlight;Mobile Security;Network Security;News;Security Awareness;Security Boulevard (Original);Social - Facebook;Social - LinkedIn;Social - X;Spotlight;amazon;crypto fraud;cryptocurrency exchange hack;	1	2024-04-15	前安全工程师因1 200万美元的加密黑客 被判3年监禁
30710	MSP Guide: How to Safeguard Your Clients During a Ransomware Attack	https://securityboulevard.com/2024/04/msp-guide-how-to-safeguard-your-clients-during-a-ransomware-attack/	securityboulevard	news;Security Bloggers Network;Blog;MSPs and Partners;	2	2024-04-15	MSP 指南:如何在Ransomware攻击期间保护客户
30711	MY TAKE: GenAI revolution — the transformative power of ordinary people conversing with AI	https://securityboulevard.com/2024/04/my-take-genai-revolution-the-transformative-power-of-ordinary-people-conversing-with-ai/	securityboulevard	news;SBN News;Security Bloggers Network;Deep Tech;My Take;New Tech;Top Stories;	1	2024-04-15	GenAI革命——普通人与AI对话的变革力量
30712	Randall Munroe’s XKCD ‘Sitting in a Tree’	https://securityboulevard.com/2024/04/randall-munroes-xkcd-sitting-in-a-tree/	securityboulevard	news;Humor;Security Bloggers Network;Randall Munroe;Sarcasm;satire;XKCD;	1	2024-04-15	Randall Munroe的 XKCD “坐在树中”
30713	Roku: Credential Stuffing Attacks Affect 591,000 Accounts	https://securityboulevard.com/2024/04/roku-credential-stuffing-attacks-affect-591000-accounts/	securityboulevard	news;Cloud Security;Cybersecurity;Data Security;Endpoint;Featured;Identity & Access;Mobile Security;Network Security;News;Security Boulevard (Original);Social - Facebook;Social - X;Spotlight;Threats & Breaches;credential stuffing attack;passwordless login;Roku;	1	2024-04-15	Roku:591 000次袭击,影响591 000次
30485	Microsoft will limit Exchange Online bulk emails to fight spam	https://www.bleepingcomputer.com/news/microsoft/microsoft-will-limit-exchange-online-bulk-emails-to-fight-spam/	bleepingcomputer	news;Microsoft;Security;	1	2024-04-15	微软将限制交换在线批量邮件以对抗垃圾邮件
30487	Cisco Duo warns third-party data breach exposed SMS MFA logs	https://www.bleepingcomputer.com/news/security/cisco-duo-warns-third-party-data-breach-exposed-sms-mfa-logs/	bleepingcomputer	news;Security;	1	2024-04-15	Cisco Duo警告第三方数据被破坏,暴露了MFA的短号短信日志
30489	Daixin ransomware gang claims attack on Omni Hotels	https://www.bleepingcomputer.com/news/security/daixin-ransomware-gang-claims-attack-on-omni-hotels/	bleepingcomputer	news;Security;	2	2024-04-15	Daixin赎金软件帮派声称攻击Omni旅馆
30499	Palo Alto Network Issues Hotfixes for Zero-Day Bug in Its Firewall OS	https://www.darkreading.com/cyberattacks-data-breaches/palo-alto-network-issues-hot-fixes-for-zero-day-bug-in-its-firewall-os	darkreading	news;	1	2024-04-15	Palo Alto网络问题网络问题热修 零日臭虫在其防火墙OS
30521	[WARNING] FBI Issues Alert on Major Phishing Campaign That Impersonates US Toll Services	https://blog.knowbe4.com/major-phishing-campaign-impersonates-us-toll-services	knowbe4	news;Social Engineering;Phishing;Security Culture;	1	2024-04-15	[WARNING] 联邦调查局问题警报 有关重大捕杀运动的主要捕捉运动 以美国收费服务公司的名义
30543	Django REST Framework SimpleJWT 5.3.1 Information Disclosure	https://buaq.net/go-234427.html	buaq	newscopy;	0	2024-04-16	Django REST框架简单JWT 5.3.1 信息披露
30549	Chain Theory: A Proposed User-Friendly and Customizable Cryptographic Model	https://buaq.net/go-234441.html	buaq	newscopy;	0	2024-04-16	链条理论:拟议的用户友好和可定制加密模型
30553	Qvest Shares Key AI Findings at NAB Show 2024, Highlighting Major Trends in Media and Entertainment	https://buaq.net/go-234445.html	buaq	newscopy;	0	2024-04-16	在NAB Show 2024,突出媒体和娱乐业的主要趋势
30571	FreeBuf早报 | Cyera 获得 3 亿美元融资；国安部披露5起国家安全领域典型案例	https://www.freebuf.com/news/397934.html	freebuf	news;资讯;	1	2024-04-15	FreeBuf早报 | Cyera 获得 3 亿美元融资；国安部披露5起国家安全领域典型案例
30599	BMC Compuware iStrobe Web 20.13 Shell Upload	https://packetstormsecurity.com/files/178059/bmcciw2013-shell.txt	packetstorm	vuln;;	1	2024-04-15	BMC Compuware iStrobe Web 20.13 Shell 上传
30607	CrushFTP Remote Code Execution	https://packetstormsecurity.com/files/178067/crushftp_rce_cve_2023_43177.rb.txt	packetstorm	vuln;;	1	2024-04-15	CrushFTP 远程代码执行
30641	OpenClinic GA 5.247.01 Path Traversal (Authenticated)	https://cxsecurity.com/issue/WLB-2024040040	cxsecurity	vuln;	1	2024-04-15	OpenClinic GA 5.247.01 Traversal 路径(经核准)
30697	Intel and Lenovo BMCs Contain Unpatched Lighttpd Server Flaw	https://thehackernews.com/2024/04/intel-and-lenovo-bmcs-contain-unpatched.html	feedburner	news;	1	2024-04-15	Intel 和 Lenovo BMC 含有无插放 Lighttpd 服务器flaw 的 BMC 服务器
30708	D3 Security at RSAC 2024: Streamline Your Security Operations with Smart SOAR	https://securityboulevard.com/2024/04/d3-security-at-rsac-2024-streamline-your-security-operations-with-smart-soar/	securityboulevard	news;Security Bloggers Network;LogRhythm Axon;RSA Conference;RSAC 2024;;SBN News;Smart SOAR;SOC Tales & Cocktails;	1	2024-04-15	RSAC 2024年RSAC的D3安保:以智能SOAR精简您的安保行动
30714	The Future of Zero Trust with AI: Exploring How AI Automates and Enhances Security	https://securityboulevard.com/2024/04/the-future-of-zero-trust-with-ai-exploring-how-ai-automates-and-enhances-security/	securityboulevard	news;Security Bloggers Network;AI (Artificial Intelligence);AI Zero Trust;AI-enhanced security;future;Innovation;zero trust;	1	2024-04-15	与AI:探索AI如何实现自动化和加强安全
30715	The ONE Thing All Modern SaaS Risk Management Programs Do	https://securityboulevard.com/2024/04/the-one-thing-all-modern-saas-risk-management-programs-do/	securityboulevard	news;Security Bloggers Network;	1	2024-04-15	" 一体行动,所有现代SaaS风险管理方案 "
30716	USENIX Security ’23 – An Empirical Study & Evaluation of Modern CAPTCHAs	https://securityboulevard.com/2024/04/usenix-security-23-an-empirical-study-evaluation-of-modern-captchas/	securityboulevard	news;Security Bloggers Network;Open Access Research;Security Conferences;USENIX;USENIX Security ’23;	2	2024-04-15	USENIX 安全 23 - 现代CAPCHA的经验研究和评估
30717	Zscaler to Acquire Airgap Networks to Segment Endpoint Traffic	https://securityboulevard.com/2024/04/zscaler-to-acquire-airgap-networks-to-segment-endpoint-traffic/	securityboulevard	news;Featured;News;Security at the Edge;Security Boulevard (Original);airgap-networks;dhcp;Endpoint security;secops;Zscaler;	1	2024-04-15	向Accre Airgap网络获取达到端点交通段的标标尺
30738	iPhone16Pro系列或有30项优化	https://s.weibo.com/weibo?q=%23iPhone16Pro系列或有30项优化%23	sina.weibo	hotsearch;weibo	2	2024-04-16	iPhone16Pro系列或有30项优化
30740	特斯拉市值一夜蒸发2200亿	https://s.weibo.com/weibo?q=%23特斯拉市值一夜蒸发2200亿%23	sina.weibo	hotsearch;weibo	1	2024-04-16	特斯拉市值一夜蒸发2200亿
31019	Quick Palo Alto Networks Global Protect Vulnerablity Update (CVE-2024-3400), (Mon, Apr 15th)	https://buaq.net/go-234457.html	buaq	newscopy;	\N	2024-04-16	No Translation
31020	The ONE Thing All Modern SaaS Risk Management Programs Do	https://buaq.net/go-234459.html	buaq	newscopy;	\N	2024-04-16	No Translation
31037	江苏省数据局发布《江苏省数据条例（草案）》 （征求意见稿）	https://www.freebuf.com/news/397997.html	freebuf	news;资讯;	\N	2024-04-15	No Translation
\.


--
-- Data for Name: spring_session; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.spring_session (primary_id, session_id, creation_time, last_access_time, max_inactive_interval, expiry_time, principal_name) FROM stdin;
\.


--
-- Data for Name: spring_session_attributes; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.spring_session_attributes (session_primary_id, attribute_name, attribute_bytes) FROM stdin;
\.


--
-- Name: data_source_autoincrease; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.data_source_autoincrease', 48, true);


--
-- Name: key_words_autoincrease; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.key_words_autoincrease', 29, true);


--
-- Name: saved_info_autoincrease; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.saved_info_autoincrease', 31201, true);


--
-- Name: data_source data_source_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.data_source
    ADD CONSTRAINT data_source_pkey PRIMARY KEY (id);


--
-- Name: key_words key_words_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.key_words
    ADD CONSTRAINT key_words_pkey PRIMARY KEY (id);


--
-- Name: saved_info saved_news_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.saved_info
    ADD CONSTRAINT saved_news_pkey PRIMARY KEY (id);


--
-- Name: spring_session_attributes spring_session_attributes_pk; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.spring_session_attributes
    ADD CONSTRAINT spring_session_attributes_pk PRIMARY KEY (session_primary_id, attribute_name);


--
-- Name: spring_session spring_session_pk; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.spring_session
    ADD CONSTRAINT spring_session_pk PRIMARY KEY (primary_id);


--
-- Name: saved_info_link_idx; Type: INDEX; Schema: public; Owner: postgres
--

CREATE UNIQUE INDEX saved_info_link_idx ON public.saved_info USING btree (link);


--
-- Name: spring_session_ix1; Type: INDEX; Schema: public; Owner: postgres
--

CREATE UNIQUE INDEX spring_session_ix1 ON public.spring_session USING btree (session_id);


--
-- Name: spring_session_ix2; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX spring_session_ix2 ON public.spring_session USING btree (expiry_time);


--
-- Name: spring_session_ix3; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX spring_session_ix3 ON public.spring_session USING btree (principal_name);


--
-- Name: spring_session_attributes spring_session_attributes_fk; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.spring_session_attributes
    ADD CONSTRAINT spring_session_attributes_fk FOREIGN KEY (session_primary_id) REFERENCES public.spring_session(primary_id) ON DELETE CASCADE;


--
-- PostgreSQL database dump complete
--

