import os
import sys
import json
import base64
import pprint
import argparse
import random
import hashlib
import binascii
import traceback
import urllib.request
import urllib.parse
from . import TPL

V2RAY_SCHEMA = "vmess://"
SS_SCHEMA = "ss://"


def parse_link(link):
    if link.startswith(SS_SCHEMA):
        return parse_ss(link)
    elif link.startswith(V2RAY_SCHEMA):
        return parse_vemss(link)
    else:
        print("ERROR: This script supports only vmess://(N/NG) and ss:// links")
        return None


def parse_ss(ss_link):
    res_obj = {
        "v": "2",
        "ps": "",
        "add": "",
        "port": "",
        "id": "",
        "aid": "",
        "net": "shadowsocks",
        "type": "",
        "host": "",
        "path": "",
        "tls": ""
    }
    if ss_link.startswith(SS_SCHEMA):
        info = ss_link[len(SS_SCHEMA):]

        if info.rfind("#") > 0:
            info, _ps = info.split("#", 2)
            res_obj["ps"] = urllib.parse.unquote(_ps)

        if info.find("@") < 0:
            # old style link
            # paddings
            blen = len(info)
            if blen % 4 > 0:
                info += "=" * (4 - blen % 4)

            info = base64.b64decode(info).decode()

            atidx = info.rfind("@")
            method, password = info[:atidx].split(":", 2)
            addr, port = info[atidx + 1:].split(":", 2)
        else:
            atidx = info.rfind("@")
            addr, port = info[atidx + 1:].split(":", 2)

            info = info[:atidx]
            blen = len(info)
            if blen % 4 > 0:
                info += "=" * (4 - blen % 4)

            info = base64.b64decode(info).decode()
            method, password = info.split(":", 2)

        res_obj["add"] = addr
        res_obj["port"] = port
        res_obj["aid"] = method
        res_obj["id"] = password
        return res_obj


def parse_vemss(vmesslink):
    if vmesslink.startswith(V2RAY_SCHEMA):
        bs = vmesslink[len(V2RAY_SCHEMA):]
        # paddings
        blen = len(bs)
        if blen % 4 > 0:
            bs += "=" * (4 - blen % 4)

        vms = base64.b64decode(bs).decode()
        return json.loads(vms)
    else:
        raise Exception("vmess link invalid")


def load_TPL(stype):
    s = TPL[stype]
    return json.loads(s)


def fill_basic(_c, _v):
    _outbound = _c["outbounds"][0]
    _vnext = _outbound["settings"]["vnext"][0]

    _vnext["address"] = _v["add"]
    _vnext["port"] = int(_v["port"])
    _vnext["users"][0]["id"] = _v["id"]
    _vnext["users"][0]["alterId"] = int(_v["aid"])

    _outbound["streamSettings"]["network"] = _v["net"]

    if _v["tls"] == "tls":
        _outbound["streamSettings"]["security"] = "tls"
        _outbound["streamSettings"]["tlsSettings"] = {"allowInsecure": True}
        if _v["host"] != "":
            _outbound["streamSettings"]["tlsSettings"]["serverName"] = _v["host"]

    return _c


def fill_shadowsocks(_c, _v):
    _ss = load_TPL("out_ss")
    _ss["email"] = _v["ps"] + "@ss"
    _ss["address"] = _v["add"]
    _ss["port"] = int(_v["port"])
    _ss["method"] = _v["aid"]
    _ss["password"] = _v["id"]

    _outbound = _c["outbounds"][0]
    _outbound["protocol"] = "shadowsocks"
    _outbound["settings"]["servers"] = [_ss]

    del _outbound["settings"]["vnext"]
    del _outbound["streamSettings"]
    del _outbound["mux"]

    return _c


def fill_tcp_http(_c, _v):
    tcps = load_TPL("http")
    tcps["header"]["type"] = _v["type"]
    if _v["host"] != "":
        # multiple host
        tcps["header"]["request"]["headers"]["Host"] = _v["host"].split(",")

    if _v["path"] != "":
        tcps["header"]["request"]["path"] = [_v["path"]]

    _c["outbounds"][0]["streamSettings"]["tcpSettings"] = tcps
    return _c


def fill_kcp(_c, _v):
    kcps = load_TPL("kcp")
    kcps["header"]["type"] = _v["type"]
    _c["outbounds"][0]["streamSettings"]["kcpSettings"] = kcps
    return _c


def fill_ws(_c, _v):
    wss = load_TPL("ws")
    wss["path"] = _v["path"]
    wss["headers"]["Host"] = _v["host"]
    _c["outbounds"][0]["streamSettings"]["wsSettings"] = wss
    return _c


def fill_h2(_c, _v):
    h2s = load_TPL("h2")
    h2s["path"] = _v["path"]
    h2s["host"] = [_v["host"]]
    _c["outbounds"][0]["streamSettings"]["httpSettings"] = h2s
    return _c


def fill_quic(_c, _v):
    quics = load_TPL("quic")
    quics["header"]["type"] = _v["type"]
    quics["security"] = _v["host"]
    quics["key"] = _v["path"]
    _c["outbounds"][0]["streamSettings"]["quicSettings"] = quics
    return _c


def vmess2client(_t, _v):
    _net = _v["net"]
    _type = _v["type"]

    if _net == "shadowsocks":
        return fill_shadowsocks(_t, _v)

    _c = fill_basic(_t, _v)

    if _net == "kcp":
        return fill_kcp(_c, _v)
    elif _net == "ws":
        return fill_ws(_c, _v)
    elif _net == "h2":
        return fill_h2(_c, _v)
    elif _net == "quic":
        return fill_quic(_c, _v)
    elif _net == "tcp":
        if _type == "http":
            return fill_tcp_http(_c, _v)
        return _c
    else:
        pprint.pprint(_v)
        raise Exception("this link seem invalid to the script, please report to dev.")


def parse_multiple(lines):
    def genPath(ps, rand=False):
        # add random in case list "ps" share common names
        curdir = os.environ.get("PWD", '/tmp/')
        rnd = "-{}".format(random.randrange(100)) if rand else ""
        name = "{}{}.json".format(vc["ps"].replace("/", "_").replace(".", "-"), rnd)
        return os.path.join(curdir, name)

    for line in lines:
        vc = parse_link(line.strip())
        if vc is None:
            continue

        if int(vc["v"]) != 2:
            print("Version mismatched, skiped. This script only supports version 2.")
            continue

        cc = fill_inbounds(fill_dns(vmess2client(load_TPL("CLIENT"), vc)))

        jsonpath = genPath(vc["ps"])
        while os.path.exists(jsonpath):
            jsonpath = genPath(vc["ps"], True)

        print("Wrote: " + jsonpath)
        with open(jsonpath, 'w') as f:
            json_dump(cc, f)


def json_dump(obj, fobj):
    if option.update is not None:
        oconf = json.load(option.update)
        if "outbounds" not in oconf:
            raise KeyError("outbounds not found in {}".format(option.update.name))

        oconf["outbounds"][0] = obj["outbounds"][0]
        option.update.close()
        with open(option.update.name, 'w') as f:
            json.dump(oconf, f, indent=4)
        print("Updated")
        return

    if option.outbound:
        onlyoutbound = {"outbounds": obj["outbounds"][:1]}  # keeps only the first element
        json.dump(onlyoutbound, fobj, indent=4)
    else:
        json.dump(obj, fobj, indent=4)


def fill_inbounds(_c):
    _ins = option.inbounds.split(",")
    for _in in _ins:
        _proto, _port = _in.split(":", maxsplit=1)
        _tplKey = "in_" + _proto
        if _tplKey in TPL:
            _inobj = load_TPL(_tplKey)

            if _proto == "dns":
                _c["dns"] = load_TPL("conf_dns")
                _c["routing"]["rules"].insert(0, {
                    "type": "field",
                    "inboundTag": ["dns-in"],
                    "outboundTag": "dns-out"
                })
                _c["outbounds"].append({
                    "protocol": "dns",
                    "tag": "dns-out"
                })

            elif _proto == "api":
                _c["api"] = {
                    "tag": "api",
                    "services": ["HandlerService", "LoggerService", "StatsService"]
                }
                _c["stats"] = {}
                _c["policy"] = {
                    "levels": {"0": {"statsUserUplink": True, "statsUserDownlink": True}},
                    "system": {"statsInboundUplink": True, "statsInboundDownlink": True}
                }
                _c["routing"]["rules"].insert(0, {
                    "type": "field",
                    "inboundTag": ["api"],
                    "outboundTag": "api"
                })

            elif _proto == "mt":
                mtinfo = _port.split(":", maxsplit=1)
                if len(mtinfo) == 2:
                    _port, _secret = mtinfo
                else:
                    _secret = hashlib.md5(str(random.random()).encode()).hexdigest()

                _inobj["settings"]["users"][0]["secret"] = _secret
                _c["outbounds"].append(load_TPL("out_mt"))
                _c["routing"]["rules"].insert(0, {
                    "type": "field",
                    "inboundTag": ["mt-in"],
                    "outboundTag": "mt-out"
                })

            _inobj["port"] = int(_port)
            _c["inbounds"].append(_inobj)
        else:
            print("Error Inbound: " + _in)

    return _c


def fill_dns(_c):
    if option.localdns != "":
        dns = {
            "address": option.localdns,
            "port": 53,
            "domains": ["geosite:cn"]
        }
        ## 当某个 DNS 服务器指定的域名列表匹配了当前要查询的域名，V2Ray 会优先使用这个 
        ## DNS 服务器进行查询，否则按从上往下的顺序进行查询。
        ## 
        _c["dns"]["servers"].insert(1, dns)

        ## 若要使 DNS 服务生效，需要配置路由功能中的 domainStrategy。
        _c["routing"]["domainStrategy"] = "IPOnDemand"

    return _c


def read_subscribe(sub_url):
    print("Reading from subscribe ...")

    if sub_url.startswith("http"):
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.3'}
        req = urllib.request.Request(url=sub_url, headers=headers)
        with urllib.request.urlopen(req) as response:
            _subs = response.read()
            return base64.b64decode(_subs).decode().splitlines()
    elif os.path.exists(sub_url):
        with open(sub_url) as f:
            _subs = f.read()
            try:
                b64lines = base64.b64decode(_subs).decode().splitlines()
                return b64lines
            except (binascii.Error, UnicodeDecodeError):
                lines = _subs.splitlines()
                return lines


def select_multiple(lines):
    vmesses = []
    for _v in lines:
        _vinfo = parse_link(_v)
        if _vinfo is not None:
            vmesses.append({"ps": "[{ps}] {add}:{port}/{net}".format(**_vinfo), "vm": _v})

    if len(vmesses) > 1:
        print("Found {} items.".format(len(vmesses)))
        for i, item in enumerate(vmesses):
            print("[{}] - {}".format(i + 1, item["ps"]))
        print()

    if not sys.stdin.isatty() and os.path.exists('/dev/tty'):
        sys.stdin.close()
        sys.stdin = open('/dev/tty', 'r')

    if len(vmesses) == 1:
        idx = 0
    elif len(vmesses) > 1 and int(option.select) > 0:
        idx = int(option.select) - 1
    elif len(vmesses) > 1 and sys.stdin.isatty():
        sel = input("Choose >>> ")
        idx = int(sel) - 1
    else:
        raise Exception("Current session can't open a tty to select. Specify the index to --select argument.")

    item = vmesses[idx]["vm"]

    ln = parse_link(item)
    if ln is None:
        return
    cc = fill_inbounds(fill_dns(vmess2client(load_TPL("CLIENT"), ln)))
    json_dump(cc, option.output)


def detect_stdin():
    if sys.stdin.isatty():
        return None
    stdindata = sys.stdin.read()
    option.subscribe = "-"
    try:
        lines = base64.b64decode(stdindata).decode().splitlines()
        return lines
    except (binascii.Error, UnicodeDecodeError):
        return stdindata.splitlines()


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="vmess2json convert vmess link to client json config.")
    parser.add_argument('--parse_all',
                        action="store_true",
                        default=False,
                        help="parse all vmess:// lines (or base64 encoded) from stdin and write each into .json files")
    parser.add_argument('--subscribe',
                        action="store",
                        default="",
                        help="read from a subscribe (local file or http url) , display a menu to choose nodes")
    parser.add_argument('-o', '--output',
                        type=argparse.FileType('w'),
                        default=sys.stdout,
                        help="write to file. default to stdout")
    parser.add_argument('-u', '--update',
                        type=argparse.FileType('r'),
                        help="update a config.json, changes only the first outbound object.")
    parser.add_argument('--outbound',
                        action="store_true",
                        default=False,
                        help="output the outbound object only.")
    parser.add_argument('--inbounds',
                        action="store",
                        default="socks:1080,http:8123",
                        help="include inbounds objects, default: \"socks:1080,http:8123\". Available proto: socks,http,dns,mt,tproxy . "
                             "For mtproto with custom password:  mt:7788:xxxxxxxxxxxxxxx")
    parser.add_argument('--localdns',
                        action="store",
                        default="",
                        help="use domestic DNS server for geosite:cn list domains.")
    parser.add_argument('--select',
                        action="store",
                        default="-1",
                        help="non-interative select for certain link")
    parser.add_argument('vmess',
                        nargs='?',
                        help="A vmess:// link. If absent, reads a line from stdin.")

    option = parser.parse_args()
    stdin_data = detect_stdin()

    if option.parse_all and stdin_data is not None:
        parse_multiple(stdin_data)
        sys.exit(0)

    # if stdin can be base64 decoded, subscribe from stdin is implicted.
    if len(option.subscribe) > 0:
        try:
            if stdin_data is None:
                select_multiple(read_subscribe(option.subscribe))
            else:
                select_multiple(stdin_data)
        except (EOFError, KeyboardInterrupt):
            print("Bye.")
        except:
            traceback.print_exc()
        finally:
            sys.exit(0)

    if option.vmess is None and stdin_data is None:
        parser.print_help()
        sys.exit(1)

    vmess = option.vmess if option.vmess is not None else stdin_data[0]
    vc = parse_link(vmess.strip())
    if vc is None:
        sys.exit(1)

    cc = fill_inbounds(fill_dns(vmess2client(load_TPL("CLIENT"), vc)))
    json_dump(cc, option.output)
