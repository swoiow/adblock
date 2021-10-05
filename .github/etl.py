import json
import os
import urllib.request
import uuid


rules_fp = "raw"
ruleset = set()

_rule_zero = "0.0.0.0 "
_rule_127 = "127.0.0.1 "

ignore_domains = [
    "::1",
    "0.0.0.0",
    "localhost",
    "baidu.com"
]


def handle_lines(lines):
    for line in lines:
        line = line.lower().strip()

        if not line.startswith("#") and \
            not line.startswith("::1") and \
            64 > len(line) > 3 or \
            line.endswith("reject"):

            if "," in line:
                kw, domain, action = line.split(",")
            else:
                domain = line

            domain = domain.strip()
            if domain.startswith(_rule_127):
                domain = domain.replace(_rule_127, "")
            else:
                domain = domain.replace(_rule_zero, "")

            if domain.startswith("."):
                domain = domain[1:]
            if domain.endswith(".") or domain.endswith("/"):
                domain = domain[:-1]

            domain = domain.strip()

            # add to ruleset
            if "." in domain and domain not in ignore_domains:
                ruleset.add(domain)
            else:
                if "." in domain:
                    print(f"handle failed: {domain}")


def etl():
    for rule_fp in os.listdir(rules_fp):
        full_fp = os.path.join(rules_fp, rule_fp)
        if full_fp.endswith(".txt"):
            with open(full_fp, "r") as rf:
                content = rf.readlines()
                handle_lines(content)
            del content

    with open("ruleset.txt", "w") as wf:
        wf.write("\n".join(sorted(ruleset)))

    print(f"ruleset number: {len(ruleset)}")


def download_rules(url):
    with urllib.request.urlopen(url) as f:
        content = f.read().decode('utf-8')
    with open(f"raw/{uuid.uuid5(uuid.NAMESPACE_URL, url)}.txt", "w", encoding="utf-8") as wf:
        wf.write(content)


def fetch_rules():
    url = "https://api.github.com/repos/swoiow/adblock/issues/comments/932148163"

    c = urllib.request.urlopen(url)
    data = c.read()
    encoding = c.info().get_content_charset('utf-8')
    content = json.loads(data.decode(encoding))

    rules = content["body"].split("\r\n")

    for url in rules:
        download_rules(url)


if __name__ == '__main__':
    fetch_rules()
    etl()
