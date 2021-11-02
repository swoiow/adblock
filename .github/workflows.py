import os
import time

import requests as net


ENV_REL_NAME = os.environ["WF_REL_NAME"]
ENV_TAG_NAME = os.environ["WF_TAG_NAME"]
ENV_GITHUB_TOKEN = os.environ["WF_GITHUB_TOKEN"]

COMMIT_SHA = os.environ["GITHUB_SHA"]
GITHUB_API = os.environ["GITHUB_API_URL"]
GITHUB_REPOSITORY = os.environ["GITHUB_REPOSITORY"]

RELEASE_API = f"{GITHUB_API}/repos/{GITHUB_REPOSITORY}/releases"
CREATE_RELEASE = RELEASE_API
UPDATE_DELETE_RELEASE = f"{RELEASE_API}/%s"
GET_RELEASE_BY_TAG_NAME = f"{RELEASE_API}/tags/%s"

Net = net.Session()
Net.headers = {
    "Accept": "application/vnd.github.v3+json",
    "authorization": f"Bearer {ENV_GITHUB_TOKEN}",
}


def update_or_create_release(release_name, tag_name, draft=False, prerelease=False):
    payload = {
        "name": release_name,
        "tag_name": tag_name,
        # "target_commitish": ENV_COMMIT_SHA,
        "draft": draft,
        "prerelease": prerelease,
    }

    r = Net.get(GET_RELEASE_BY_TAG_NAME % tag_name)

    if r.status_code == 200:
        delete_release(r.json()["id"])
        time.sleep(2)

    c = Net.post(CREATE_RELEASE, json=payload)
    print(c.text)


def remove_all_draft_release():
    r = Net.get(RELEASE_API)

    for item in r.json():
        if item["draft"]:
            delete_release(item["id"])
            time.sleep(1)


def delete_release(release_id):
    d = Net.delete(UPDATE_DELETE_RELEASE % release_id)
    print(f"[delete] release_id: {release_id}")
