import json
import logging
import sys
import time
import typing
import urllib.parse
import warnings

import click
import requests
import urllib3.exceptions


class VijnError(Exception):
    pass


class VijnAPI:
    def __init__(self, url: str, api_token: str, ignore_ssl: bool) -> None:
        self._url = url
        self._sess = requests.session()
        self._sess.verify = not ignore_ssl
        self._sess.hooks["response"] = [
            self._raise_for_status,
            self._ensure_json,
        ]
        self._sess.headers["Authorization"] = f"Basic {api_token}"

    def get_site_id(self, url: str) -> typing.Optional[int]:
        sites_url = urllib.parse.urljoin(self._url, "sites")
        resp = self._sess.get(sites_url)
        for site in resp.json()["data"]:
            if site["url"] == url:
                return int(site["id"])
        return None

    def add_site(self, target_url: str) -> int:
        sites_url = urllib.parse.urljoin(self._url, "sites/add")
        sites_req = {"url": target_url}
        resp = self._sess.post(sites_url, json=sites_req)
        site_id = resp.json()["data"]["id"]
        return int(site_id)

    def start_scan(self, site_id: int) -> int:
        sites_url = urllib.parse.urljoin(self._url, f"sites/{site_id}/start")
        resp = self._sess.post(sites_url)
        scan_id = resp.json()["data"]["id"]
        return int(scan_id)

    def stop_scan(self, site_id: int) -> None:
        sites_url = urllib.parse.urljoin(self._url, f"sites/{site_id}/stop")
        self._sess.post(sites_url)

    def is_site_busy(self, site_id: int) -> bool:
        sites_url = urllib.parse.urljoin(self._url, f"sites/{site_id}")
        resp = self._sess.get(sites_url)
        site = resp.json()["data"]
        last_scan = site["lastScan"]
        if not last_scan:
            return False
        last_scan_status = last_scan["status"]
        return last_scan_status not in ("STOPPED", "FINISHED")

    def is_scan_busy(self, site_id: int, scan_id: int) -> bool:
        scan_url = urllib.parse.urljoin(self._url, f"sites/{site_id}/scans/{scan_id}")
        resp = self._sess.get(scan_url)
        scan = resp.json()["data"]
        return scan["status"] not in ("STOPPED", "FINISHED")

    def is_scan_ok(self, site_id: int, scan_id: int) -> bool:
        scan_url = urllib.parse.urljoin(self._url, f"sites/{site_id}/scans/{scan_id}")
        resp = self._sess.get(scan_url)
        scan = resp.json()["data"]
        return scan["status"] == "FINISHED" and scan["errorReason"] is None

    def get_vulns(
        self, site_id: int, scan_id: int
    ) -> typing.List[typing.Dict[str, str]]:
        vulns_url = urllib.parse.urljoin(
            self._url, f"sites/{site_id}/scans/{scan_id}/vulnerabilities"
        )
        resp = self._sess.get(vulns_url)
        raw_vulns = resp.json()["data"]
        return [
            {
                "url": raw["urlFull"],
                "name": raw["type"]["localeKey"],
                "category": raw["type"]["categoryLocaleKey"],
                "severity": raw["severity"],
                "falsePositive": str(raw["falsePositive"]),
                "fixed": str(raw["fixed"]),
            }
            for raw in raw_vulns
        ]

    def create_shared_link(self, site_id: int, scan_id: int) -> str:
        url = urllib.parse.urljoin(self._url, f"sites/{site_id}/scans/{scan_id}/shared")
        resp = self._sess.post(url)
        uuid = resp.json()["data"]["uuid"]
        return typing.cast(str, uuid)

    @staticmethod
    def _raise_for_status(
        resp: requests.Response, *args: typing.Any, **kwargs: typing.Any
    ) -> None:
        resp.raise_for_status()

    @staticmethod
    def _ensure_json(
        resp: requests.Response, *args: typing.Any, **kwargs: typing.Any
    ) -> None:
        if resp.headers.get("content-type") != "application/json":
            raise VijnError(
                "unexpected API response content type, "
                "check if Vijn URL is specified correctly"
            )


class VijnOperator:
    def __init__(self, url: str, api_token: str, ignore_ssl: bool) -> None:
        self._ui_base_url = url
        api_url = urllib.parse.urljoin(url, "app/api/v1/")
        self._api = VijnAPI(api_url, api_token, ignore_ssl)
        self._site_id: typing.Optional[int] = None
        self._scan_id: typing.Optional[int] = None
        self._scan_finished: bool = False

    def set_target(self, url: str, auto_create: bool) -> None:
        # FIXME: Search may not work because of URL normalization at the backend.
        site_id = self._api.get_site_id(url)
        if site_id is None:
            if not auto_create:
                raise VijnError(
                    "the site with the URL specified was not found, "
                    "use UI to create one manually, "
                    "or use --auto-create flag to do so automatically"
                )
            site_id = self._api.add_site(url)
        self._site_id = site_id

    def ensure_target_is_idle(self, previous: str) -> None:
        if not self._site_id:
            raise RuntimeError("target not set")
        if not self._api.is_site_busy(self._site_id):
            return
        if previous == "fail":
            raise VijnError("the target is busy")
        if previous == "stop":
            self._api.stop_scan(self._site_id)
        # previous is either "stop" or "wait"
        self._wait_for_target()

    def start_scan(self) -> None:
        if not self._site_id:
            raise RuntimeError("target not set")
        self._scan_id = self._api.start_scan(self._site_id)
        self._scan_finished = False

    def get_scan_report(self, share_link: bool) -> str:
        if not self._site_id or not self._scan_id:
            raise RuntimeError("target or scan not set")
        report: typing.Dict[str, typing.Any] = {
            "url": self._scan_url,
            "vulns": [],
        }
        if share_link:
            report["sharedLink"] = self._create_shared_link()
        if self._scan_finished:
            report["vulns"] = self._api.get_vulns(self._site_id, self._scan_id)
        return json.dumps(report)

    def wait_for_scan(self) -> None:
        if not self._site_id or not self._scan_id:
            raise RuntimeError("target or scan not set")
        while self._api.is_scan_busy(self._site_id, self._scan_id):
            time.sleep(2.0)
        self._scan_finished = True
        if not self._api.is_scan_ok(self._site_id, self._scan_id):
            raise VijnError(
                f"the scan did not succeed, "
                f"see UI for the error reason: {self._scan_url}"
            )

    def _wait_for_target(self) -> None:
        if not self._site_id:
            raise RuntimeError("target not set")
        while self._api.is_site_busy(self._site_id):
            time.sleep(2.0)

    def _create_shared_link(self) -> str:
        if not self._site_id or not self._scan_id:
            raise RuntimeError("target or scan not set")

        shared_link_uuid = self._api.create_shared_link(self._site_id, self._scan_id)
        shared_link = urllib.parse.urljoin(
            self._ui_base_url, f"/shared/{shared_link_uuid}"
        )
        return shared_link

    @property
    def _scan_url(self) -> str:
        return urllib.parse.urljoin(
            self._ui_base_url,
            f"/sites/{self._site_id}/scans/{self._scan_id}/overview",
        )


@click.command()
@click.option("--vijn-url", envvar="VIJN_URL", default="https://vijn.io/")
@click.option("--vijn-api-token", envvar="VIJN_API_TOKEN", required=True)
@click.option("--target-url", envvar="TARGET_URL", required=True)
@click.option(
    "--ignore-ssl",
    envvar="IGNORE_SSL",
    is_flag=True,
    default=False,
    help="Skip verification of Vijn API host certificate.",
)
@click.option(
    "--auto-create",
    is_flag=True,
    help="Automatically create a site if a site with the target URL was not found.",
)
@click.option(
    "--previous",
    type=click.Choice(["wait", "stop", "fail"]),
    default="fail",
    help="What to do if the target is currently being scanned.",
)
@click.option(
    "--no-wait",
    is_flag=True,
    help="Do not wait until the started scan is finished.",
)
@click.option(
    "--shared-link",
    is_flag=True,
    default=False,
    help="Create shared link for scan.",
)
def main(
    vijn_url: str,
    vijn_api_token: str,
    target_url: str,
    ignore_ssl: bool,
    auto_create: bool,
    previous: str,
    no_wait: bool,
    shared_link: bool,
) -> None:
    if ignore_ssl:
        warnings.simplefilter("ignore", urllib3.exceptions.InsecureRequestWarning)
    operator = VijnOperator(vijn_url, vijn_api_token, ignore_ssl)
    operator.set_target(target_url, auto_create)
    operator.ensure_target_is_idle(previous)
    operator.start_scan()
    if not no_wait:
        operator.wait_for_scan()
    print(operator.get_scan_report(shared_link))


def log_http_error(err: requests.HTTPError) -> None:
    verbose = ""
    if isinstance(err.response, requests.Response):
        if err.response.headers["Content-Type"] == "application/json":
            body_json = err.response.json()
            verbose = json.dumps(body_json, indent=2)
            verbose = f"\n{verbose}"
    logging.error(f"Vijn API call failed: {err}{verbose}")


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.DEBUG, format="%(asctime)s %(levelname)s [%(name)s] %(message)s"
    )
    try:
        main()
    except requests.HTTPError as err:
        log_http_error(err)
    except VijnError as err:
        logging.error(f"Vijn error: {err}")
    else:
        sys.exit(0)
    sys.exit(1)
