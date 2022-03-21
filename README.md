# vijn-scan

This tool is a command-line client for the [Vijn](https://vijn.io/) API, that can help to integrate Dynamic Application Security Testing (DAST) into a CI/CD pipeline.

## Requirements

[Python](https://www.python.org/) version 3.6.2 or above is required to run the tool. The use of [virtualenv](https://docs.python.org/3/library/venv.html) is recommended.

To install required Python packages, run:

```shell
pip install -r requirements.txt
```

## Usage

### Synopsis

```
  vijn-scan.py [OPTIONS]
```

### Options

```
Usage: vijn-scan.py [OPTIONS]

Options:
  --vijn-url TEXT
  --vijn-api-token TEXT        [required]
  --target-url TEXT            [required]
  --ignore-ssl                 Skip verification of Vijn API host certificate.
  --auto-create                Automatically create a site if a site with the
                               target URL was not found.
  --previous [wait|stop|fail]  What to do if the target is currently being
                               scanned.
  --no-wait                    Do not wait until the started scan is finished.
  --shared-link                Create shared link for scan.
  --help                       Show this message and exit.
```

### Environment

The following environment variables may be used instead of corresponding options:

- `VIJN_URL`/`--vijn-url`
- `VIJN_API_TOKEN`/`--vijn-api-token`
- `TARGET_URL`/`--target-url`
- `IGNORE_SSL`/`--ignore-ssl`

## Example

```shell
export VIJN_URL=https://vijn.io/
export VIJN_API_TOKEN=D4OPXw7mXCWjHER0lE48PCr4UkcfD86AwOwnio9I1w3HsOSS3Hxo9xi82hoWOB5deVYMk3kedgh0f9yq
export TARGET_URL=http://staging.example.com/

python vijn-scan.py --auto-create --previous=stop
```

## Results

When a scan finishes without an error, the tool returns exit code `0` and prints JSON-formatted report to `stdout`. A report may be passed for processing to a tool such as [jq](https://stedolan.github.io/jq/).

Example output (reformatted for readability):

```json
{
    "url": "https://vijn.io/sites/3/scans/1/overview",
    "user": "devsecops@example.com",
    "vulns": [
        {
            "url": "http://staging.example.com/",
            "name": "missing_x-xss-protection",
            "category": "security_headers",
            "severity": "LOW",
            "falsePositive": "False",
            "fixed": "False"
        },
        {
            "url": "http://staging.example.com/info.php",
            "name": "phpinfo.disable_functions",
            "category": "security_misconfiguration",
            "severity": "LOW",
            "falsePositive": "False",
            "fixed": "False"
        },
        {
            "url": "http://staging.example.com/upload.php",
            "name": "fileupload",
            "category": "insecure_design",
            "severity": "HIGH",
            "falsePositive": "False",
            "fixed": "False"
        },
        {
            "url": "https://staging.example.com/",
            "name": "no_https_scheme",
            "category": "cryptography",
            "severity": "MEDIUM",
            "falsePositive": "False",
            "fixed": "False"
        }
    ],
  "sharedLink": "https://vijn.io/shared/dee4Lyx"
}
```

In case an error occurs, the tool returns non-zero exit code and prints error log messages to `stderr`:

```
2021-12-03 13:24:52,517 ERROR [root] Vijn error: the scan did not succeed, see UI for the error reason: http://vijn.io/sites/2/scans/1/overview
```

## Bugs and Issues

To report a problem related to the tool, please create a new issue.

## Terms

For Vijn terms of use, see [Vijn License](https://vijn.io/license).

## License

For the tool licensing terms, see [LICENSE](LICENSE) file.
