# wiretap-auto

Zero-configuration capture for [wiretap](https://github.com/ssx/wiretap).
Records outbound HTTP calls made by **any** code in the process — including
your vendor directory, which you cannot edit.

```bash
composer require ssx/wiretap-auto
pecl install opentelemetry     # see below
```

That is the entire install. No service provider, no bootstrap line, no SPI.
Composer's autoloader registers the hooks.

## What it captures that middleware cannot

```php
// Untouched vendor code, three directories deep. Captured.
$ch = curl_init('https://api.example.com/v1/orders');
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
$body = curl_exec($ch);

// A Guzzle client with no middleware attached at all. Captured.
$response = (new GuzzleHttp\Client())->get('https://api.example.com/v1');
```

## What is captured

Both halves of ext-curl are hooked: `curl_exec` and the `curl_multi_*`
interface.

| | Captured by this package |
| --- | --- |
| `curl_exec()` anywhere, including vendor code | yes |
| Guzzle, synchronous (`$client->get()`) | yes |
| Guzzle, async (`getAsync()`, `Pool`, `requestAsync`) | yes |
| Symfony HttpClient (`CurlHttpClient`) | yes |
| Raw `curl_multi_*` loops | yes |

The multi interface matters more than it sounds. Guzzle's default handler is
`Proxy::wrapSync(CurlMultiHandler, CurlHandler)`, so every async request, every
`Pool` and every concurrent batch goes through `curl_multi_*` and never touches
`curl_exec`. Symfony's `CurlHttpClient` is multi-only and never calls it at all.
Vendor code making async calls is precisely what this package exists to see.

Measured, not assumed — one script doing a sync GET, an async GET, a two-request
pool and a raw multi loop:

```
before   recorded 1:
           /sync     status=200

after    recorded 5:
           /async    status=200
           /multi-1  status=200 bytes=8
           /pool-1   status=200
           /pool-2   status=200
           /sync     status=200
```

A transfer is set up when it enters the multi stack, takes the correlation id
and sequence in scope at that moment, and is recorded when
`curl_multi_info_read()` reports it finished, which is what Guzzle's and
Symfony's handlers use. curl reports how a transfer ended only there
(`curl_errno()` stays 0 even after a timeout), and reading it for you would
take the message from the application. So a transfer removed with
`curl_multi_remove_handle()` without being reported is judged by what
`curl_multi_exec()` said:

- **it had finished** (an exec after it was added reported nothing running,
  as in a loop that runs until `$running` is 0): recorded, with the outcome
  read from its info. No response, a total time at the timeout, or fewer bytes
  than the `Content-Length` makes it a failure; otherwise a success. The
  record carries `context.transfer_outcome = "inferred"`, because a failure
  that leaves none of those traces reads as a success.
- **it was still running**: cancelled. A failure, `removed before curl
  finished it; cancelled`, with no response body.
- **it never ran**: nothing was sent, and nothing is recorded.

Recording happens once per transfer.

### Response bodies

Guzzle configures `CURLOPT_WRITEFUNCTION` to stream responses, so there is no
returned string for wiretap to read and those records carry
`omitted_reason: streaming` rather than a body. That is true of Guzzle's
synchronous path too and is not specific to async. Code using
`CURLOPT_RETURNTRANSFER`, including raw multi loops, records the body normally.

If you own the client, the bridge packages capture bodies in every case —
[`ssx/wiretap-guzzle`](https://github.com/ssx/wiretap-guzzle) and
[`ssx/wiretap-symfony`](https://github.com/ssx/wiretap-symfony). Run one
alongside this package and each call is still recorded once: the bridge
claims the requests it records, and the hooks record nothing for a claimed
transfer, on any redirect or retry hop. The bridge's record, with bodies, is
the one you get; this package keeps covering everything the bridge does not
see. That needs wiretap-guzzle v0.0.10 or wiretap-symfony v0.0.7 or later.

The claim is read where Guzzle's `CurlFactory` and Symfony's
`CurlHttpClient` build their curl handles. A client that builds handles some
other way, such as a custom `CurlFactoryInterface`, is recorded by both, which
is a duplicate record and nothing worse: the request itself is never changed.
`Wiretap::diagnostics()` reports `transfer_claim: honoured` when this is
active.

## How it works

`ext-opentelemetry` exposes PHP's `zend_observer` API to userland. This package
uses it to observe the whole curl handle lifecycle:

| Hook | Why it is needed |
| --- | --- |
| `curl_init` | register the handle, capture a URL passed to the constructor |
| `curl_setopt`, `curl_setopt_array` | curl options are **write-only** — there is no `curl_getopt()`, so the only way to know a handle's URL or POSTFIELDS is to watch every call go past |
| `curl_copy_handle` | a copied handle inherits the options, so the shadow state must be copied too |
| `curl_reset` | returns the handle to defaults, and is the one way a handle whose options are unknown becomes capturable again |
| `curl_exec` | pre: run the blocklist gate and install capture options. post: the return value **is** the response body |
| `curl_close` | not hooked: since PHP 8 it does nothing and the handle stays usable, so the shadow state lives until the handle is destroyed |

### Two things it deliberately does not do

**It does not force `CURLOPT_RETURNTRANSFER`.** Without it the application is
streaming to stdout or a file handle, and switching it changes where the
response goes. The body is recorded as `omitted: not-returned` instead. A
missing body is a bug report; a corrupted download is an incident.

**It does not set `CURLINFO_HEADER_OUT`.** That option makes curl keep the
request headers it sent, and hands them to anything that calls
`curl_getinfo()` — Authorization included. Guzzle copies them into handler
stats and exception context, so they reach logs and error trackers. It also
shares libcurl's debug slot with `CURLOPT_VERBOSE`, silently blanking verbose
output ([bug 65348](https://bugs.php.net/bug.php?id=65348)). Nor does it use
PHP 8.4's `CURLOPT_DEBUGFUNCTION`, which would see the same bytes: installing
one makes PHP store them in `curl_getinfo()` all the same, and makes an
application's own later `CURLINFO_HEADER_OUT` throw.

Instead the record rebuilds the request headers from the handle's options,
following libcurl's rules and order: `Host`, `Authorization` (Basic from
`CURLOPT_USERPWD`, `CURLOPT_USERNAME`/`PASSWORD` or the URL, Bearer from
`CURLOPT_XOAUTH2_BEARER`), `User-Agent`, `Accept`, `Accept-Encoding`,
`Referer`, `Cookie`, the application's own headers (which replace or, as
`Name:`, remove curl's), then the body's `Content-Length` and
`Content-Type`. It is marked `context.request_headers = "reconstructed"`, and
a record replays as the request the server received. What the options do not
determine is left out rather than guessed: Digest, NTLM and Negotiate, a
multipart boundary, `Expect`, cookies from curl's own jar, and body headers
after a redirect. The rebuilt `Authorization` and `Cookie` go through
redaction like any other header. If the application turned
`CURLINFO_HEADER_OUT` on itself, the headers actually sent are used and marked
`"sent"`.

The method and body on record follow libcurl's own method state, which every
method option moves: `CURLOPT_POST => false` or `NOBODY` set and then cleared
means GET, `UPLOAD` or `PUT` means PUT, a string `POSTFIELDS` survives a switch
to GET and is sent again by a later `POST => true`, and `CUSTOMREQUEST`
renames the method without changing which body goes out. An array
`POSTFIELDS` is sent as `multipart/form-data`, and is recorded that way: the
parts as curl writes them, with a boundary of wiretap's in place of curl's
random one (same length, so the same size), marked
`context.request_body = "reconstructed"`. Multipart is not a capturable type
by default, so those fields are stored only if you add `multipart/form-data`
to the capturable types, and a configured body path, which cannot be applied
to multipart, drops such a body rather than keep what it named.

An application's `CURLOPT_HEADERFUNCTION` is chained, never replaced. If it
is a private or protected method, which curl accepts from the application's
scope but wiretap cannot call from its own, the transfer is not captured
rather than have its callback dropped.

## Requirements

- **PHP 8.2+.** The extension runs on 8.0+, but observation of *internal*
  functions — which `curl_exec` is — arrived in PHP 8.2. On 8.1 the same API
  sees only userland functions, so raw curl would be invisible.
- **`ext-opentelemetry`.** Install with `pecl install opentelemetry`, then add
  `extension=opentelemetry.so` to the php.ini of the SAPI that actually runs
  your application, and restart its workers.

`opentelemetry.allow_stack_extension` is **not** required. It is only needed to
*add arguments* in a pre-hook, which this package never does.

Without the extension the package is inert rather than broken: it registers
nothing and records nothing. CI covers that case explicitly.

## Nothing is captured until you say so

```bash
WIRETAP_ENABLED=true
WIRETAP_PATH=/var/log/wiretap        # default: system temp
WIRETAP_BODY_LIMIT=65536
WIRETAP_SAMPLE_BP=10000              # basis points; 10000 = keep everything
WIRETAP_BLOCK=api.internal.test,*.acquirer.test
WIRETAP_REDACT=false                 # store plaintext; default on (core v0.0.19+)
WIRETAP_DISABLE_AUTO=true            # skip hook registration entirely
```

A package that started recording personal data the moment it was installed
would be indefensible, so capture is off unless `WIRETAP_ENABLED` is truthy.

Redaction is the other way round: on unless `WIRETAP_REDACT` is an
unmistakable false (`false`, `0`, `off` or `no`, any case). Unset, empty or a
typo leaves it on, so a misspelling never stores credentials in plaintext.

The `payment-gateways` and `cloud-metadata` blocklist presets are on by
default. Cloud metadata endpoints hand out short-lived IAM credentials;
capturing one puts a live token in your log.

## Wiring in your own recorder

```php
use Ssx\Wiretap\Auto\Wiretap;

Wiretap::setRecorder($myConfiguredRecorder);
```

Safe to call after autoload. The hooks resolve the recorder per call rather
than capturing it at registration, precisely so a framework booting later can
swap in one that is properly wired.

## Diagnostics

```php
print_r(Ssx\Wiretap\Auto\Wiretap::diagnostics());
```

Reports the extension state, whether hooks registered, live handle count,
blocklist pattern counts by source, and whether the blocklist has failed
closed. This exists because "why is nothing being recorded" otherwise costs an
afternoon.

## ⚠️ Do not leave it running

Wiretap records complete request and response bodies. See the
[main README](https://github.com/ssx/wiretap) — it is not PCI-DSS compliant and
not GDPR compliant on its own.

## Licence

MIT.
