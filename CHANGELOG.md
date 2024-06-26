## 2.9.0 - 28-05-2024

* Update libredirectionio to 2.11.2

## 2.8.0 - 06-02-2024

* Update libredirectionio to 2.10.0
* Fix request time in log
* Add backend duration to log

## 2.7.0 - 03-10-2023

* Update libredirectionio to 2.9.0

## 2.6.0 - 26-05-2023

* Update libredirectionio to 2.8.0

## 2.5.0 - 20-03-2023

* Support new compression format for body filtering: deflate and brotli

## 2.4.2 - 23-11-2022

* Allow libredirectionio to modify the `Content-Type` header

## 2.4.1 - 27-10-2022

* Support gzip compression when filtering body, by updating libredirectionio deps

## 2.4.0 - 07-07-2022

* Fix a bug when multiple rules where used with a backend status code trigger

## 2.3.0 - 13-04-2022

* Add the `redirectionio_trusted_proxies` configuration directive for correct ip
  matching - ([see the documentation](https://redirection.io/documentation/developer-documentation/nginx-module#redirectionio-trusted-proxies))
* Add support for the IP address trigger (requires the version 2.3 of the agent)
* Add support for the robots.txt action (requires the version 2.3 of the agent)
* Add the possibility to disable log for a specific request using a rule (requires the version 2.3 of the agent)
* Fix an issue when a rule was serving a 200 response without the backend being called
* Better options for sockets management in the dialog with the agent

## 2.2.2 - 22-09-2021

* new release, for new distributions (debian 11 bullseye, and latest ubuntu)

## 2.2.1 - 11-05-2021

* fix rare occurrence of agent socket not available for writing after starting the connection

## 2.2.0 - 06-05-2021

* Add the `redirectionio_set_header`
  directive - ([see the documentation](https://redirection.io/documentation/developer-documentation/nginx-module#redirectionio-set-header))
* Add connection pool management options to the `redirectionio_pass` directive: `min_conns`, `keep_conns`, `max_conns`
  and `timeout` - ([see the documentation](https://redirection.io/documentation/developer-documentation/nginx-module#redirectionio-pass))

## 2.1.1 - 16-04-2021

* Fix double content encoding header in some edge cases

## 2.1.0 - 02-02-2021

* Pass the client IP address to the agent

## 2.0.1 - 11-01-2021

* Move redirectionio to access phase instead of pre access phase

## 2.0.0 - 11-01-2021

* Send proxy version in logs
* Send content-type in logs
* Use 2.0.0 version of [libredirection](https://github.com/redirectionio/libredirectionio): more matching and actions
  available
* **[BC BREAK]** New proxy protocol: please update the agent when updating the proxy to the 2.0 branch

## 0.5.0 - 15-02-2019

* Send request method in logs
* Add support for filtering header and body response with the agent
* Fix compilation on C99

## 0.4.0 - 18-01-2019

* Improve stability of the module
* Add support for matching redirection on response status code

## 0.3.2 - 28-11-2018

* Open source module

## 0.3.1 - 27-11-2018

* Stability fixes:
    * Avoid potential seg fault when reloading nginx
    * Fix memory leak issues

## 0.3.0 - 15-11-2018

* Add connection pool to limit number of parallels connections on heavy usage
* Better timeout when agent not responding under a specific time

## 0.2.0 - 14-11-2018

* New package name (switch from `redirectionio-nginx-module` to `libnginx-mod-redirectionio`)

## 0.1.0 - 31-10-2018

* Initial release
