## 2.4.0 - 07-07-2022

 * Fix a bug when multiple rules where used with a backend status code trigger

## 2.3.0 - 13-04-2022

 * Added the `redirectionio_trusted_proxies` configuration directive for correct ip matching - ([see the documentation](https://redirection.io/documentation/developer-documentation/nginx-module#redirectionio-trusted-proxies))
 * Added support for the IP address trigger (requires the version 2.3 of the agent)
 * Added support for the robots.txt action (requires the version 2.3 of the agent)
 * Added the possibility to disable log for a specific request using a rule (requires the version 2.3 of the agent)
 * Fixed an issue when a rule was serving a 200 response without the backend being called
 * Better options for sockets management in the dialog with the agent

## 2.2.2 - 22-09-2021

 * new release, for new distributions (debian 11 bullseye, and latest ubuntu)

## 2.2.1 - 11-05-2021

 * fix rare occurrence of agent socket not available for writing after starting the connection

## 2.2.0 - 06-05-2021

 * added the `redirectionio_set_header` directive - ([see the documentation](https://redirection.io/documentation/developer-documentation/nginx-module#redirectionio-set-header))
 * added connection pool management options to the `redirectionio_pass` directive: `min_conns`, `keep_conns`, `max_conns` and `timeout` - ([see the documentation](https://redirection.io/documentation/developer-documentation/nginx-module#redirectionio-pass))

## 2.1.1 - 16-04-2021

 * Fix double content encoding header in some edge cases

## 2.1.0 - 02-02-2021

 * Pass the client IP address to the agent

## 2.0.1 - 11-01-2021

 * Move redirectionio to access phase instead of pre access phase

## 2.0.0 - 11-01-2021

 * Send proxy version in logs
 * Send content-type in logs
 * Use 2.0.0 version of [libredirection](https://github.com/redirectionio/libredirectionio): more matching and actions available
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
