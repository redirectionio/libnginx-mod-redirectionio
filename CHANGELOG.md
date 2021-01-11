## 2.0.1 - 11-01-2021

 * Move redirectionio to access phase instead of pre access phase

## 2.0.0 - 11-01-2021

 * Send proxy version in logs
 * Send content type in logs
 * Use 2.0.0 version of libredirection: more matching and actions availables
 * [BC BREAK] Use new agent protocol (only compatible with agent in 2.0 or more)

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

 * New package name (switch from redirectionio-nginx-module to libnginx-mod-redirectionio)

## 0.1.0 - 31-10-2018

 * Initial release
