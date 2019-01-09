# About

Nginx HTTP module to do redirections on data coming from https://redirection.io/

## Installation

When using the default nginx version of your distribution use this documentation to install the module 
https://redirection.io/documentation/developer-documentation/nginx-module

### Manual

If your nginx version is different from the default distribution or your distribution is not supported 
you have to compile this module yourself. 

When compiling this module you need to use the **same exact source** and the **same exact compilation flags** 
which were used to compile the nginx binary (some patches may be added compared to the official source).

You have to add the following directive on the `./configure` script: 

`--add-dynamic-module=/path/to/nginx-redirectionio-module-source` for a dynamic module (loaded with a config directive)

or

`--add-module=/path/to/nginx-redirectionio-module-source` for a static module (present in the binary)

## Directives

### redirectionio

**syntax:** *redirectionio on|off*

**default:** *off*

**context:** *http, server, server if, location, location if*

Enable or disable redirectionio matching process for request matching the current context.

### redirectionio_pass

**syntax:** *redirectionio_pass ip:port|unix:///path*

**default:** *127.0.0.1:10301*

**context:** *http, server, server if, location, location if*

Specify the Agent backend for matching requests

### redirectionio_project_key

**syntax:** *redirectionio_project_key key*

**default:** *none*

**context:** *http, server, server if, location, location if*

Set the project key to use for request matching the current context.

### redirectionio_no_logs

**syntax:** *redirectionio_no_logs on|off*

**default:** *[value of redirectionio directive]*

**context:** *http, server, server if, location, location if*

Disable or reenable logs for the current matching context
