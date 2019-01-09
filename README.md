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

[See this documentation](https://redirection.io/documentation/developer-documentation/nginx-module#module-configuration-directives) for available directives
