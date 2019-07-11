# About

Nginx HTTP module to do redirections on data coming from https://redirection.io/

## Installation

When using the default nginx version of your distribution use this documentation to install the module
https://redirection.io/documentation/developer-documentation/nginx-module

### Manual

If your nginx version is different from the default distribution or your distribution is not supported
you have to compile this module yourself.

To manually build this library you will need to compile first the [libredirectionio library](https://github.com/redirectionio/libredirectionio)
in some path (e.g. `/tmp/libredirectionio`)

When compiling this module you need to use the **same exact source** and the **same exact compilation flags**
which were used to compile the nginx binary (some patches may be added compared to the official source).

You have to add the following directive on the `./configure` script:

`--add-dynamic-module=/path/to/nginx-redirectionio-module-source` for a dynamic module (loaded with a config directive)

or

`--add-module=/path/to/nginx-redirectionio-module-source` for a static module (present in the binary)

And also update the `with-cc-opt` and `with-ld-opt` flag to add the path where you compile the [libredirectionio library](https://github.com/redirectionio/libredirectionio)

```
--with-cc-opt="...-I/tmp/libredirectionio/target"
--with-ld-opt="... -L/tmp/libredirectionio/target/release"
```

You can look at our `dev-build.sh` script that use https://github.com/openresty/openresty-devel-utils scripts to compile this module in our dev environment.

## Directives

[See this documentation](https://redirection.io/documentation/developer-documentation/nginx-module#module-configuration-directives) for available directives

##  License

This code is licensed under the MIT License - see the  [LICENSE](./LICENSE.md)  file for details.
