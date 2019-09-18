# About

Nginx HTTP module to do redirections on data coming from https://redirection.io/

## Installation

When using the default nginx version of your distribution use this documentation to install the module
https://redirection.io/documentation/developer-documentation/nginx-module

### Manual

If your nginx version is different from the default distribution or your distribution is not supported
you have to compile this module yourself.

To manually build this library you will need to compile and install the [libredirectionio library](https://github.com/redirectionio/libredirectionio)

You can then do the following commands:

```
autoreconf -i
./configure
make
make install
```

#### Specific nginx version

You can also build the module against a specific version of nginx:

```
./configure --with-nginx-version=1.16.0
```

## Directives

[See this documentation](https://redirection.io/documentation/developer-documentation/nginx-module#module-configuration-directives) for available directives

##  License

This code is licensed under the MIT License - see the  [LICENSE](./LICENSE.md)  file for details.
