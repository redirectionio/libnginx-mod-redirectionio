# Nginx Module

#### Installation

```
fab local.infastructure.build
```

#### Compile nginx + module and execute nginx with it

```
fab local.nginx.compile_and_test
```

#### Compile nginx + module and execute nginx with it and will output memory error into memory.log file

```
fab local.nginx.compile_and_test_memory_leaks
```

#### Rebuild from scratch (clean + build)

```
touch clients/nginx-redirectionio-module/config
fab local.nginx.compile_and_test[_memory_leaks]
```

#### Building modules for distribs

````
docker build -f clients/nginx-redirectionio-module/Dockerfile[distrib] -t modulecompile clients/nginx-redirectionio-module
docker run -ti -v `pwd`/clients:/root/clients modulecompile
````

### Proxy Directives

#### redirectionio

**syntax:** *redirectionio on|off*

**default:** *off*

**context:** *http, server, server if, location, location if*

Enable or disable redirectionio matching process for request matching the current context.

#### redirectionio_project_key

**syntax:** *redirectionio_project_key key*

**default:** *none*

**context:** *http, server, server if, location, location if*

Set the project key to use for request matching the current context.

#### redirectionio_no_logs

**syntax:** *redirectionio_no_logs on|off*

**default:** *off*

**context:** *http, server, server if, location, location if*

Disable or reenable logs for the current matching context

#### redirectionio_pass

**syntax:** *redirectionio_pass ip:port|unix:///path*

**default:** *127.0.0.1:10301*

**context:** *http, server, server if, location, location if*

Specify the Agent backend for matching requests

### Agent Directives

#### redirectionio_agent_enable

**syntax:** *redirectionio_agent_enable on|off*

**default:** *on*

**context:** *http*

Enable or disable launching a redirectionio agent from nginx

#### redirectionio_listen

**syntax:** *redirectionio_listen ip:port|unix:///path*

**default:** *127.0.0.1:10301*

**context:** *http*

Specify the backend network where the agent should listen to

#### redirectionio_host

**syntax:** *redirectionio_host ip:port|unix:///path*

**default:** *https://api.redirection.io*

**context:** *http*

On which host the agent should make api calls

#### redirectionio_instance_name

**syntax:** *redirectionio_instance_name ip:port|unix:///path*

**default:** *machine hostname*

**context:** *http*

Identifier for the agent that allows to trace logs and update from the manager

#### redirectionio_persist

**syntax:** *redirectionio_persist on|off*

**default:** *on*

**context:** *http*

Whether or not rules should be persisted on disk

#### redirectionio_datadir

**syntax:** *redirectionio_datadir ip:port|unix:///path*

**default:** */var/lib/redirectionio*

**context:** *http*

On which directory rules should be stored

#### redirectionio_cache

**syntax:** *redirectionio_cache on|off*

**default:** *on*

**context:** *http*

Whether or not rules should be cached, when enabled it will consume more memory but will respond faster, when disabled
consumes less memory but slower.

#### redirectionio_debug

**syntax:** *redirectionio_debug on|off*

**default:** *off*

**context:** *http*

Enable or disable debug log for the agent (if enable error_log of nginx should be set to debug too)
