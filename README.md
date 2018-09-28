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
