#ifndef redirectionio_pool_h
#define redirectionio_pool_h

#include <ngx_core.h>
#include <ngx_event_posted.h>

typedef struct ngx_reslist_callback_queue_s     ngx_reslist_callback_queue_t;
typedef struct ngx_reslist_res_s                ngx_reslist_res_t;
typedef struct ngx_reslist_s                    ngx_reslist_t;

typedef ngx_int_t (*ngx_reslist_available)(ngx_reslist_t *reslist, void *resource, void *data, ngx_int_t deferred);

typedef ngx_int_t (*ngx_reslist_constructor)(void **resource, void *params, ngx_pool_t *pool);

typedef ngx_int_t (*ngx_reslist_destructor)(void *resource, void *params, ngx_pool_t *pool);

struct ngx_reslist_callback_queue_s {
    ngx_reslist_available   callback;
    void                    *data;
    void                    *resource;
    ngx_queue_t             queue;
    ngx_event_t             event;
    ngx_reslist_t           *reslist;
};

struct ngx_reslist_res_s {
    time_t      freed;
    void        *resource;
    ngx_queue_t queue_avail;
    ngx_queue_t queue_free;
};

struct ngx_reslist_s {
    ngx_log_t                       *log;
    ngx_pool_t                      *pool;          /* the pool used in constructor and destructor calls */
    ngx_int_t                       ntotal;         /* total number of resources managed by this list */
    ngx_int_t                       nidle;          /* number of available resources */
    ngx_int_t                       min;            /* desired minimum number of available resources */
    ngx_int_t                       keep;           /* soft maximum on the total number of resources */
    ngx_int_t                       max;            /* hard maximum on the total number of resources */
    time_t                          ttl;            /* Resource time to live in seconds */
    ngx_msec_t                      timeout;        /* Timeout for waiting on resource */
    ngx_reslist_constructor         constructor;
    ngx_reslist_destructor          destructor;
    void                            *params;        /* opaque data passed to constructor and destructor calls */
    ngx_queue_t                     res_avail_list; /* List of all resources of this pool */
    ngx_queue_t                     res_free_list;  /* List of all resources free of this pool */
    ngx_queue_t                     callback_avail_list; /* List of callbacks to calls when a resource is available */
};

ngx_int_t ngx_reslist_create(ngx_reslist_t **rreslist, ngx_log_t *log, ngx_pool_t *pool, ngx_int_t min, ngx_int_t keep, ngx_int_t max, ngx_msec_t timeout, void *params, ngx_reslist_constructor constructor, ngx_reslist_destructor destructor);

ngx_int_t ngx_reslist_acquire(ngx_reslist_t *reslist, ngx_reslist_available callback, void *data);

ngx_int_t ngx_reslist_release(ngx_reslist_t *reslist, void *resource);

ngx_int_t ngx_reslist_invalidate(ngx_reslist_t *reslist, void *resource);

ngx_int_t ngx_reslist_maintain(ngx_reslist_t *reslist);

#endif
