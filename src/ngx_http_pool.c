#include <ngx_http_pool.h>

static ngx_reslist_res_t *pop_resource(ngx_reslist_t *reslist);
static ngx_int_t push_resource(ngx_reslist_t *reslist, ngx_reslist_res_t *resource, int new);
static ngx_reslist_res_t *get_container(ngx_reslist_t *reslist);
static void free_container(ngx_reslist_t *reslist, ngx_reslist_res_t *container);
static ngx_int_t create_resource(ngx_reslist_t *reslist, ngx_reslist_res_t **ret_res);
static ngx_int_t destroy_resource(ngx_reslist_t *reslist, ngx_reslist_res_t *res);
static void reslist_cleanup(void *data);
static ngx_int_t reslist_maintain(ngx_reslist_t *reslist);
static void ngx_reslist_defer_maintain_handler(ngx_event_t *event);
static ngx_int_t ngx_reslist_defer_maintain(ngx_reslist_t *reslist);
static ngx_int_t ngx_reslist_call_acquire_resource(ngx_reslist_t *reslist, ngx_reslist_available callback, void *data, ngx_pool_t *pool, ngx_int_t deferred);

ngx_int_t ngx_reslist_maintain(ngx_reslist_t *reslist) {
    return reslist_maintain(reslist);
}

ngx_int_t ngx_reslist_create(ngx_reslist_t **rreslist, ngx_log_t *log, ngx_pool_t *pool, ngx_int_t min, ngx_int_t keep, ngx_int_t max, ngx_msec_t timeout, void *params, ngx_reslist_constructor constructor, ngx_reslist_destructor destructor) {
    ngx_reslist_t       *reslist;
    ngx_pool_cleanup_t  *cln;

    reslist = ngx_pcalloc(pool, sizeof(ngx_reslist_t));

    if (reslist == NULL) {
        return NGX_ERROR;
    }

    reslist->log = log;
    reslist->pool = pool;
    reslist->ntotal = 0;
    reslist->nidle = 0;
    reslist->min = min;
    reslist->keep = keep;
    reslist->max = max;
    reslist->timeout = timeout;
    reslist->params = params;
    reslist->constructor = constructor;
    reslist->destructor = destructor;

    ngx_queue_init(&reslist->res_avail_list);
    ngx_queue_init(&reslist->res_free_list);
    ngx_queue_init(&reslist->callback_avail_list);

    cln = ngx_pool_cleanup_add(pool, 0);
    cln->handler = reslist_cleanup;
    cln->data = reslist;

    *rreslist = reslist;

    return NGX_OK;
}

ngx_int_t ngx_reslist_acquire(ngx_reslist_t *reslist, ngx_reslist_available callback, ngx_pool_t *pool, void *data) {
    if (reslist->nidle > 0 || reslist->ntotal < reslist->max) {
        return ngx_reslist_call_acquire_resource(reslist, callback, data, pool, 0);
    }

    ngx_reslist_callback_queue_t *callback_available = ngx_pcalloc(pool, sizeof(ngx_reslist_callback_queue_t));

    if (callback_available == NULL) {
        return NGX_ERROR;
    }

    callback_available->callback = callback;
    callback_available->pool = pool;
    callback_available->data = data;

    ngx_queue_insert_head(&reslist->callback_avail_list, &callback_available->queue);

    return NGX_AGAIN;
}

ngx_int_t ngx_reslist_release(ngx_reslist_t *reslist, void *resource) {
    ngx_reslist_res_t   *res;

    res = get_container(reslist);
    res->resource = resource;
    push_resource(reslist, res, 0);

    // Deffer maintain
    ngx_reslist_defer_maintain(reslist);

    return NGX_OK;
}

ngx_int_t ngx_reslist_invalidate(ngx_reslist_t *reslist, void *resource) {
    ngx_int_t           rv;

    rv = reslist->destructor(resource, reslist->params, reslist->pool);
    reslist->ntotal--;

    // Deffer maintain
    ngx_reslist_defer_maintain(reslist);

    return rv;
}

static ngx_reslist_res_t *pop_resource(ngx_reslist_t *reslist) {
    ngx_reslist_res_t *res;

    res = ngx_queue_data(ngx_queue_head(&reslist->res_avail_list), ngx_reslist_res_t, queue_avail);

    ngx_queue_remove(&res->queue_avail);
    reslist->nidle--;

    return res;
}

static ngx_int_t push_resource(ngx_reslist_t *reslist, ngx_reslist_res_t *resource, int new) {
    ngx_queue_insert_head(&reslist->res_avail_list, &resource->queue_avail);

    reslist->nidle++;

    if (new) {
        reslist->ntotal++;
    }

    return NGX_OK;
}

static ngx_reslist_res_t *get_container(ngx_reslist_t *reslist) {
    ngx_reslist_res_t *res;

    if (!ngx_queue_empty(&reslist->res_free_list)) {
        res = ngx_queue_data(ngx_queue_head(&reslist->res_free_list), ngx_reslist_res_t, queue_free);

        ngx_queue_remove(&res->queue_free);
    } else {
        res = ngx_pcalloc(reslist->pool, sizeof(ngx_reslist_res_t));
    }

    return res;
}

static void free_container(ngx_reslist_t *reslist, ngx_reslist_res_t *container) {
    ngx_queue_insert_tail(&reslist->res_free_list, &container->queue_free);
}

static ngx_int_t create_resource(ngx_reslist_t *reslist, ngx_reslist_res_t **ret_res) {
    ngx_int_t           rv;
    ngx_reslist_res_t   *res;

    res = get_container(reslist);

    rv = (reslist->constructor)(&res->resource, reslist->params, reslist->pool);
    *ret_res = res;

    return rv;
}

static ngx_int_t destroy_resource(ngx_reslist_t *reslist, ngx_reslist_res_t *res) {
    return (reslist->destructor)(res->resource, reslist->params, reslist->pool);
}

static void reslist_cleanup(void *data) {
    ngx_reslist_t *rl   = data;
    ngx_reslist_res_t   *res;

    while (rl->nidle > 0) {
        res = pop_resource(rl);
        rl->ntotal--;
        destroy_resource(rl, res);
        free_container(rl, res);
    }
}

static ngx_int_t reslist_maintain(ngx_reslist_t *reslist) {
    ngx_int_t                       rv;
    ngx_reslist_res_t               *res;
    ngx_reslist_callback_queue_t    *callback_queue;
    int                             created_one = 0;

    /* Check if we need to create more resources, and if we are allowed to. */
    while (reslist->nidle < reslist->min && reslist->ntotal < reslist->max) {
        rv = create_resource(reslist, &res);

        if (rv != NGX_OK) {
            free_container(reslist, res);

            return rv;
        }

        rv = push_resource(reslist, res, 1);

        if (rv != NGX_OK) {
            return rv;
        }

        created_one++;
    }

    while (!ngx_queue_empty(&reslist->callback_avail_list) && (reslist->nidle > 0 || reslist->ntotal < reslist->max)) {
        callback_queue = ngx_queue_data(ngx_queue_last(&reslist->callback_avail_list), ngx_reslist_callback_queue_t, queue);
        ngx_queue_remove(&callback_queue->queue);

        rv = ngx_reslist_call_acquire_resource(reslist, callback_queue->callback, callback_queue->data, callback_queue->pool, 1);

        if (rv != NGX_OK) {
            return rv;
        }
    }

    while (reslist->nidle > reslist->keep && reslist->nidle > 0) {
        res = ngx_queue_data(ngx_queue_last(&reslist->res_avail_list), ngx_reslist_res_t, queue_avail);
        ngx_queue_remove(&res->queue_avail);
        reslist->nidle--;
        reslist->ntotal--;

        rv = destroy_resource(reslist, res);
        free_container(reslist, res);

        if (rv != NGX_OK) {
            return rv;
        }
    }

    return NGX_OK;
}

static void ngx_reslist_defer_maintain_handler(ngx_event_t *event) {
    ngx_reslist_t   *reslist = (ngx_reslist_t *)event->data;
    ngx_reslist_maintain(reslist);

    free(event);
}

static ngx_int_t ngx_reslist_defer_maintain(ngx_reslist_t *reslist) {
    ngx_event_t     *event;

    event = malloc(sizeof(ngx_event_t));
    event->data = reslist;
    event->log = reslist->log;
    event->index = NGX_INVALID_INDEX;
    event->handler = ngx_reslist_defer_maintain_handler;
    event->ready = 1;
    event->posted = 0;

    ngx_post_event(event, &ngx_posted_events);

    return NGX_OK;
}

static ngx_int_t ngx_reslist_call_acquire_resource(ngx_reslist_t *reslist, ngx_reslist_available callback, void *data, ngx_pool_t *pool, ngx_int_t deferred) {
    ngx_reslist_res_t   *res;

    if (ngx_queue_empty(&reslist->res_avail_list)) {
        if (create_resource(reslist, &res) == NGX_OK) {
            reslist->ntotal++;
        }

        free_container(reslist, res);
    } else {
        res = pop_resource(reslist);
        free_container(reslist, res);
    }

    return (callback)(res->resource, data, pool, deferred);
}
