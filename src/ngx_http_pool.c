#include <ngx_http_pool.h>

static ngx_int_t ngx_reslist_defer_maintain(ngx_reslist_t *reslist);
static ngx_int_t ngx_reslist_create_resource(ngx_reslist_t *reslist);
static ngx_int_t ngx_reslist_call_acquire_resource(ngx_reslist_t *reslist, ngx_reslist_available callback, void *data, ngx_pool_t *pool, ngx_int_t deferred);
static ngx_int_t ngx_reslist_delete_resource(ngx_reslist_t *reslist);
static ngx_int_t ngx_reslist_delete_free_resource(ngx_reslist_t *reslist, resource_queue_t *rq);
static ngx_int_t ngx_reslist_delete_avail_resource(ngx_reslist_t *reslist, resource_queue_t *rq);
static void ngx_reslist_defer_maintain_handler(ngx_event_t *event);

ngx_reslist_t* ngx_reslist_create(ngx_log_t *log, ngx_pool_t *pool, ngx_int_t min, ngx_int_t keep, ngx_int_t max, ngx_msec_t timeout, void *params, ngx_reslist_constructor constructor, ngx_reslist_destructor destructor) {
    ngx_reslist_t *reslist;

    reslist = ngx_pcalloc(pool, sizeof(ngx_reslist_t));

    reslist->log = log;
    reslist->pool = pool;
    reslist->navail = 0;
    reslist->nfree = 0;
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

    // @TODO Add cleanup fonction

    return reslist;
}

ngx_int_t ngx_reslist_acquire(ngx_reslist_t *reslist, ngx_reslist_available callback, ngx_pool_t *pool, void *data) {
    if (reslist->nfree > 0 || reslist->navail < reslist->max) {
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

    // Deffer maintain
    ngx_reslist_defer_maintain(reslist);

    return NGX_AGAIN;
}

ngx_int_t ngx_reslist_release(ngx_reslist_t *reslist, void *resource) {
    resource_queue_t    *rq;
    ngx_queue_t         *q;

    if (resource == NULL) {
        return NGX_OK;
    }

    // Call callbacks for each free resource or create the resource if max not reached (and free the structure)
    for (q = ngx_queue_head(&reslist->res_avail_list); q != ngx_queue_sentinel(&reslist->res_avail_list); q = ngx_queue_next(q)) {
        rq = ngx_queue_data(q, resource_queue_t, queue_avail);

        if (rq->resource == resource) {
            break;
        }

        rq = NULL;
    }

    if (rq == NULL) {
        return NGX_ERROR;
    }

    ngx_queue_insert_head(&reslist->res_free_list, &rq->queue_free);
    reslist->nfree++;

    // Deffer maintain
    ngx_reslist_defer_maintain(reslist);

    return 0;
}

ngx_int_t ngx_reslist_invalidate(ngx_reslist_t *reslist, void *resource) {
    ngx_int_t           status;
    resource_queue_t    *rq;
    ngx_queue_t         *q;

    if (resource == NULL) {
        return NGX_OK;
    }

    // Call callbacks for each free resource or create the resource if max not reached (and free the structure)
    for (q = ngx_queue_head(&reslist->res_avail_list); q != ngx_queue_sentinel(&reslist->res_avail_list); q = ngx_queue_next(q)) {
        rq = ngx_queue_data(q, resource_queue_t, queue_avail);

        if (rq->resource == resource) {
            break;
        }

        rq = NULL;
    }

    if (rq == NULL) {
        return NGX_ERROR;
    }

    status = ngx_reslist_delete_avail_resource(reslist, rq);

    if (status != NGX_OK) {
        return status;
    }

    // Deffer maintain
    ngx_reslist_defer_maintain(reslist);

    return NGX_OK;
}

ngx_int_t ngx_reslist_maintain(ngx_reslist_t *reslist) {
    ngx_int_t                       status;
    ngx_queue_t                     *q;
    ngx_reslist_callback_queue_t    *callback_queue;

    while (reslist->navail < reslist->min) {
        status = ngx_reslist_create_resource(reslist);

        if (status != NGX_OK) {
            return status;
        }
    }

    while (!ngx_queue_empty(&reslist->callback_avail_list) && reslist->navail < reslist->max) {
        q = ngx_queue_last(&reslist->callback_avail_list);
        callback_queue = ngx_queue_data(q, ngx_reslist_callback_queue_t, queue);
        ngx_queue_remove(&callback_queue->queue);

        status = ngx_reslist_call_acquire_resource(reslist, callback_queue->callback, callback_queue->data, callback_queue->pool, 1);

        if (status != NGX_OK) {
            return status;
        }
    }

    // Remove not needed resources
    while (!ngx_queue_empty(&reslist->res_free_list) && reslist->navail > reslist->keep) {
        status = ngx_reslist_delete_resource(reslist);

        if (status != NGX_OK) {
            return status;
        }
    }

    return NGX_OK;
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

static ngx_int_t ngx_reslist_create_resource(ngx_reslist_t *reslist) {
    ngx_int_t                   status;
    resource_queue_t            *rq;

    rq = ngx_pcalloc(reslist->pool, sizeof(resource_queue_t));

    if (rq == NULL) {
        return NGX_ERROR;
    }

    status = (reslist->constructor)(&rq->resource, reslist->params, reslist->pool);

    if (status != NGX_OK) {
        return status;
    }

    // Add this queue to the res and free list
    ngx_queue_insert_head(&reslist->res_avail_list, &rq->queue_avail);
    ngx_queue_insert_head(&reslist->res_free_list, &rq->queue_free);

    reslist->navail++;
    reslist->nfree++;

    return NGX_OK;
}

static ngx_int_t ngx_reslist_call_acquire_resource(ngx_reslist_t *reslist, ngx_reslist_available callback, void *data, ngx_pool_t *pool, ngx_int_t deferred) {
    ngx_queue_t         *q;
    resource_queue_t    *rq;
    ngx_int_t           status;

    // Create a resource if none are free
    if (ngx_queue_empty(&reslist->res_free_list)) {
        status = ngx_reslist_create_resource(reslist);

        if (status != NGX_OK) {
            return status;
        }
    }

    q = ngx_queue_last(&reslist->res_free_list);
    rq = ngx_queue_data(q, resource_queue_t, queue_free);

    ngx_queue_remove(&rq->queue_free);
    reslist->nfree--;

    return (callback)(rq->resource, data, pool, deferred);
}

static ngx_int_t ngx_reslist_delete_resource(ngx_reslist_t *reslist) {
    ngx_queue_t         *q;
    resource_queue_t    *rq;

    if (ngx_queue_empty(&reslist->res_free_list)) {
        return NGX_OK;
    }

    q = ngx_queue_last(&reslist->res_free_list);
    rq = ngx_queue_data(q, resource_queue_t, queue_free);

    ngx_reslist_delete_free_resource(reslist, rq);

    return ngx_reslist_delete_avail_resource(reslist, rq);
}

static ngx_int_t ngx_reslist_delete_free_resource(ngx_reslist_t *reslist, resource_queue_t *rq) {
    ngx_queue_remove(&rq->queue_free);
    reslist->nfree--;

    return NGX_OK;
}

static ngx_int_t ngx_reslist_delete_avail_resource(ngx_reslist_t *reslist, resource_queue_t *rq) {
    ngx_queue_remove(&rq->queue_avail);
    reslist->navail--;

    return (reslist->destructor)(rq->resource, reslist->params, reslist->pool);
}

static void ngx_reslist_defer_maintain_handler(ngx_event_t *event) {
    ngx_reslist_t   *reslist = (ngx_reslist_t *)event->data;
    ngx_reslist_maintain(reslist);

    free(event);
}
