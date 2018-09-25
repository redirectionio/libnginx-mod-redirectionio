
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>


ngx_array_t *
ngx_array_create(ngx_pool_t *p, ngx_uint_t n, size_t size)
{
    ngx_array_t *a;

    a = ngx_palloc(p, sizeof(ngx_array_t));
    if (a == NULL) {
        return NULL;
    }

    if (ngx_array_init(a, p, n, size) != NGX_OK) {
        return NULL;
    }

    return a;
}


void
ngx_array_destroy(ngx_array_t *a)
{
    ngx_pool_t          *p;
    ngx_array_link_t    *link;

    p = a->pool;

    if (a->elts) {
        ngx_pfree(p, a->elts);
    }

    for (link = a->old_elts; link; link = link->next) {
        ngx_pfree(p, link->elts);
    }

    ngx_pfree(p, a);
}


void *
ngx_array_push(ngx_array_t *a)
{
    void                *elt, *new;
    size_t               size;
    ngx_pool_t          *p;
    ngx_array_link_t    *link;

    if (a->nelts == a->nalloc) {

        /* the array is full */

        size = a->size * a->nalloc;

        p = a->pool;

        /* allocate a new array */

        new = ngx_palloc(p, 2 * size);
        if (new == NULL) {
            return NULL;
        }

        ngx_memcpy(new, a->elts, size);

        link = ngx_palloc(p, sizeof(ngx_array_link_t));
        if (link == NULL) {
            ngx_pfree(p, new);
            return NULL;
        }

        link->next = a->old_elts;
        link->elts = a->elts;
        a->old_elts = link;

        a->elts = new;
        a->nalloc *= 2;
    }

    elt = (u_char *) a->elts + a->size * a->nelts;
    a->nelts++;

    return elt;
}


void *
ngx_array_push_n(ngx_array_t *a, ngx_uint_t n)
{
    void        *elt, *new;
    ngx_uint_t   nalloc;
    ngx_pool_t  *p;

    ngx_array_link_t    *link;

    if (a->nelts + n > a->nalloc) {

        /* the array is full */

        p = a->pool;

        nalloc = 2 * ((n >= a->nalloc) ? n : a->nalloc);

        new = ngx_palloc(p, nalloc * a->size);
        if (new == NULL) {
            return NULL;
        }

        ngx_memcpy(new, a->elts, a->nelts * a->size);

        link = ngx_palloc(p, sizeof(ngx_array_link_t));
        if (link == NULL) {
            ngx_pfree(p, new);
            return NULL;
        }

        link->next = a->old_elts;
        link->elts = a->elts;
        a->old_elts = link;

        a->elts = new;
        a->nalloc = nalloc;
    }

    elt = (u_char *) a->elts + a->size * a->nelts;
    a->nelts += n;

    return elt;
}
