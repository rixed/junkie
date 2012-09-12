#ifndef HOOK_H_120822
#define HOOK_H_120822

/* A hook is composed of a list of subscribers and a mutex.
 */
#define HOOK(name) \
    static struct proto_subscribers name##_subscribers; \
    static struct mutex name##_subscribers_lock; \
    static void name##_hook_init(void) \
    { \
        LIST_INIT(&name##_subscribers); \
        mutex_ctor(&name##_subscribers_lock, STRIZE(name) " subscribers"); \
    } \
    static void name##_hook_fini(void) \
    { \
        if (! LIST_EMPTY(&name##_subscribers)) { \
            SLOG(LOG_NOTICE, "Some " STRIZE(name) " subscribers are still registered"); \
        } \
        mutex_dtor(&name##_subscribers_lock); \
    } \
    int name##_subscriber_ctor(struct proto_subscriber *sub, proto_cb_t *cb) \
    { \
        SLOG(LOG_DEBUG, "Construct a new " STRIZE(name) " subscriber@%p", sub); \
        sub->cb = cb; \
        mutex_lock(&name##_subscribers_lock); \
        LIST_INSERT_HEAD(&name##_subscribers, sub, entry); \
        mutex_unlock(&name##_subscribers_lock); \
        return 0; \
    } \
    void name##_subscriber_dtor(struct proto_subscriber *sub) \
    { \
        SLOG(LOG_DEBUG, "Destruct a " STRIZE(name) " subscriber@%p", sub); \
        mutex_lock(&name##_subscribers_lock); \
        LIST_REMOVE(sub, entry); \
        mutex_unlock(&name##_subscribers_lock); \
    } \
    void name##_subscribers_call(struct proto_info *info, size_t tot_cap_len, uint8_t const *tot_packet, struct timeval const *now) \
    { \
        mutex_lock(&name##_subscribers_lock); \
        struct proto_subscriber *sub; \
        LIST_FOREACH(sub, &name##_subscribers, entry) { \
            sub->cb(sub, info, tot_cap_len, tot_packet, now); \
        } \
        mutex_unlock(&name##_subscribers_lock); \
    }

#endif
