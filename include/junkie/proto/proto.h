// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#ifndef PROTO_H_100330
#define PROTO_H_100330
#include <stdint.h>
#include <stddef.h>
#include <sys/time.h>
#include <libguile.h>
#include <pthread.h>
#include <junkie/config.h>
#include <junkie/cpp.h>
#include <junkie/tools/log.h>
#include <junkie/tools/miscmacs.h>
#include <junkie/tools/queue.h>
#include <junkie/tools/timeval.h>
#include <junkie/tools/mutex.h>
#include <junkie/tools/ref.h>
#include <junkie/tools/bench.h>

/** @file
 * @brief Packet inspection
 *
 * Each packet received from libpcap is passed to a toplevel "capture" parser,
 * which then builds a small struct proto_info describing the packet and
 * handling the payload to a child parser. This child parser performs in a
 * similar fashion, extracting from the received data the interesting bits,
 * building another struct proto_info describing this parser and handling the
 * payload to yet another parser, etc... Eventually the whole packet will be
 * inspected, with various content involving several protocols one or several
 * times.  Each time a proto_info is construct for a given protocol, callbacks
 * registered for this proto are called with the list of all the proto_infos
 * from packet root up to this proto layer.
 *
 * Parsers are designed in order to be (as most as possible) independent on
 * each others. Their aim is to extract from the packet only the informations
 * regarding the protocol they implement (ie. the information that are easy to
 * extract in realtime but presumed meaningful for a large set of callbacks).
 *
 * Having independent parsers implies that every parser is committed to a given
 * behavior. For instance, every protocol parser must have a single parse
 * function receiving the relevant data from its parent and its parent's
 * proto_info (which can be used to inspect upper layers). This common behavior
 * is inherited from the struct proto that defines the behavior of all parsers
 * of this proto.
 *
 * We have several constraints/wishes to take into account :
 *
 * - we want to store all gathered informations on the stack so that we don't
 * have to handle memory allocation for these transient data structures;
 *
 * - we want a parser to be able to call several sub-parsers on the same data
 * if its unsure which parser should handle a payload;
 *
 * - for robustness we would like junkie to keep working if for some reason a
 * parser is unable to operate (lack some resource).
 *
 * How can a parser call a sub-parser if they do not know each other? For
 * instance, how can IP call UDP parser? Either IP has to know UDP and call it
 * directly for proper protocol field, or UDP has to know that there is that IP
 * parser which dispatch its payload according to a protocol field, and register
 * for the protocol 17. This later alternative, although more complex, was
 * chosen because it is more general and also make it possible to configure any
 * other mapping in runtime (for instance, ask for HTTP parsing on TCP port
 * 8080 as well as 80).
 *
 * Either way, the struct proto describing a parser has to be public so that a
 * parser can spawn a new parser for this protocol. But that's the only link
 * that exists between two parsers, and apart from the case where a parser look
 * something into one of its parent's proto_info then one can safely modify a
 * parser implementation without interfering with any other parsers.
 *
 * Regarding callbacks, please bear in mind that many are called for every
 * packet.  Even a given one can be called several times for the same packet.
 * This is contrary to the rule that was prevailing with previous versions of
 * junkie (prior to version 2.0), and makes pcap writing/injecting more
 * complex.  The benefit is to allow more in depth analyses to free the upper
 * protocol layers from the bounds of individual packets.
 */

/// The various possible exit codes of the parse functions
enum proto_parse_status {
    /// When a parser (not necessarily its children) recognize its protocol
    PROTO_OK,
    /// When a parser does not recognize its protocol
    PROTO_PARSE_ERR,
    /** When a parser can't tell if the payload belongs to him because the capture length is not enough
     *  (proto_parse will return PROTO_OK to the parent) */
    PROTO_TOO_SHORT,
};

char const *proto_parse_status_2_str(enum proto_parse_status status);

struct parser;
struct proto;
struct proto_info;
struct proto_subscriber;

typedef enum proto_parse_status parse_fun(
    struct parser *parser,      ///< The parser to hand over the payload to, or NULL if no protocol suit the payload
    struct proto_info *parent,  ///< It's parent proto_info (NULL for gaps)
    unsigned way,               ///< Direction identifier (@see struct mux_proto)
    uint8_t const *packet,      ///< Raw data to parse (may be NULL)
    size_t cap_len,             ///< How many bytes are present in packet (0 to report a gap in data)
    size_t wire_len,            ///< How many bytes were present on the wire
    struct timeval const *now,  ///< The current time
    size_t tot_cap_len,         ///< The capture length of the total packet (to be passed to subscribers) (0 for gaps)
    uint8_t const *tot_packet   ///< The total packet (to be passed to subscribers) (may be NULL)
);

/// The callback function for proto subscribers
typedef void proto_cb_t(struct proto_subscriber *, struct proto_info const *, size_t tot_cap_len, uint8_t const *tot_packet, struct timeval const *ts);

/// A subscriber is a plugin that want to be called for each proto_info of a given proto.
/** Previous junkie 1.5 each plugin had a callback function that was called for every packet.
 * This is not the case anymore. Now if you are interested in a particular proto_info then
 * you are required to register a callback with hook_subscriber_ctor(&proto->hook, ...).
 * Notice that there are no lock in this structure, so the callback must be thread safe. */
struct proto_subscriber {
    LIST_ENTRY(proto_subscriber) entry; ///< In the list of all proto subscribers
    proto_cb_t *cb;
};

/// A hook is composed of a list of subscribers and a mutex.
struct hook {
    char const *name;
    LIST_HEAD(proto_subscribers, proto_subscriber) subscribers;
    struct rwlock lock;
};

void hook_ctor(struct hook *, char const *);
void hook_dtor(struct hook *);
int hook_subscriber_ctor(struct hook *, struct proto_subscriber *, proto_cb_t *cb);
void hook_subscriber_dtor(struct hook *, struct proto_subscriber *);
void hook_subscribers_call(struct hook *, struct proto_info *, size_t, uint8_t const *, struct timeval const *);

/// Call all subscribers of given proto (same as normal hook_subscribers_call but ensure we call it no more than once per packet)
void proto_subscribers_call(struct proto *proto, struct proto_info *info, size_t tot_cap_len, uint8_t const *tot_packet, struct timeval const *now);

/// Call all subscribers of per-packet hook
void full_pkt_subscribers_call(struct proto_info *, size_t tot_cap_len, uint8_t const *tot_packet, struct timeval const *now);

/// Subscriber to packet (not protocolar events)
/** Many plugins want to be called once per packet, with a good but not necessarily
 * comprehensive description of the packet content, in a way similar to what was
 * offered by junkie v1.x. This is possible with this special case of subscription.
 * Technically, these subscribers will be called only when there are no more subparsers,
 * once per packet. We use a special bit in the cap proto_info to tell when packet
 * subscribers have already been called (which is not perfect since the cap proto_info
 * is deep in the stack.
 * Again, notice the callback must be thread safe. */
extern struct hook pkt_hook;

/// A protocol implementation.
/** Only one instance for each protocol ever exist (located in the protocol compilation unit).
 * Can be overloaded to achieve special behavior (for instance see mux_proto or uniq_proto).
 *
 * A proto is basically a name (for instance "TCP"), a set of operations and a list
 * of parsers sharing the same implementation of these operations.
 *
 * @see mux_proto and uniq_proto */
struct proto {
    /// The methods that must be implemented
    struct proto_ops {
        /// Parse some data from the captured frame
        parse_fun *parse;
        /// Create a new parser of this protocol
        /// (notice that if the parser is stateless there is actually only one instance of it, refcounted)
        struct parser *(*parser_new)(struct proto *proto);
        /// Delete a parser
        void (*parser_del)(struct parser *parser);
        /// Pretty-print an info structure into a string
        char const *(*info_2_str)(struct proto_info const *);
        /// Return the start address and size of an overloaded proto_info (used to copy it, see pkt_wait_list)
        void const *(*info_addr)(struct proto_info const *, size_t *);
    } const *ops;
    char const *name;       ///< Protocol name, used mainly for pretty-printing
    bool enabled;           ///< so that we can disable/enable a protocol at runtime
    enum proto_code {
        PROTO_CODE_CAP, PROTO_CODE_ETH, PROTO_CODE_ARP,
        PROTO_CODE_IP, PROTO_CODE_IP6, PROTO_CODE_UDP,
        PROTO_CODE_TCP, PROTO_CODE_DNS, PROTO_CODE_DNSoTCP, PROTO_CODE_FTP,
        PROTO_CODE_GRE, PROTO_CODE_HTTP, PROTO_CODE_ICMP,
        PROTO_CODE_MGCP, PROTO_CODE_RTCP, PROTO_CODE_RTP,
        PROTO_CODE_SDP, PROTO_CODE_SIP, PROTO_CODE_TNS,
        PROTO_CODE_PGSQL, PROTO_CODE_MYSQL,
        PROTO_CODE_NETBIOS, PROTO_CODE_CIFS, PROTO_CODE_TLS, PROTO_CODE_ERSPAN,
        PROTO_CODE_SKINNY, PROTO_CODE_DHCP,
        PROTO_CODE_DISCOVERY, PROTO_CODE_DUMMY, PROTO_CODE_FCOE,
        PROTO_CODE_TDS, PROTO_CODE_TDS_MSG,
        PROTO_CODE_GTP, PROTO_CODE_VXLAN,
        PROTO_CODE_MAX
    } code;                 ///< Numeric code used for instance to serialize these events
    uint64_t nb_frames;     ///< How many times we called this parse (count frames only if this parser is never called more than once on a frame)
    uint64_t nb_bytes;      ///< How many bytes this proto had on wire
    /// How many parsers of this proto exists
    unsigned nb_parsers;
    /// Entry in the list of all registered protos
    LIST_ENTRY(proto) entry;
    /// Fuzzing statistics: number of time this proto has been fuzzed.
    unsigned fuzzed_times;
    /// Hook to be called back for each packet involving this proto
    struct hook hook;
    /// Mutex to protect the mutable values of this proto (entry, parsers, nb_parsers, nb_frames, subscribers list)
    struct mutex lock;
    /// Some benchmark counters
    struct bench_event parsing; // measure time spent parsing this protocol
};

/// The list of registered protos
extern LIST_HEAD(protos, proto) protos;

/// Use it to initialize a proto that's not yet implemented
extern struct proto *proto_dummy;

/// Constructor for struct proto.
void proto_ctor(
    struct proto *proto,            ///< The proto to construct
    struct proto_ops const *ops,    ///< The ops structure of this implementation
    char const *name,               ///< A name for the proto
    enum proto_code code            ///< The numeric code identifying this proto
);

/// Destruct a proto (some parsers may still be present after this if referenced by other parsers)
void proto_dtor(struct proto *proto);

/// Call this instead of accessing proto->ops->parse, so that counters are updated properly.
parse_fun proto_parse;

/// Lookup by name in the list of registered protos
/** @returns NULL if not found. */
struct proto *proto_of_name(char const *);

/// Lookup by proto_code in the list of registered protos
/** @returns NULL if not found. */
struct proto *proto_of_code(enum proto_code);

/// Protocol Informations.
/** A proto parse function is supposed to overload this (publicly) and stores
 * all relevant informations gathered from the frame into its specialized
 * proto_info.  The protocol stack is made of struct proto_info linked together
 * up to the capture layer.  The last one is passed to the "continuation" (from
 * this last one the whole protocol stack can be accessed through the "parent"
 * pointer). */
struct proto_info {
    struct proto_info *parent;  ///< Previous proto_info, or NULL if we are at root (ie proto = capture)
    struct parser *parser;      ///< The parser that generated this structure
    /// Common information that all protocol must fill one way or another
    size_t head_len;            ///< Size of the header
    size_t payload;             ///< Size of the embedded payload (including what we did not capture from the wire)
    bool proto_sbc_called;      ///< The subscribers for this proto were already called (avoids calling several times the sbcs in various circumstances)
    bool pkt_sbc_called;        ///< The packet subscribers where already called for this packet and should not be called again (only used when at the bottom of the proto_info stack)
};

/// Constructor for a proto_info
void proto_info_ctor(
    struct proto_info *info,    ///< The proto_info to construct
    struct parser *parser,      ///< The parser it belongs to
    struct proto_info *parent,  ///< Previous proto_info
    size_t head_len,            ///< Preset this header length
    size_t payload              ///< and this payload.
);

/// Base implementation for info_2_str method.
/** Use it into your own to display head_len and payload. */
char const *proto_info_2_str(struct proto_info const *);

/// Base implementation for info_addr method.
/** Use it if you do not overload proto_info (?) */
void const *proto_info_addr(struct proto_info const *, size_t *);

/// Helper for metric modules.
/** @returns the last proto_info owned by the given proto, or NULL if not found.
 */
struct proto_info const *proto_info_get(
    struct proto const *proto,      ///< The proto to look for
    struct proto_info const *last   ///< Where to start looking for (may be NULL)
);

/** @returns the last proto_info owned by any of the given protos, or NULL.
 * Useful for ipv4/ipv6 for instance */
struct proto_info const *proto_info_get_any(
    unsigned nb_protos,             ///< Length of following array
    struct proto const **protos,    ///< The protos to look for
    struct proto_info const *last   ///< Where to start looking for (may be NULL)
);

#define ASSIGN_INFO_OPT(proto, last) \
    struct proto_info const *proto##_proto__ = proto_info_get(proto_##proto, last); \
    struct proto##_proto_info const *proto = proto##_proto__ ? DOWNCAST(proto##_proto__, info, proto##_proto_info) : NULL;

/// Used if both TCP and UDP can handle a upper protocol (say... DNS or SIP)
#define ASSIGN_INFO_OPT2(proto1, proto2, last) \
    struct proto1##_proto_info const *proto1 = NULL; \
    struct proto2##_proto_info const *proto2 = NULL; \
    { \
        struct proto_info const *proto_info__ = proto_info_get_any(2, (struct proto const *[]){ proto_##proto1, proto_##proto2 }, last); \
        if (proto_info__) { \
            if (proto_info__->parser->proto == proto_##proto1) proto1 = DOWNCAST(proto_info__, info, proto1##_proto_info); \
            else proto2 = DOWNCAST(proto_info__, info, proto2##_proto_info); \
        } \
    }

#define ASSIGN_INFO_CHK(proto, last, err) \
    ASSIGN_INFO_OPT(proto, last); \
    if (! proto) { \
        SLOG(LOG_DEBUG, "Can't find proto " #proto); \
        return err; \
    }

#define ASSIGN_INFO_CHK2(proto, proto_alt, last, err) \
    ASSIGN_INFO_OPT2(proto, proto_alt, last); \
    if (! proto && ! proto_alt) { \
        SLOG(LOG_DEBUG, "Can't find neither " #proto " nor " #proto_alt); \
        return err; \
    }


/*
 * Parsers
 */

/// Base implementation of a parser.
/** You are supposed to inherit from this if you need a persistent state.
 *
 * A parser is used to store informations related to a given stream of data,
 * although the base implementation (struct parser) does not store anything of
 * value but merely provides the plumbing to do so. Thus whenever you need to
 * implement a parser with some state information that must be preserved from
 * one packet to the next you are supposed to inherit the plumbing from struct
 * parser and add your protocol related informations.
 *
 * If you do not need internal state then you'd rather use a
 * uniq_proto/uniq_parser instead.
 *
 * @see mux_parser and uniq_parser */
struct parser {
    struct ref ref;
    struct proto *proto;    ///< The proto owning this parser
    /// @note obviously, owner of the lock does not need a ref
};

/// Construct a new parser
int parser_ctor(
    struct parser *parser,  ///< The parser to initialize
    struct proto  *proto    ///< The proto implemented by this parser
);

/// Destruct a parser
void parser_dtor(
    struct parser *parser   ///< The parser to destruct
);

/// Return a name for this parser (suitable for debugging)
char const *parser_name(struct parser const *parser);

/// Declare a new ref on a parser.
/** @note Its ok to ref NULL.
 * @returns a new reference to a parser (actually, the same parser is returned with its ref_count incremented) */
struct parser *parser_ref(struct parser *parser);

/// Declare that a ref to a parser is no more used
/** @note It's OK to unref NULL. */
void parser_unref(struct parser **parser);

struct mux_parser;
struct mux_subparser;

/// If your proto parsers are multiplexer, inherit from mux_proto instead of a mere proto
/** Multiplexers are the most complicated parsers.
 *
 * A parser is called a \e multiplexer if it has several children of various
 * types (ie. of various struct proto) and pass some payload to them according
 * to a given key. For instance, IP is a multiplexer that use the ip addresses
 * and protocol field as a key to choose amongst its children which is
 * responsible for the payload. Similarly, TCP is a multiplexer using the
 * ports pair to choose amongst its children the one in charge for a payload.
 *
 * Multiplexers can not be stateless, since each instance of a multiplexer must
 * carry a list of its children; for performance reason actually not a list
 * but a hash. But many multiplexers share a common behavior : from the header
 * of their data, build a key that identifies a children, then lookup in the
 * children list (hash) the one in charge for this key, or create a new one if
 * none is found.
 *
 * struct mux_proto/mux_parser implement this common behavior, given a small
 * set of parameters :
 *
 * - the size of the key;
 *
 * - the max number of children allowed per multiplexer instance.
 *
 * The hash function being generic, only the key size matters and not the
 * actual structure of the key (as long as your key is packed_).
 *
 * But yet there is an important difficulty to grasp : some stateful parsers
 * deeper in the tree may need to handle traffic in both direction in order to
 * parse the payload (for instance, it need the query to parse the answer, or
 * just want to repeat the query in the proto_info of the answer for
 * simplicity). This mean, for instance, that the same TCP parser that handles
 * the TCP payload from ipA to ipB also handles the payload from ipB to ipA
 * (and so on). In this very example it implies that the IP parser must use the
 * same key for (TCP, ipA, ipB) than for (TCP, ipB, ipA). This is easily done
 * for instance if the IP key is build with sorted IP addresses, for instance
 * storing always smallest IP first (this is actually what's done).
 *
 * But this TCP parser itself must pass its payload from ipA:portA->ipB:portB
 * to the same child than the one receiving payload from ipB:portB->ipA:portA.
 * This is where things get more complicated, since TCP cannot merely sort
 * the ports when building its key. If we were doing this, the same child would
 * also receive traffic from ipA:portB->ipB:portA, which would be a bug.
 * In fact, to build its key the TCP parser must know how the IP key was build
 * and respect the same order. In other word, the rule is : once the top level
 * multiplexer (here, IP) have chosen a way to store its bidirectional key then
 * all multiplexers deepest in the tree must build their keys accordingly.
 *
 * That's the purpose of the "way" parameter of the parse() function : once set
 * by the toplevel multiplexer, other multiplexers must use it to build their key
 * (and pass it to their children).
 *
 * Although quite abstract for the average C coder, once understood these
 * helpers allows to add other multiplexers very quickly and provides as a free
 * bonus SNMP statistics for all multiplexers (such as average collision rate
 * in the hash) and guile extensions available for tuning any multiplexers.
 */
struct mux_proto {
    struct proto proto; ///< The mux_proto is a specialization of this proto
    /// If you do not overload mux_subparser just use &mux_proto_ops
    struct mux_proto_ops {
        struct mux_subparser *(*subparser_new)(struct mux_parser *mux_parser, struct parser *child, struct proto *requestor, void const *key, struct timeval const *now);
        void (*subparser_del)(struct mux_subparser *mux_subparser);
    } ops;
    size_t key_size;                ///< The size of the key used to multiplex
    /// Following 3 fields are protected by proto->lock
    LIST_ENTRY(mux_proto) entry;    ///< Entry in the list of mux protos
    unsigned hash_size;             ///< The required size for the hash used to store subparsers
    unsigned nb_max_children;       ///< The max number of subparsers (after which old ones are deleted)
    uint64_t nb_infanticide;        ///< Nb children that were deleted because of the previous limitation
    uint64_t nb_collisions;         ///< Nb collisions in the hashes since last change of hash size
    uint64_t nb_lookups;            ///< Nb lookups in the hashes since last change of hash size
    uint64_t nb_timeouts;           ///< Nb subparsers timeouted from the hashes (ie. not how many parsers of this proto were timeouted!)
    time_t last_used;               ///< last time we had traffic (used to give time to timeouter thread)
    /** A pool of mutexes so that we have enough for all the subparsers hash lines
     * but not one per hash line (would require too much memory). Also, we turn this
     * into profit by having only a few timeout queues that can be visited often in order
     * to timeout subparsers quickly. */
    struct per_mutex {
        struct mutex mutex;
        TAILQ_HEAD(timeout_queue, mux_subparser) timeout_queue;
    } mutexes[CPU_MAX];
};

/// Generic new/del functions for struct mux_subparser, suitable iff you do not overload mux_subparser
extern struct mux_proto_ops mux_proto_ops;

/// Construct a mux_proto
void mux_proto_ctor(
    struct mux_proto *mux_proto,    ///< The mux_proto to initialize
    struct proto_ops const *ops,    ///< The methods for this proto
    struct mux_proto_ops const *mux_ops,    ///< The methods specific to mux_proto
    char const *name,               ///< Protocol name
    enum proto_code code,           ///< Protocol Id
    size_t key_size,                ///< Size of the key used to identify subparsers
    unsigned hash_size              ///< Hash size for storing the subparsers
);

/// Destruct a mux_proto
void mux_proto_dtor(
    struct mux_proto *proto         ///< The mux_proto to destruct
);

/// Like proto_of_name() but from a SCM proto name
/// @return the proto
struct proto *proto_of_scm_name(SCM name);

/// A mux_parser comes with a hash of mux_supbarsers.
/** So it was already said that a mux_parser have a state composed of a hash of
 * its children.  This is actually a little bit more complex, since there is no
 * LIST_ENTRY in struct parser usable for this hash (especially since stateless
 * parsers are actually instantiated only once).
 *
 * So the hash of children is actually a hash of mux_subparser, which is a
 * small structure that "boxes" the parser. In addition to the pointer to the
 * subparser we also store there the LIST_ENTRY for the hash, the key
 * identifying this child (so that mux_subparser_lookup() can be generic) and
 * an optional pointer called "requestor", linking to the proto of the parser
 * that created this parser (useful to associate a traffic from one location
 * to the parser's tree to another, in case of connection tracking).
 *
 * @note Remember to add the packed_ attribute to your keys ! */
struct mux_subparser {
    struct ref ref;                         ///< Note that being stored in parent's hash does count as a reference
    TAILQ_ENTRY(mux_subparser) to_entry;    ///< Its entry in its timeout queue (sorted in least recently used first)
    STAILQ_ENTRY(mux_subparser) h_entry;    ///< Its entry in the hash (sorted in more recently used first - so that lookups are faster)
    struct parser *parser;                  ///< The actual parser
    struct timeval last_used;               ///< Last time we called its parse method
    struct proto *requestor;                ///< The proto that requested its creation
    struct mux_parser *mux_parser;          ///< Backlink to our mux_parser
    struct mux_proto *mux_proto;            ///< Backlink to our mux_proto, for when mux_parser cannot be used (see mux_subparser_del_as_ref())
#   define NOT_HASHED UNSET
    unsigned h_idx;                         ///< Our hash index into mux_parser->subparsers (NO_HASHED if not queued in any list)
    char key[];                             ///< The key used to identify it (beware of the variable size)
};

/// A parser implementing a mux_proto is a mux_parser.
/** Inherit this and add your context information (if any).
 * Beware that since struct mux_parser has variable size, you must inherit it
 * "from the top" instead of "from the bottom". For instance, if you want to
 * implement a parser for protocol XYZ which is a multiplexer, do \e not do this :
 *
 * @verbatim
 * struct XYZ_parser {
 *    struct mux_parser mux_parser;
 *    my_other_datas...;
 * };
 * @endverbatim
 *
 * but do this instead :
 *
 * @verbatim
 * struct XYZ_parser {  // Beware that I'm of variable size as well !
 *     my_other_datas...;   // hello, I'm a comment in a code in a comment :)
 *     struct mux_parser mux_parser;
 * };
 * @endverbatim
 */
struct mux_parser {
    struct parser parser;                                   ///< A mux_parser is a specialization of this parser
    unsigned hash_size;                                     ///< The hash size for this particular mux_parser (taken from mux_proto at creation time, constant)
    unsigned nb_max_children;                               ///< The max number of children allowed (0 if not limited)
    unsigned nb_children;                                   ///< Current number of children
    /// The hash of subparsers (Beware of the variable size)
    struct subparsers {
        /// These two fields are protected by one of the mux_proto->mutexes
        STAILQ_HEAD(mux_subparsers, mux_subparser) list;    ///< The list of all subparsers with same hash value (least recently used last)
    } subparsers[];
};

/// @returns the size to be allocated before creating the mux_parser
size_t mux_parser_size(unsigned hash_size);

/** If you overload struct mux_subparser, you might want to use this to allocate your
 * custom mux_subparser since its length depends on the key size. */
void *mux_subparser_alloc(struct mux_parser *mux_parser, size_t size_without_key);

/// Create a mux_subparser for a given parser
struct mux_subparser *mux_subparser_new(
    struct mux_parser *mux_parser,  ///< The parent of the requested subparser
    struct parser *parser,          ///< The subparser itself
    struct proto *requestor,        ///< Who required its creation
    void const *key,                ///< The key used to identify it
    struct timeval const *now       ///< So that we don't timeout it at once
);

/// or if you'd rather overload it
int mux_subparser_ctor(
    struct mux_subparser *mux_subparser,    ///< The mux_subparser to construct
    struct mux_parser *mux_parser,          ///< The parent of the requested subparser
    struct parser *parser,                  ///< The parser we want to be our child
    struct proto *requestor,                ///< Who required its creation
    void const *key,                        ///< The key used to identify it
    struct timeval const *now               ///< So that we don't timeout it at once
);

/// Many time you want to create the child and the subparser in a single move :
struct mux_subparser *mux_subparser_and_parser_new(
    struct mux_parser *mux_parser,  ///< The parent of the requested subparser
    struct proto *proto,            ///< The proto we want our subparser to implement
    struct proto *requestor,        ///< The parser that required the creation of this subparser
    void const *key,                ///< The key used to identify it
    struct timeval const *now       ///< The current time
);

/// Delete a mux_subparser
void mux_subparser_del(
    struct mux_subparser *subparser ///< The subparser to delete
);

/// or if you'd rather overload it
void mux_subparser_dtor(
    struct mux_subparser *mux_subparser ///< The mux_subparser to destruct
);

/// Search (and optionally create) a subparser
/* Note: in both cases a new ref is returned. */
struct mux_subparser *mux_subparser_lookup(
    struct mux_parser *parser,  ///< Look for a subparser of this mux_parser
    struct proto *create_proto, ///< If not found, create a new one that implements this proto
    struct proto *requestor,    ///< If creating, the proto that required its creation
    void const *key,            ///< The key to look for
    struct timeval const *now   ///< The current time
);

/// Update the key of a subparser
void mux_subparser_change_key(
    struct mux_subparser *subparser,    ///< The subparser to update
    struct mux_parser *mux_parser,      ///< Which is a subparser of this parser
    void const *key                     ///< The new key
);

/// Declare a new ref on a mux_subparser.
struct mux_subparser *mux_subparser_ref(struct mux_subparser *);

/// Declare that a ref to a mux_subparser is no more used
void mux_subparser_unref(struct mux_subparser **);

/// Remove a mux_subparser from its mux_proto hash, thus probably killing the only left ref apart yours.
void mux_subparser_deindex(struct mux_subparser *);

/// Construct a mux_parser
int mux_parser_ctor(struct mux_parser *mux_parser, struct mux_proto *mux_proto, unsigned hash_size, unsigned nb_max_children);

/// Destruct a mux_parser
void mux_parser_dtor(struct mux_parser *parser);

/// In case you have no context, use these in your mux_proto ops :
struct parser *mux_parser_new(struct proto *proto);
void mux_parser_del(struct parser *parser);

/// If you need only one instance of a parser, implement a uniq_proto :
/** Most parsers are easier than multiplexers since most parsers are stateless
 * (ie. no internal state nor long lived child).
 * For these a single instance of parser is enough. */
struct uniq_proto {
    struct proto proto;
    // FIXME: Although unique, parser may want to have private fields (and thus inherit from struct parser)
    struct parser *parser;
};

/// Construct a uniq_proto
void uniq_proto_ctor(
    struct uniq_proto *uniq_proto,  ///< Uniq proto that's being constructed
    struct proto_ops const *ops,    ///< Its operations
    char const *name,               ///< Its name
    enum proto_code code            ///< Its Id
);

/// Destruct a uniq_proto
void uniq_proto_dtor(struct uniq_proto *uniq_proto);

/// Create a new parser from a uniq_proto
struct parser *uniq_parser_new(struct proto *);

/// Delete a parser of a uniq_proto
void uniq_parser_del(struct parser *);

/// The log category used for all log messages related to packet inspection
extern LOG_CATEGORY_DEC(proto);

void proto_init(void);
void proto_fini(void);

#endif
