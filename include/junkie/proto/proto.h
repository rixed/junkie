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

/** @file
 * @brief Packet inspection
 *
 * Each packet received from libpcap is passed to a toplevel "capture" parser,
 * which then builds a small struct proto_info describing the packet and handling
 * the payload to a child parser. This child parser performs in a similar fashion,
 * extracting from the received data the interesting bits, building another
 * struct proto_info describing this parser and handling the payload to yet another
 * parser, etc... At the end, once a leaf of the protocol tree is reached, the
 * user callback is called with the list of all these proto_infos.
 *
 * Parsers are designed in order to be (as most as possible) independent on
 * each others. Their aim is to extract from the packet only the informations
 * regarding the protocol they implement (ie. the information that are easy to
 * extract in realtime but presumed meaningful for a large set of callbacks).
 *
 * Having independent parsers implies that every parser is committed to a given
 * behavior. For instance, every protocol parser must have a single parse
 * function receiving the relevant data from it's parent and its parent's
 * proto_info (which can be used to inspect upper layers). This common
 * behavior is inherited from the struct proto that defines the behavior of
 * all parsers of this proto.
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
 * Storing every information related to a frame on the stack leads to simpler
 * code (especially if a parser can call several sub-parser on the same data
 * and/or when multiple threads are performing frame parsing) but implies that
 * the final callback that should be called once the frame is fully broken to
 * pieces must be called at the deepest point of the parsing call graph. In
 * other words, the callback function must be called by a parser when it has no
 * sub-parser (notice that this function may then be called several times if a
 * parser try different sub-parsers).
 *
 * For generality we choose here to pass an additional parameter to the parse
 * method which is a kind of "continuation" to call when no more parsing is
 * required.  This allows a parser to replace this function by another one that
 * will perform any final action before calling the received continuation, and
 * is similar to netfilter hooks implementation (just to say it's not _that_
 * alien).
 *
 * How can a parser call a sub-parser if they do not know each other ? Well,
 * obviously a parser must have some kind of knowledge of what other parsers
 * are available.  That's why the struct proto describing a parser is public,
 * so that a parser can spawn a new parser for this protocol. But that's the
 * only link that exists between two parsers, and apart from the case where a
 * parser look something into one of its parent's proto_info then one can
 * safely modify a parser implementation without interfering with any other
 * parsers.
 *
 * Anyway, a dummy parser is created whenever a proto in not implemented or no
 * more accessible.
 *
 * FIXME: if a parser call several sub-parsers in parallel the continuation
 * will be called several times.
 */

struct parser;
struct proto_info;
/// The type for the continuation function
/** This continuation function will actually call the parse_callback()
 * function of every loaded plugin. */
typedef int proto_okfn_t(struct proto_info const *, size_t tot_cap_len, uint8_t const *tot_packet);

/// The various possible exit codes of the parse functions
enum proto_parse_status {
    /// When a parser (not necessarily its children) recognize its protocol (okfn was called, then)
    PROTO_OK,
    /// When a parser does not recognize its protocol (okfn was not already called then)
    PROTO_PARSE_ERR,
    /** When a parser can't tell if the payload belongs to him because the capture length is not enough
     *  (proto_parse will call okfn and return PROTO_OK to the parent) */
    PROTO_TOO_SHORT,
};

typedef enum proto_parse_status parse_fun(
    struct parser *parser,      ///< The parser to hand over the payload to. If NULL okfn is called instead
    struct proto_info *parent,  ///< It's parent proto_info
    unsigned way,               ///< Direction identifier (@see struct mux_proto)
    uint8_t const *packet,      ///< Raw data to parse
    size_t cap_len,             ///< How many bytes are present in packet
    size_t wire_len,            ///< How many bytes were present on the wire
    struct timeval const *now,  ///< The current time
    proto_okfn_t *okfn,         ///< The "continuation"
    size_t tot_cap_len,         ///< The capture length of the total packet (to be passed to okfn)
    uint8_t const *tot_packet   ///< The total packet (to be passed to okfn)
);

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
    uint64_t nb_frames;     ///< How many times we called this parse (count frames only if this parser is never called more than once on a frame)
    uint64_t nb_bytes;      ///< How many bytes this proto had on wire
    /// How many parsers of this proto exists
    unsigned nb_parsers;
    /// Timeout for parsers of this proto (0 to disable timeouting)
    unsigned timeout;
    /// Entry in the list of all registered protos
    LIST_ENTRY(proto) entry;
    /// Fuzzing statistics: number of time this proto has been fuzzed.
    unsigned fuzzed_times;
    /// Mutex to protect the mutable values of this proto (entry, parsers, nb_parsers, nb_frames)
    struct mutex lock;
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
    unsigned timeout                ///< Any parser unused after that many seconds may be killed (0 for no timeout)
);

/// Destruct a proto (some parsers may still be present after this if referenced by other parsers)
void proto_dtor(struct proto *proto);

/// Call this instead of accessing proto->ops->parse, so that counters are updated properly.
parse_fun proto_parse;

/// Lookup by name in the list of registered protos
/** @returns NULL if not found. */
struct proto *proto_of_name(char const *);

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
/** @returns the last proto_info owned by the given proto.
 */
struct proto_info const *proto_info_get(
    struct proto const *proto,      ///< The proto to look for
    struct proto_info const *last   ///< Where to start looking for
);

#define ASSIGN_INFO_OPT(proto, last) \
    struct proto_info const *proto##_proto__ = proto_info_get(proto_##proto, last); \
    struct proto##_proto_info const *proto = proto##_proto__ ? DOWNCAST(proto##_proto__, info, proto##_proto_info) : NULL;

/// Used if both TCP and UDP can handle a upper protocol (say... DNS or SIP)
#define ASSIGN_INFO_OPT2(proto, proto_alt, last) \
    ASSIGN_INFO_OPT(proto, last); \
    struct proto_info const *proto_alt##_proto__ = NULL; \
    struct proto_alt##_proto_info const *proto_alt = NULL; \
    if (! proto) { \
        proto_alt##_proto__ = proto_info_get(proto_##proto_alt, last); \
        proto_alt = proto_alt##_proto__ ? DOWNCAST(proto_alt##_proto__, info, proto_alt##_proto_info) : NULL; \
    }

#define ASSIGN_INFO_CHK(proto, last, err) \
    ASSIGN_INFO_OPT(proto, last); \
    if (! proto) return err;

#define ASSIGN_INFO_CHK2(proto, proto_alt, last, err) \
    ASSIGN_INFO_OPT2(proto, proto_alt, last); \
    if (! proto && ! proto_alt) return err;

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
    /// @note obvisouly, owner of the lock does not need a ref
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
/** @note It's OK to unref NULL.
 * @returns NULL to remember you of actually NULLing your ref */
struct parser *parser_unref(struct parser *parser);

struct mux_parser;
struct mux_subparser;

/// If your proto parsers are multiplexer, inherit from mux_proto instead of a mere proto
/** Multiplexers are the most complicated parsers.
 *
 * A parser is called a \e multiplexer if it have several children of various
 * types (ie. of various struct proto) and pass some payload to them according
 * to a given key. For instance, IP is a multiplexer that use the ip addresses
 * and protocol field as a key to choose amongst its children which is
 * responsible for the payload. Similarly, TCP is a multiplexer using the
 * ports pair to choose amongst its children the one in charge for a payload.
 *
 * Multiplexers can not be stateless, since each instance of a multiplexer must
 * carry a list of it's children; for performance reason actually not a list
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
 * actual structure of the key (as long as your key is packed_ (see jhash.h
 * and cpp.h).
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
    /** A pool of mutexes so that we have enough for all the subparsers hash lines
     * but not one per hash line (would be too much) */
    struct mutex mutexes[CPU_MAX];
};

/// Generic new/del functions for struct mux_subparser, suitable iff you do not overload mux_subparser
extern struct mux_proto_ops mux_proto_ops;

/// Construct a mux_proto
void mux_proto_ctor(
    struct mux_proto *mux_proto,    ///< The mux_proto to initialize
    struct proto_ops const *ops,    ///< The methods for this proto
    struct mux_proto_ops const *mux_ops,    ///< The methods specific to mux_proto
    char const *name,               ///< Protocol name
    unsigned timeout,               ///< Timeout unused parsers after that many seconds
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
    struct ref ref;
    struct parser *parser;                  ///< The actual parser
    struct timeval last_used;               ///< Last time we call it's parse method
    struct proto *requestor;                ///< The proto that requested its creation
    TAILQ_ENTRY(mux_subparser) entry;       ///< Its entry in the hash (sorted in least recently used first)
    struct mux_parser *mux_parser;          ///< Backlink to our mux_parser
    struct mux_proto *mux_proto;            ///< Backlink to our mux_proto, for when mux_parser cannot be used (see mux_subparser_del_as_ref())
#   define NOT_HASHED (~0U)
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
 *
 * See for instance the SIP parser for an actual example. */
struct mux_parser {
    struct parser parser;                                   ///< A mux_parser is a specialization of this parser
    unsigned hash_size;                                     ///< The hash size for this particular mux_parser (taken from mux_proto at creation time)
    unsigned nb_max_children;                               ///< The max number of children allowed (0 if not limited)
    unsigned max_timeout;                                   ///< The longest timeout we have for our subparsers
    unsigned nb_children;                                   ///< Current number of children
    /// The hash of subparsers (Beware of the variable size)
    struct subparsers {
        /// These two fields are protected by one of the mux_proto->mutexes
        TAILQ_HEAD(mux_subparsers, mux_subparser) list;     ///< The list of all subparsers with same hash value
    } subparsers[];
};

/// @returns the size to be allocated before creating the mux_parser
size_t mux_parser_size(struct mux_proto *mux_proto);

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
    struct timeval const *now   ///< The current time (required if create_proto is set)
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
struct mux_subparser *mux_subparser_unref(struct mux_subparser *);

/// Remove a mux_subparser from it's mux_proto hash, thus probably killing the only left ref apart yours.
void mux_subparser_deindex(struct mux_subparser *);

/// Construct a mux_parser
int mux_parser_ctor(struct mux_parser *mux_parser, struct mux_proto *mux_proto);

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
void uniq_proto_ctor(struct uniq_proto *uniq_proto, struct proto_ops const *ops, char const *name);

/// Destruct a uniq_proto
void uniq_proto_dtor(struct uniq_proto *uniq_proto);

/// Create a new parser from a uniq_proto
struct parser *uniq_parser_new(struct proto *);

/// Delete a parser of a uniq_proto
void uniq_parser_del(struct parser *);

/// The log category used for all log messages related to packet inspection
LOG_CATEGORY_DEC(proto)

void proto_init(void);
void proto_fini(void);

#endif
