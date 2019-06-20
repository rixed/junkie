#!/usr/bin/env python
# vim:sw=4 ts=4 sts=4 expandtab
import sys
import string

def parse_p0f():
    """
    Parse the p0f.fp file (stdin).
    We are only interested in the [tcp:request] and [tcp:response] sections (ie.
    signatures based on TCP syns).
    We return a list of (tests, label), where tests is a list of tests which first
    element is the direction of the packet (0 for the [tcp:request] section and
    1 for the [tcp:response] section), and other tests are merely constituents of
    the signature.
    label is the numerical value of the identified OS (0 meaning unknown).
    Beware that many different tests yield the same label, and that a label typically
    appear twice in p0f.fp (once per direction).
    Also, we do not build a dico with label as key since what we want ultimately is
    an ordered list of tests to execute in order.
    """
    sigs = []
    labels = ["unknown"]

    direction = None  ## 0 if in tcp client->server section, 1 if in tcp server->client section
    for line in sys.stdin.readlines():
        line = line.rstrip()
        if not line:
            continue

        if line == "[tcp:request]":
            direction = 0
        elif line == "[tcp:response]":
            direction = 1
        elif line[0] == '[':
            direction = None

        if '=' in line and direction is not None:
            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip()
            if key == "label":
                current_label = value
                labels.append(value)
            elif key == "sig":
                sigs.append(([direction] + value.split(":"), labels.index(current_label)))

    return [sigs, labels]

def split_sigs(sigs):
    """
    Split a list of pairs of vectors according to the first coordinate of the first vector.
    For instance, if we split [ ([a,b,c], x), ([b,z,f,y,e], y), ([a,g,y,e], z) ] then we
    will obtain: [ a: [ ([b,c], x), ([g,y,e], z) ], b: [ ([z,f,y,e], y) ] ]
    ie. we factorize out the first test, effecitvely transforming:
      if (a && b && c) { return x; }
      else if (b && z && f && y && e) { return y; }
      else if (a && g && y && e) { return z; }
    into:
      if (a) {
        if (b && c) { return x; }
        if (g && y && e) { return z; }
      } else if (b) {
        if (z && f && y && e) { return y; }
      }
    this process will of course be applied recursively.
    """
    res = {}
    for sig, label_idx in sigs:
        if len(sig) > 0:
            res.setdefault(sig[0], []).append((sig[1:], label_idx))
        else:
            res[''] = label_idx
    return res

def reindent(tab, txt):
    i = ' '*tab
    return i + string.replace(txt, "\n", "\n%s" % i)

def tests_for(indent, num, sigs):
    """
    So here we build the C code for testing all the signatures in sigs.
    num is an integer that tells us what's the first test of the signatures (the first one
    is the test for direction, the second for IP version, and so on, see the README of
    p0f for more details (or the following comments).
    Of course, performing all these tests is done recursively, with num going deeper until
    nothing's left in sigs.
    code is returned as a list of strings so that's easy to indent.
    Note: the indent param is not the indentation level but a boolean.
    """
    values = split_sigs(sigs)
    code = []

    def dispatch_on_value(values, condfunc):
        "Many tests consist of a mere enumeration of separate cases."
        code = []
        if not values:
            return code
        for i, x in enumerate(sorted(values)):
            prefix = "} else " if i > 0 else ""
            code.append(prefix + "if (%s) {" % condfunc(x))
            code.append(tests_for(True, num+1, values[x]))
        code.append("}")
        return code

    if num == 0: ## direction (0 = C->S, 1 = S->C)
        code.append("if (! tcp->ack) { /* client to server */")
        if 0 in values: code.append(tests_for(True, num+1, values[0]))
        code.append("} else { /* server to client */")
        if 1 in values: code.append(tests_for(True, num+1, values[1]))
        code.append("}")

    elif num == 1: ## ip version
        code.append("if (ip->version == 4) {")
        if values.has_key("4"): code.append(tests_for(True, num+1, values["4"]))
        code.append("} else if (ip->version == 6) {")
        if values.has_key("6"): code.append(tests_for(True, num+1, values["6"]))
        code.append("}")
        if values.has_key("*"):
            code.append("/* independant of IP version */")
            code.append(tests_for(False, num+1, values["*"]))

    elif num == 2: ## initial TTL
        for x in sorted(values.keys()):
            if x.endswith("-"):
                code.append("if (ip->ttl <= %s) {" % x[:-1])
            else:
                code.append("if (ip->ttl <= %s && %s <= ip->ttl + 20 /* MAX_DIST */) {" % (x, x))
            code.append(tests_for(True, num+1, values[x]))
            code.append("}")

    elif num == 3: ## IP Option length, always look for 0
        code += dispatch_on_value(values, lambda x: "ip->info.head_len - 20 == %s" % x)

    elif num == 4: ## MSS ('*' always pass)
        match_all = values.pop("*", None)
        code += dispatch_on_value(values, lambda x: "(tcp->set_values & TCP_MSS_SET) && tcp->mss == %s" % x)
        if match_all is not None:
            code += [ tests_for(False, num+1, match_all) ]

    elif num == 5: ## WinSize, WinScaleFactor
        def cond_of_wsz_wsf(x):
            x_ = x.split(',')
            wsz = x_[0]
            wsf = x_[1]
            if wsz == "*":
                wsz = "true"
            elif wsz[0] == "%":
                wsz = "tcp->window %% %d == 0" % int(wsz[1:])
            elif wsz.startswith("mss*"):
                wsz = "(tcp->set_values & TCP_MSS_SET) && (tcp->window == tcp->mss * %d)" % int(wsz[4:])
            elif wsz.startswith("mtu*"):
                wsz = "true /* multiple of MTU not implemented */"
            else:
                wsz = "tcp->window == %d" % int(wsz)
            if wsf == '*':
                wsf = "true"
            else:
                wsf = "(!(tcp->set_values & TCP_WSF_SET)) || (tcp->wsf == %d)" % int(wsf)
            return "(%s) && (%s)" % (wsz, wsf)
        code += dispatch_on_value(values, cond_of_wsz_wsf)

    elif num == 6: ## option layout
        def option_kind_of(opt):
            if opt.startswith("?"):
                return opt[1:]
            options = {
                "nop": "1", "mss": "2", "ws": "3", "sok": "4", "sack": "5", "ts": "8"
            }
            return options[opt]

        for i, x in enumerate(sorted(values)):
            prefix = "} else " if i > 0 else ""
            opts = x.split(',')
            code.append(prefix + "if (")
            for idx, opt in enumerate(opts):
                if not opt.startswith("eol+"): ## no support for this since we lack the information
                    code.append("  (%s < tcp->nb_options && tcp->options[%s] == %s) &&" % (idx, idx, option_kind_of(opt)))
            code.append("  true) {")
            code.append(tests_for(True, num+1, values[x]))
        code.append("}")

    elif num == 7:  ## quirks
        quirk_tests = {
            "df":     "ip->version == 6 || ip->fragmentation == IP_DONTFRAG",
            "id+":    "ip->version == 6 || (ip->fragmentation == IP_DONTFRAG && ip->id != 0)",
            "id-":    "ip->version == 6 || (ip->fragmentation == IP_NOFRAG && ip->id == 0)",
            "ecn":    "0 != (ip->traffic_class & IP_TOS_ECN_MASK)",
            "0+":     "true", ## not supported
            "flow":   "ip->version == 4 || ip->id != 0",
            "seq-":   "tcp->seq_num == 0",
            "ack+":   "tcp->ack_num != 0 && !tcp->ack",
            "ack-":   "tcp->ack_num == 0 && tcp->ack",
            "uptr+":  "tcp->urg_ptr != 0 && !tcp->urg",
            "urgf+":  "tcp->urg",
            "pushf+": "tcp->psh",
            "ts1-":   "true", ## not implemented
            "ts2+":   "true", ## not implemented
            "opt+":   "true", ## not implemented
            "exws":   "(tcp->set_values & TCP_WSF_SET) && tcp->wsf > 14",
            "bad":    "true", ## not implemented
            "":       "true"
        }

        for i, x in enumerate(sorted(values)):
            prefix = "} else " if i > 0 else ""
            quirks = x.split(',')
            code.append(prefix + "if (")
            for quirk in quirks:
                code.append("  (%s) &&" % quirk_tests.get(quirk, "true"))
            code.append("  true) {")
            code.append(tests_for(True, num+1, values[x]))
        code.append("}")

    elif num == 8:  ## pclass
        code.append("if (tcp->info.payload > 0) {")
        if values.has_key("+"): code.append(tests_for(True, num+1, values["+"]))
        code.append("} else if (tcp->info.payload == 0) {")
        if values.has_key("0"): code.append(tests_for(True, num+1, values["0"]))
        code.append("}")
        if values.has_key("*"):
            code.append("/* independant of payload class */")
            code.append(tests_for(False, num+1, values["*"]))
 
    elif num == 9:  ## no more tests, return the result
        code.append("return %s;" % values[''])

    code = "\n".join(code)
    if indent:
        code = reindent(2, code)
    return code

if __name__ == "__main__":
    sigs, labels = parse_p0f()
    code = tests_for(True, 0, sigs)

    print '// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-'
    print '// vim:sw=4 ts=4 sts=4 expandtab'
    print '// THIS CODE WAS GENERATED BY fp_2_c.py < p0f.fp'
    print '#include <stdlib.h>'
    print '#include "junkie/cpp.h"'
    print '#include "junkie/proto/ip.h"'
    print '#include "junkie/proto/tcp.h"'
    print '#include "proto/ip_hdr.h"'
    print '#include "junkie/proto/os-detect.h"'
    print
    print 'char const *os_name(unsigned id)'
    print '{'
    print '  switch (id) {'
    for i, label in enumerate(labels):
        print '    case %d: return "%s";' % (i, label)
    print '  }'
    print '  return "INVALID";'
    print '}'
    print
    print 'unsigned os_detect(struct ip_proto_info const *ip, struct tcp_proto_info const *tcp)'
    print '{'
    print '  if (! tcp->syn) return 0; // we are only interested in SYNs/SYNACKS'
    print
    print code
    print
    print '  return 0;'
    print '}'
    print
    print 'void os_detect_init(void) {}'

