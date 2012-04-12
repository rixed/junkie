#!/usr/bin/env python
# vim:sw=2 ts=2 sts=2 expandtab
import sys
import string

sigs = []
labels = ["unknown"]

def parse_p0f():
  direction = -1  # 0 if in tcp client->server section, 1 if in tcp server->client section
  for line in sys.stdin.readlines():
    line = line.rstrip()
    if len(line) > 0:
      if line == "[tcp:request]":
        direction = 0
      elif line == "[tcp:response]":
        direction = 1
      elif line[0] == '[':
        direction = -1

      if line[0:8] == "label = " and direction <> -1:
        label = line[8:]
        labels.append(label)
      elif line[0:8] == "sig   = " and direction <> -1:
        assert(label is not None)
        sigs.append(([direction] + line[8:].split(':'), labels.index(label)))

def split_sigs(sigs):
  "Split a list of pairs of vectors according to the first coordinate of the first vector."
  res = {}
  for sig, label in sigs:
    if len(sig) > 0:
      if res.has_key(sig[0]):
        res[sig[0]] += [(sig[1:], label)]
      else:
        res[sig[0]] = [(sig[1:], label)]
    else:
      res[''] = label
  return res

def reindent(tab, txt):
  i = ' '*tab
  return i + string.replace(txt, "\n", "\n%s" % i)

def tests_for(indent, num, sigs):
  values = split_sigs(sigs)
  code = []

  def dispatch_on_value(values, condfunc):
    delim = ""
    code = []
    for x in sorted(values.keys()):
      code += [
        ("%sif (%s) {" % (delim, condfunc(x))),
          tests_for(True, num+1, values[x])
      ]
      delim = "} else "
    if delim == "":
      return code
    else:
      return code + ["}"]

  if num == 0: # direction (0 = C->S, 1 = S->C)
    code.append("if (! tcp->ack) { /* client to server */")
    if values.has_key(0): code.append(tests_for(True, num+1, values[0]))
    code.append("} else { /* server to client */")
    if values.has_key(1): code.append(tests_for(True, num+1, values[1]))
    code.append("}")

  elif num == 1: # ip version
    code.append("if (ip->version == 4) {")
    if values.has_key("4"): code.append(tests_for(True, num+1, values["4"]))
    code.append("} else if (ip->version == 6) {")
    if values.has_key("6"): code.append(tests_for(True, num+1, values["6"]))
    code.append("}")
    if values.has_key("*"):
      code.append("/* independant of IP version */")
      code.append(tests_for(False, num+1, values["*"]))

  elif num == 2: # initial TTL
    for x in sorted(values.keys()):
      if x[-1] == "-":
        code.append("if (ip->ttl <= %s) {" % x[:-1])
      else:
        code.append("if (ip->ttl <= %s && %s <= ip->ttl + 20 /* MAX_DIST */) {" % (x, x))
      code.append(tests_for(True, num+1, values[x]))
      code.append("}")

  elif num == 3: # IP Option length, always look for 0
    code += dispatch_on_value(values, lambda x: "ip->info.head_len - 20 == %s" % x)

  elif num == 4: # MSS ('*' always pass)
    match_all = values.pop("*", None)
    code += dispatch_on_value(values, lambda x: "(tcp->set_values & TCP_MSS_SET) && tcp->mss == %s" % x)
    if match_all is not None:
      code += [ tests_for(False, num+1, match_all) ]

  elif num == 5: # WinSize, WinScaleFactor
    def cond_of_wsz_wsf(x):
      x_ = x.split(',')
      wsz = x_[0]
      wsf = x_[1]
      if wsz == "*":
        wsz = "true"
      elif wsz[0] == "%":
        wsz = "tcp->window % %s == 0" % int(wsz[1:])
      elif wsz[0:4] == "mss*":
        wsz = "(tcp->set_values & TCP_MSS_SET) && (tcp->window == tcp->mss * %s)" % int(wsz[4:])
      elif wsz[0:4] == "mtu*":
        wsz = "true /* multiple of MTU not implemented */"
      else:
        wsz = "tcp->window == %s" % int(wsz)
      if wsf == '*':
        wsf = "true"
      else:
        wsf = "(!(tcp->set_values & TCP_WSF_SET)) || (tcp->wsf == %s)" % int(wsf)
      return "(%s) && (%s)" % (wsz, wsf)
    code += dispatch_on_value(values, cond_of_wsz_wsf)

  elif num == 6: # option layout
    def option_kind_of(opt):
      if opt == "nop":    return "1"
      elif opt == "mss":  return "2"
      elif opt == "ws":   return "3"
      elif opt == "sok":  return "4"
      elif opt == "sack": return "5"
      elif opt == "ts":   return "8"
      elif opt[0] == "?": return opt[1:]
      raise NameError(opt)
    delim = ""
    for x in sorted(values.keys()):
      opts = x.split(',')
      idx = 0
      code.append("%sif (" % delim)
      delim = "} else "
      for opt in opts:
        if opt[0:4] <> "eol+": # no support for this since we lack the information
          code.append("  (%s < tcp->nb_options && tcp->options[%s] == %s) &&" % (idx, idx, option_kind_of(opt)))
          idx += 1
      code.append("  true) {")
      code.append(tests_for(True, num+1, values[x]))
    code.append("}")

  elif num == 7:  # quirks
    def quirk_of(q):
      if q == "df":       return "ip->version == 6 || ip->fragmentation == IP_DONTFRAG"
      elif q == "id+":    return "ip->version == 6 || (ip->fragmentation == IP_DONTFRAG && ip->id != 0)"
      elif q == "id-":    return "ip->version == 6 || (ip->fragmentation == IP_NOFRAG && ip->id == 0)"
      elif q == "ecn":    return "0 != (ip->traffic_class & IP_TOS_ECN_MASK)"
      elif q == "0+":     return "true" # not supported
      elif q == "flow":   return "ip->version == 4 || ip->id != 0"
      elif q == "seq-":   return "tcp->seq_num == 0"
      elif q == "ack+":   return "tcp->ack_num != 0 && !tcp->ack"
      elif q == "ack-":   return "tcp->ack_num == 0 && tcp->ack"
      elif q == "uptr+":  return "tcp->urg_ptr != 0 && !tcp->urg"
      elif q == "urgf+":  return "tcp->urg"
      elif q == "pushf+": return "tcp->psh"
      elif q == "ts1-":   return "true" # not implemented
      elif q == "ts2+":   return "true" # not implemented
      elif q == "opt+":   return "true" # not implemented
      elif q == "exws":   return "(tcp->set_values & TCP_WSF_SET) && tcp->wsf > 14"
      elif q == "bad":    return "true" # not implemented
      elif q == '':       return "true"
      raise NameError(q)
    delim = ""
    for x in sorted(values.keys()):
      quirks = x.split(',')
      code.append("%sif (" % delim)
      delim = "} else "
      for quirk in quirks:
        code.append("  (%s) &&" % quirk_of(quirk))
      code.append("  true) {")
      code.append(tests_for(True, num+1, values[x]))
    code.append("}")

  elif num == 8:  # pclass
    code.append("if (tcp->info.payload > 0) {")
    if values.has_key("+"): code.append(tests_for(True, num+1, values["+"]))
    code.append("} else if (tcp->info.payload == 0) {")
    if values.has_key("0"): code.append(tests_for(True, num+1, values["0"]))
    code.append("}")
    if values.has_key("*"):
      code.append("/* independant of payload class */")
      code.append(tests_for(False, num+1, values["*"]))
 
  elif num == 9:  # no more tests, return the result
    code.append("return %s;" % values[''])

  code = "\n".join(code)
  if indent:
    code = reindent(2, code)
  return code

parse_p0f()
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
print ''
print 'char const *os_name(unsigned id)'
print '{'
print '  switch (id) {'
for x in range(0, len(labels)-1):
  print '    case %d: return "%s";' % (x, labels[x])
print '  }'
print '  return "INVALID";'
print '}'
print ''
print 'unsigned os_detect(struct ip_proto_info const *ip, struct tcp_proto_info const *tcp)'
print '{'
print '  if (! tcp->syn) return 0; // we are only interrested in SYNs/SYNACKS'
print ''
print code
print ''
print '  return 0;'
print '}'
print ''
print 'void os_detect_init(void) {}'


