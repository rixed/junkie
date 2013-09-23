// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#ifndef FCOE_H_130919
#define FCOE_H_130919

struct fcoe_proto_info {
    struct proto_info info;
    uint8_t version;
    uint8_t sof, eof; // start-of-frame & end-of-frame markers
};

void fcoe_init(void);
void fcoe_fini(void);

#endif
