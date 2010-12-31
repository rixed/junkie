#include <stdlib.h>
#include <stdio.h>
#include <junkie/proto/proto.h>
#include <junkie/cpp.h>

// Default parse continuation :
static void dump_frame_rec(struct proto_info const *info)
{
    if (info->parent) dump_frame_rec(info->parent);
    printf("%s@%p: %s\n", info->parser->proto->name, info->parser, info->parser->proto->ops->info_2_str(info));
}

int parse_callback(struct proto_info const *last)
{
    dump_frame_rec(last);
    printf("\n");
    return 0;
}

void on_load(void)
{
	SLOG(LOG_INFO, "Dumper loaded\n");
}

void on_unload(void)
{
	SLOG(LOG_INFO, "Dumper unloading\n");
}
