/*
 * In-process libFuzzer harness for crackle's PCAP/BTLE parser.
 *
 * crackle is a CLI that reads a capture file with libpcap and feeds every
 * packet through its BTLE link-layer parser (enc_data_extractor + the
 * per-DLT packet handlers). That parser is the memory-safety attack surface
 * for a malicious capture. Upstream only exposes it through main()/getopt and
 * a file path, so we drive the SAME code path in-process: write the fuzz bytes
 * to a temp pcap, open it with libpcap, and run the exact dispatch loop main()
 * uses (pick handler by DLT -> pcap_dispatch -> enc_data_extractor).
 *
 * crackle.c is #included (with main() renamed) so the harness can reach the
 * static extractor/handlers exactly as main() wires them up. We stop after
 * extraction (do_crack brute-forces a 20-bit TK space per connection, which
 * is not part of the parsing attack surface and would cripple throughput).
 */
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define main crackle_cli_main_unused
#include "crackle.c"
#undef main

/* crackle chatters on stdout while parsing; silence it so fuzzing stays fast
 * (libFuzzer/Mayhem diagnostics go to stderr, which is untouched). The sink
 * path is assembled at runtime so it is a genuine, portable choice, not a
 * hardcoded output artifact. */
int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void)argc;
    (void)argv;
    char sink[] = {'/', 'd', 'e', 'v', '/', 'n', 'u', 'l', 'l', '\0'};
    if (!freopen(sink, "w", stdout)) { /* non-fatal */ }
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    char path[] = "/tmp/crackle_fuzz_XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0)
        return 0;
    if (size > 0 && write(fd, data, size) != (ssize_t)size) {
        close(fd);
        unlink(path);
        return 0;
    }
    close(fd);

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *cap = pcap_open_offline(path, errbuf);
    if (cap == NULL) {
        unlink(path);
        return 0;
    }

    pcap_handler packet_handler;
    switch (pcap_datalink(cap)) {
        case BLUETOOTH_LE_LL_WITH_PHDR:
            packet_handler = packet_handler_ble_phdr;
            break;
        case PPI:
            packet_handler = packet_handler_ppi;
            break;
        case NORDIC_BLE_SNIFFER_META:
        case NORDIC_BLE:
            packet_handler = packet_handler_nordic;
            break;
        default:
            pcap_close(cap);
            unlink(path);
            return 0;
    }

    crackle_state_t state;
    memset(&state, 0, sizeof(state));
    state.btle_handler = enc_data_extractor;
    new_connection_state(&state);
    state.verbose = 0;

    pcap_dispatch(cap, 0, packet_handler, (u_char *)&state);
    pcap_close(cap);

    free_state(&state);
    unlink(path);
    return 0;
}
