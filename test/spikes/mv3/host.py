#!/usr/bin/python3 -I
# MV3 spike native host: logs every message with a timestamp.
import sys, struct, json, time
log = open("/tmp/vpncell-spike.log", "a", buffering=1)
log.write(f"{time.time():.1f} host start\n")
while True:
    h = sys.stdin.buffer.read(4)
    if len(h) < 4:
        log.write(f"{time.time():.1f} host EOF\n"); break
    n = struct.unpack("<I", h)[0]
    m = json.loads(sys.stdin.buffer.read(n))
    log.write(f"{time.time():.1f} {json.dumps(m)}\n")
