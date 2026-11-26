#!/usr/bin/env python3
"""Read-only probe of the DCT gearbox ECU over wired ENET, to find Park status and oil temperature.

It only sends OBD mode 01 reads and UDS ReadDataByIdentifier (22) requests. Nothing is written
to any ECU. Identification DIDs (F1xx, which include the VIN) are never requested.

Full scan (about 30-45 minutes, ignition on, parked; Ctrl-C keeps what was found so far):
    python3 dct_probe.py --gateway 169.254.17.57 --label park
Check an older-style gearbox read as well (21 0A), plus one known identifier:
    python3 dct_probe.py --gateway 169.254.17.57 --label kwp --local-ids 0a --dids DE31
Re-read only chosen identifiers in another state (seconds):
    python3 dct_probe.py --gateway 169.254.17.57 --label neutral --dids 4a2b,d0c1
"""

import argparse
import json
import socket
import struct
import time

DME, EGS = 0x12, 0x18
TESTER = 0xF4
FULL = "4000-5FFF,D000-EFFF,2000-3FFF,0000-1FFF,6000-CFFF,F000-F0FF,F200-FFFF"


class Link:
    def __init__(self, gateway, local):
        self.gateway, self.local, self.conn = gateway, local, None

    def close(self):
        if self.conn:
            self.conn.close()
        self.conn = None

    def _exact(self, length, deadline):
        data = bytearray()
        while len(data) < length:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError
            self.conn.settimeout(remaining)
            part = self.conn.recv(length - len(data))
            if not part:
                raise ConnectionError("gateway closed the connection")
            data.extend(part)
        return bytes(data)

    def read(self, ecu, request, wait=1.0):
        """Return ("ok", data), ("nrc", code) or ("timeout", b"")."""
        assert request[0] in (0x01, 0x21, 0x22), "read-only requests only"
        assert not (request[0] == 0x22 and request[1] == 0xF1), "identification DIDs are not read"
        try:
            if not self.conn:
                source = (self.local, 0) if self.local else None
                self.conn = socket.create_connection((self.gateway, 6801), timeout=2, source_address=source)
            self.conn.sendall(struct.pack(">IHBB", len(request) + 2, 1, TESTER, ecu) + request)
            deadline = time.monotonic() + wait
            prefix = bytes((request[0] + 0x40,)) + request[1:]
            while True:
                length, control = struct.unpack(">IH", self._exact(6, deadline))
                if length > 8192:
                    raise ValueError("oversized frame")
                payload = self._exact(length, deadline)
                if control == 0x12:  # gateway alive check
                    self.conn.sendall(struct.pack(">IHBB", 2, 0x13, 0, TESTER))
                if control != 1 or payload[:2] != bytes((ecu, TESTER)):
                    continue
                reply = payload[2:]
                if reply.startswith(prefix):
                    return "ok", reply[len(prefix):]
                if len(reply) == 3 and reply[0] == 0x7F and reply[1] == request[0]:
                    if reply[2] == 0x78:  # response pending
                        deadline = time.monotonic() + wait
                        continue
                    return "nrc", reply[2:]
        except (TimeoutError, OSError, ValueError):
            # A late answer must never be matched to the next request: start a fresh connection.
            self.close()
            return "timeout", b""


def parse_ranges(text, parser):
    spans = []
    for span in text.split(","):
        first, _, last = span.partition("-")
        first, last = int(first, 16), int(last or first, 16)
        if not 0 <= first <= last <= 0xFFFF:
            parser.error("bad range " + span)
        spans.append((first, last))
    return spans


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--gateway", required=True, help="diagnostic gateway IPv4, e.g. 169.254.17.57")
    parser.add_argument("--local", help="only if needed: this computer's wired ENET IPv4 (169.254.x.x)")
    parser.add_argument("--label", required=True, help="what state the car is in: park, neutral, warm ...")
    parser.add_argument("--ranges", default=FULL, help="gearbox DID ranges to scan, hex, comma separated")
    parser.add_argument("--local-ids", help="also send read-only 21 xx (ReadDataByLocalIdentifier) to the gearbox, "
                        "hex bytes, comma separated, e.g. 0a")
    parser.add_argument("--dids", help="only read these gearbox DIDs (hex, comma separated) instead of scanning")
    args = parser.parse_args()
    if args.gateway.split(".")[:2] != ["169", "254"]:
        parser.error("gateway must be a 169.254.x.x ENET address")
    spans = parse_ranges(args.dids if args.dids else args.ranges, parser)
    dids = [d for first, last in spans for d in range(first, last + 1) if d >> 8 != 0xF1]

    link = Link(args.gateway, args.local)
    name = f"dct-probe-{args.label}-{time.strftime('%H%M%S')}.txt"
    counts = {}
    last = [None]
    with open(name, "w") as out:
        out.write(json.dumps({"label": args.label, "time": time.strftime("%Y-%m-%d %H:%M:%S")}) + "\n")

        def record(ecu, request, show=True):
            status, data = link.read(ecu, request)
            if status == "timeout":  # one retry on a fresh connection
                time.sleep(0.5)
                status, data = link.read(ecu, request)
            key = status + (" " + data.hex() if status == "nrc" else "")
            counts[key] = counts.get(key, 0) + 1
            row = last[0] = {"ecu": f"{ecu:02X}", "request": request.hex(" "), "status": status, "data": data.hex(" ")}
            if key != "nrc 31":  # plain "not supported" is only counted
                out.write(json.dumps(row) + "\n")
                out.flush()
            if status == "ok" and show:
                print(json.dumps(row), flush=True)
            return status

        try:
            print("Engine checks (rpm, speed, coolant, engine oil temperature):")
            if record(DME, bytes.fromhex("010c")) != "ok":
                print("No answer from the engine ECU. Check the cable, the gateway address and that ignition is on.")
            for r in ("010d", "0105", "015c"):
                record(DME, bytes.fromhex(r))
            for item in (args.local_ids or "").split(","):
                if item:
                    request = bytes((0x21, int(item, 16)))
                    status = record(EGS, request, show=False)
                    print(f"Gearbox {request.hex(' ')}: {status}", json.dumps(last[0]))
            print(f"Reading {len(dids)} gearbox identifiers (read-only). Ctrl-C stops and keeps the results.")
            silent, started = 0, time.monotonic()
            for index, did in enumerate(dids):
                status = record(EGS, bytes((0x22, did >> 8, did & 0xFF)))
                silent = silent + 1 if status == "timeout" else 0
                if silent >= 6:
                    print(f"The gearbox ECU stopped answering at {did:04X}; stopping here.")
                    break
                if index and index % 2048 == 0:
                    left = (time.monotonic() - started) / index * (len(dids) - index) / 60
                    print(f"  ...{index}/{len(dids)} done, now at {did:04X}, about {left:.0f} min left", flush=True)
                time.sleep(0.004)
        except KeyboardInterrupt:
            print("Stopped by you.")
        finally:
            link.close()
            out.write(json.dumps({"summary": counts}) + "\n")
    print(f"Saved {name}  {counts}")


if __name__ == "__main__":
    main()
