#!/usr/bin/env python3
"""Read-only probe of the DCT gearbox ECU over wired ENET, to find Park status and oil temperature.

It only sends OBD mode 01 reads and UDS ReadDataByIdentifier (22) requests. Nothing is written
to any ECU. Identification DIDs (F1xx, which include the VIN) are never requested.

Run it parked, engine running, once per condition, for example:
    python3 dct_probe.py --gateway 169.254.17.57 --label park
    python3 dct_probe.py --gateway 169.254.17.57 --label neutral
"""

import argparse
import json
import socket
import struct
import time

DME, EGS = 0x12, 0x18
TESTER = 0xF4


def exact(conn, length, deadline):
    data = bytearray()
    while len(data) < length:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError
        conn.settimeout(remaining)
        part = conn.recv(length - len(data))
        if not part:
            raise ConnectionError("gateway closed the connection")
        data.extend(part)
    return bytes(data)


def exchange(conn, ecu, request, wait=1.5):
    assert request[0] in (0x01, 0x22), "read-only requests only"
    assert not (request[0] == 0x22 and request[1] == 0xF1), "identification DIDs are not read"
    conn.sendall(struct.pack(">IHBB", len(request) + 2, 1, TESTER, ecu) + request)
    deadline = time.monotonic() + wait
    prefix = bytes((request[0] + 0x40,)) + request[1:]
    while True:
        length, control = struct.unpack(">IH", exact(conn, 6, deadline))
        if length > 8192:
            raise ValueError("oversized frame")
        payload = exact(conn, length, deadline)
        if control == 0x12:  # gateway alive check
            conn.sendall(struct.pack(">IHBB", 2, 0x13, 0, TESTER))
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


def read(gateway, ecu, request, local=None):
    try:
        source = (local, 0) if local else None
        with socket.create_connection((gateway, 6801), timeout=2, source_address=source) as conn:
            return exchange(conn, ecu, request)
    except TimeoutError:
        return "timeout", b""
    except OSError:  # refused, reset or closed: treat like no answer and carry on
        return "timeout", b""


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--gateway", required=True, help="diagnostic gateway IPv4, e.g. 169.254.17.57")
    parser.add_argument("--local", help="only if needed: this computer's wired ENET IPv4 (169.254.x.x)")
    parser.add_argument("--label", required=True, help="what state the car is in: park, neutral, warm ...")
    parser.add_argument("--ranges", default="DA00-DAFF,D900-D9FF,DB00-DBFF",
                        help="gearbox DID ranges to scan, hex, comma separated")
    args = parser.parse_args()
    if args.gateway.split(".")[:2] != ["169", "254"]:
        parser.error("gateway must be a 169.254.x.x ENET address")

    name = f"dct-probe-{args.label}-{time.strftime('%H%M%S')}.txt"
    rows = []

    def record(ecu, request):
        status, data = read(args.gateway, ecu, request, args.local)
        row = {"ecu": f"{ecu:02X}", "request": request.hex(" "), "status": status, "data": data.hex(" ")}
        rows.append(row)
        if status == "ok":
            print(json.dumps(row), flush=True)
        time.sleep(0.08)
        return status

    print("Engine checks (rpm, speed, coolant, engine oil temperature):")
    engine_ok = [record(DME, bytes.fromhex(r)) for r in ("010c", "010d", "0105", "015c")]
    if engine_ok[0] != "ok":
        print("No answer from the engine ECU. Check the cable, the gateway address and that ignition is on.")
    print("Gearbox reads the apps use today (Park status DA2E, oil temperature DA12):")
    for r in ("22da2e", "22da12"):
        status = record(EGS, bytes.fromhex(r))
        print(f"  {r}: {status} {rows[-1]['data']}")

    print("Scanning gearbox identifiers (read-only). This takes a few minutes...")
    silent = 0
    for span in args.ranges.split(","):
        first, last = (int(x, 16) for x in span.split("-"))
        if not (0xD000 <= first <= last <= 0xEFFF):
            parser.error("ranges must stay inside D000-EFFF")
        for did in range(first, last + 1):
            if did in (0xDA2E, 0xDA12):
                continue
            status = record(EGS, bytes((0x22, did >> 8, did & 0xFF)))
            silent = silent + 1 if status == "timeout" else 0
            if silent >= 6:
                print("The gearbox ECU stopped answering; stopping the scan here.")
                break
        if silent >= 6:
            break

    with open(name, "w") as out:
        out.write(json.dumps({"label": args.label, "time": time.strftime("%Y-%m-%d %H:%M:%S")}) + "\n")
        for row in rows:
            if row["status"] != "nrc" or row["data"] != "31":  # skip plain "not supported"
                out.write(json.dumps(row) + "\n")
        counts = {}
        for row in rows:
            key = row["status"] + (" " + row["data"] if row["status"] == "nrc" else "")
            counts[key] = counts.get(key, 0) + 1
        out.write(json.dumps({"summary": counts}) + "\n")
    print(f"Saved {name}")


if __name__ == "__main__":
    main()
