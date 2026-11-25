#!/usr/bin/env python3
"""Read-only probe for TempDeck: which temperature and tyre readings this car answers, over wired ENET.

Tyre blocks (DSC 22 DC98-DC9B) and the F32 DME temperature DIDs come from OBDb's BMW 4 Series
signal sets: https://github.com/OBDb/BMW-4-Series and https://github.com/OBDb/BMW-M4

It only sends OBD mode 01 reads and UDS ReadDataByIdentifier (22) requests. Nothing is written to
any ECU. Identification DIDs (F1xx, which include the VIN) are never requested.

Quick check, ignition on or engine idling, parked (under a minute):
    python3 temps_probe.py --gateway 169.254.17.57 --label idle-warm \
        --note "cluster outside 9C; iDrive tyre screen FL 2.4 bar 14C, FR ..., RL ..., RR ..."
Also find which ECU addresses answer at all (adds about a minute):
    python3 temps_probe.py --gateway 169.254.17.57 --label sweep --sweep
Scan one ECU's identifiers, e.g. to look for the tyre data once the sweep shows candidates (long):
    python3 temps_probe.py --gateway 169.254.17.57 --label scan40 --scan 40 --ranges 2000-2FFF,4000-4FFF,D000-DFFF
"""

import argparse
import json
import socket
import struct
import time

DME, EGS = 0x12, 0x18
TESTER = 0xF4

# Standard OBD mode 01 temperature PIDs (SAE J1979), with decoders for the data bytes.
OBD_TEMPS = {
    0x05: ("coolant", lambda d: d[0] - 40),
    0x0F: ("intake air", lambda d: d[0] - 40),
    0x3C: ("catalyst B1S1 (modelled)", lambda d: ((d[0] << 8) | d[1]) / 10 - 40),
    0x3D: ("catalyst B2S1 (modelled)", lambda d: ((d[0] << 8) | d[1]) / 10 - 40),
    0x3E: ("catalyst B1S2 (modelled)", lambda d: ((d[0] << 8) | d[1]) / 10 - 40),
    0x3F: ("catalyst B2S2 (modelled)", lambda d: ((d[0] << 8) | d[1]) / 10 - 40),
    0x46: ("ambient air", lambda d: d[0] - 40),
    0x5C: ("engine oil", lambda d: d[0] - 40),
    0x67: ("coolant sensors A/B", lambda d: [d[1] - 40, d[2] - 40]),
    0x68: ("intake air sensors A/B", lambda d: [d[1] - 40, d[2] - 40]),
    0x77: ("charge air cooler temps", lambda d: [d[1] - 40, d[2] - 40]),
    0x78: ("exhaust gas bank 1 (raw)", lambda d: d.hex(" ")),
    0x79: ("exhaust gas bank 2 (raw)", lambda d: d.hex(" ")),
}
# Context readings, so temperatures can be judged against engine state.
OBD_CONTEXT = {0x0C: "rpm", 0x0D: "speed km/h", 0x33: "baro kPa"}

# DME identifiers seen in this repository or upstream issues. Decoders are candidates, not facts.
DME_DIDS = {
    0x4300: ("coolant (S55 answers 1 byte: raw*0.75-48?)",
             lambda d: d[0] * 0.75 - 48 if len(d) == 1 else ((d[0] << 8) | d[1]) / 10 - 273.15),
    0x580F: ("intake air (raw*0.75-48)", lambda d: d[0] * 0.75 - 48),
    0x4650: ("gearbox temp on A90 DME (unknown here)", lambda d: d.hex(" ")),
    0x4201: ("ambient pressure kPa (raw/256)", lambda d: ((d[0] << 8) | d[1]) / 256),
    # OBDb BMW-M4 signal set, answered by a 2015 F82 M4: 4402 oil (byte 1 / 2), 4506 oil (1 byte),
    # 4408 oil (raw/10 on 2015-2018 M4s), 4015 intake air (byte 1). 582F cat temp was refused there.
    0x4402: ("engine oil, M4 (byte1/2)", lambda d: d[1] / 2),
    0x4506: ("engine oil, M4 (1 byte)", lambda d: d[0]),
    0x4408: ("engine oil, M4 2015-18 (raw/10)", lambda d: ((d[0] << 8) | d[1]) / 10),
    0x4015: ("intake air, M4 (byte 1)", lambda d: d[1]),
    0x582F: ("catalyst temp, F32 B58/N55 (raw/10-273.15)", lambda d: round(((d[0] << 8) | d[1]) / 10 - 273.15, 1)),
}
DSC = 0x29
# Tyre blocks on the DSC, from OBDb's BMW 4 Series signal set (F32 generation, 2014-2020):
# byte 4 sensor position, bytes 5-6 pressure (little-endian, signed, /1000 bar), byte 7 temperature
# (signed C), bytes 8-9 the stored set point (little-endian, /1000 bar). Bytes count after 62 DC 9x.
TYRES = {0xDC98: "FL", 0xDC99: "FR", 0xDC9A: "RL", 0xDC9B: "RR"}
# Outside air: instrument cluster 60 D112 (byte/2 - 40) and climate control 78 D96B (word/2 - 40),
# both answered by a 2015 F82 M4 in OBDb's captures.
AMBIENT = [(0x60, 0xD112, "ambient, cluster (byte/2-40)", lambda d: d[0] / 2 - 40),
           (0x78, 0xD96B, "ambient, climate control (word/2-40)", lambda d: struct.unpack(">h", d[:2])[0] / 2 - 40)]


def tyre(d):
    s16 = lambda lo, hi: struct.unpack("<h", bytes((lo, hi)))[0] / 1000
    return {"pos": d[4], "bar": s16(d[5], d[6]), "C": struct.unpack("b", d[7:8])[0], "set_bar": s16(d[8], d[9])}


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
        assert request[0] in (0x01, 0x22), "read-only requests only"
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
    parser.add_argument("--label", required=True, help="what state the car is in: idle-cold, idle-warm ...")
    parser.add_argument("--note", default="", help="what the cluster and iDrive tyre screen show right now")
    parser.add_argument("--sweep", action="store_true", help="also list which ECU addresses 00-7F answer")
    parser.add_argument("--scan", help="scan one ECU (hex address) over --ranges instead of the quick check")
    parser.add_argument("--ranges", default="2000-2FFF,4000-4FFF,D000-DFFF", help="DID ranges for --scan")
    args = parser.parse_args()
    if args.gateway.split(".")[:2] != ["169", "254"]:
        parser.error("gateway must be a 169.254.x.x ENET address")

    link = Link(args.gateway, args.local)
    name = f"temps-probe-{args.label}-{time.strftime('%Y%m%d-%H%M')}.txt"
    counts = {}
    with open(name, "w") as out:
        out.write(json.dumps({"label": args.label, "note": args.note,
                              "time": time.strftime("%Y-%m-%d %H:%M:%S")}) + "\n")

        def record(ecu, request, meaning="", decode=None, wait=1.0, retry=True):
            status, data = link.read(ecu, request, wait)
            if status == "timeout" and retry:  # one retry on a fresh connection
                time.sleep(0.3)
                status, data = link.read(ecu, request, wait)
            key = status + (" " + data.hex() if status == "nrc" else "")
            counts[key] = counts.get(key, 0) + 1
            row = {"ecu": f"{ecu:02X}", "request": request.hex(" "), "status": status, "data": data.hex(" ")}
            if meaning:
                row["meaning"] = meaning
            if status == "ok" and decode:
                try:
                    row["value"] = decode(data)
                except (IndexError, ValueError):
                    row["value"] = "unexpected length"
            if args.scan and key == "nrc 31":  # plain "not supported" is only counted in a scan
                return status, data
            out.write(json.dumps(row) + "\n")
            out.flush()
            if not args.scan or status == "ok":
                shown = row.get("value", row["data"] if status == "ok" else key)
                print(f"  {row['ecu']} {row['request']:<9} {meaning:<42} {shown}", flush=True)
            return status, data

        try:
            if args.scan:
                ecu = int(args.scan, 16)
                dids = [d for a, b in parse_ranges(args.ranges, parser) for d in range(a, b + 1) if d >> 8 != 0xF1]
                print(f"Reading {len(dids)} identifiers on ECU {ecu:02X} (read-only). Ctrl-C keeps the results.")
                silent = 0
                for index, did in enumerate(dids):
                    status, _ = record(ecu, bytes((0x22, did >> 8, did & 0xFF)))
                    silent = silent + 1 if status == "timeout" else 0
                    if silent >= 6:
                        print(f"ECU {ecu:02X} stopped answering at {did:04X}; stopping here.")
                        break
                    if index and index % 1024 == 0:
                        print(f"  ...{index}/{len(dids)}, now at {did:04X}", flush=True)
                    time.sleep(0.004)
                return

            print("Engine ECU, standard OBD readings:")
            if record(DME, bytes((0x01, 0x0C)), OBD_CONTEXT[0x0C], lambda d: ((d[0] << 8) | d[1]) / 4)[0] != "ok":
                print("No answer from the engine ECU. Check the cable, the gateway address and that ignition is on.")
                return
            record(DME, bytes((0x01, 0x0D)), OBD_CONTEXT[0x0D], lambda d: d[0])
            record(DME, bytes((0x01, 0x33)), OBD_CONTEXT[0x33], lambda d: d[0])
            supported = set()
            for base in (0x00, 0x20, 0x40, 0x60, 0x80, 0xA0):
                status, data = record(DME, bytes((0x01, base)), f"supported PIDs {base + 1:02X}-{base + 0x20:02X}")
                if status != "ok" or len(data) < 4:
                    break
                bits = int.from_bytes(data[:4], "big")
                supported |= {base + i + 1 for i in range(32) if bits >> (31 - i) & 1}
                if not bits & 1:
                    break
            out.write(json.dumps({"supported_pids": sorted(f"{p:02X}" for p in supported)}) + "\n")
            for pid, (meaning, decode) in OBD_TEMPS.items():
                flag = "" if pid in supported else " [not listed as supported]"
                record(DME, bytes((0x01, pid)), meaning + flag, decode)

            print("Engine ECU, BMW identifiers:")
            for did, (meaning, decode) in DME_DIDS.items():
                record(DME, bytes((0x22, did >> 8, did & 0xFF)), meaning, decode)

            print("Tyres, from the DSC (pressure bar, temperature C, set point):")
            for did, corner in TYRES.items():
                record(DSC, bytes((0x22, did >> 8, did & 0xFF)), f"tyre {corner}", tyre)

            print("Outside air:")
            for ecu, did, meaning, decode in AMBIENT:
                record(ecu, bytes((0x22, did >> 8, did & 0xFF)), meaning, decode)

            print("Gearbox (DCT) status block:")
            record(EGS, bytes((0x22, 0xDE, 0x31)), "DCT oil temp, word at byte 20 (C)",
                   lambda d: [struct.unpack(">h", d[20:22])[0], struct.unpack(">h", d[22:24])[0],
                              "park" if d[36:38] == b"\0\0" else "not park"])

            if args.sweep:
                print("ECU addresses that answer (any reply, even 'not supported', means present):")
                present = []
                for ecu in range(0x00, 0x80):
                    status, data = link.read(ecu, bytes((0x22, 0x00, 0x00)), 0.35)
                    if status != "timeout":
                        present.append(f"{ecu:02X}")
                        print(f"  {ecu:02X} answers ({status} {data.hex()})", flush=True)
                out.write(json.dumps({"present_ecus": present}) + "\n")
        except KeyboardInterrupt:
            print("Stopped by you.")
        finally:
            link.close()
            out.write(json.dumps({"summary": counts}) + "\n")
            print(f"Saved {name}  {counts}")


if __name__ == "__main__":
    main()
