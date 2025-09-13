#!/usr/bin/env python3
import argparse
import sys
import textwrap
import os
import struct

PCI_CAP_NAMES = {
    0x01: "Power Management",
    0x02: "AGP",
    0x03: "VPD (Vital Product Data)",
    0x04: "Slot Identification",
    0x05: "MSI (Message Signaled Interrupts)",
    0x06: "CompactPCI HotSwap",
    0x07: "PCI-X",
    0x08: "HyperTransport",
    0x09: "Vendor Specific",
    0x0A: "Debug Port",
    0x0B: "CompactPCI Central Resource Control",
    0x0C: "PCI Hot-Plug",
    0x0D: "SATA Data/Index Config",
    0x0E: "PCI-X 2.0",
    0x0F: "PCIe Advanced Features",
    0x10: "PCI Express",
    0x11: "MSI-X",
    0x12: "HyperTransport (Alt)",
    0x13: "Vendor Specific (Alt)",
    0x14: "Bridge Subsystem Vendor ID",
    0x15: "AGP 8x",
    0x16: "Secure Device",
    0x17: "PCI Express Endpoint ID",
    0x18: "MSI Pooled Subsystem",
    0x19: "SATA Configuration",
    0x1A: "Advanced Features (PCIe AF)",
    0x1B: "Enhanced Allocation",
    0x1C: "Flattening Portal Bridge",
    0x1D: "Resizable BAR",
    0x1E: "Dynamic Power Allocation",
    0x1F: "TPH Requester",
    0x20: "Latency Tolerance Reporting (LTR)",
    0x21: "Secondary PCIe Capability",
    0x22: "Process Address Space ID (PASID)",
    0x23: "Designated Vendor-Specific Extended Capability (DVSEC)",
    0x24: "Data Object Exchange (DOE)",
    0x25: "Integrity and Data Encryption (IDE)",
    0x26: "Device Serial Number (DSN)",
    0x27: "Readiness Time Reporting",
    0x28: "Uncorrectable Error Severity",
    0x29: "Page Request Interface (PRI)",
    0x2A: "Scalable I/O Virtualization (SIOV)",
    0x2B: "Compute Express Link (CXL)",
    0x2C: "Performance Monitoring",
    0x2D: "Data Cache Interface",
    0x2E: "Power Management Hints",
    0x2F: "Multi-Function Virtual Channel (MFVC)",
    0x30: "Protocol Multiplexing",
    0x31: "Compute Express Link 2.0+ (CXL Ext)",
    0x32: "Vendor-Specific Extended Capability (new)",
}



def bdf_to_sysfs(bdf: str) -> str:
    if len(bdf.split(":")) == 2:  # e.g. 00:1f.0
        bdf = "0000:" + bdf
    return f"/sys/bus/pci/devices/{bdf}/config"

def read_config(bdf: str) -> bytes:
    path = bdf_to_sysfs(bdf)
    if not os.path.exists(path):
        print(f"Device {bdf} not found.")
        sys.exit(1)
    with open(path, "rb") as f:
        return f.read(256)

def field(ofs, bits, name, attr, val):
    print(f"0x{ofs:02X}  {bits:<7} {name:<30} {attr:<7} 0x{val:X}")

def print_table_header(title):
    print(f"\n{title}")
    print("Offset  Bits    Name                          Attr     Value")
    print("---------------------------------------------------------------")

def print_header(cfg: bytes):
    print_table_header("<PCI header>")
    vendor, device = struct.unpack_from("<HH", cfg, 0x00)
    field(0x00, "15:0", "Vendor ID", "RO", vendor)
    field(0x00, "31:16", "Device ID", "RO", device)

    command, status = struct.unpack_from("<HH", cfg, 0x04)
    field(0x04, "15:0", "Command", "RW", command)
    field(0x06, "31:16", "Status", "RO/RC", status)

    rev, prog_if, subclass, classcode = struct.unpack_from("<BBBB", cfg, 0x08)
    field(0x08, "7:0", "Revision ID", "RO", rev)
    field(0x08, "15:8", "Prog IF", "RO", prog_if)
    field(0x08, "23:16", "Subclass", "RO", subclass)
    field(0x08, "31:24", "Class Code", "RO", classcode)

    cacheline, latency, header_type, bist = struct.unpack_from("<BBBB", cfg, 0x0C)
    field(0x0C, "7:0", "Cache Line Size", "RW", cacheline)
    field(0x0D, "15:8", "Latency Timer", "RW", latency)
    field(0x0E, "23:16", "Header Type", "RO", header_type)
    field(0x0F, "31:24", "BIST", "RO/WO", bist)

    for i in range(6):
        bar, = struct.unpack_from("<I", cfg, 0x10 + i*4)
        field(0x10+i*4, "31:0", f"BAR{i}", "RW", bar)

    cardbus, = struct.unpack_from("<I", cfg, 0x28)
    field(0x28, "31:0", "CardBus CIS Ptr", "RO", cardbus)

    subsys_vendor, subsys_id = struct.unpack_from("<HH", cfg, 0x2C)
    field(0x2C, "15:0", "Subsystem Vendor ID", "RO", subsys_vendor)
    field(0x2E, "31:16", "Subsystem ID", "RO", subsys_id)

    exp_rom, = struct.unpack_from("<I", cfg, 0x30)
    field(0x30, "31:0", "Expansion ROM BAR", "RW", exp_rom)

    cap_ptr = cfg[0x34]
    field(0x34, "7:0", "Capabilities Ptr", "RO", cap_ptr)

    intr_line, intr_pin, min_gnt, max_lat = struct.unpack_from("<BBBB", cfg, 0x3C)
    field(0x3C, "7:0", "Interrupt Line", "RW", intr_line)
    field(0x3D, "15:8", "Interrupt Pin", "RO", intr_pin)
    field(0x3E, "23:16", "Min_Gnt", "RO", min_gnt)
    field(0x3F, "31:24", "Max_Lat", "RO", max_lat)

def walk_capabilities(cfg: bytes):
    _, status = struct.unpack_from("<HH", cfg, 0x04)
    if not (status & 0x10):  # no Capabilities List
        return []

    cap_ptr = cfg[0x34]
    caps = []
    visited = set()

    while cap_ptr and cap_ptr < len(cfg):
        if cap_ptr in visited:  # avoid loops
            break
        visited.add(cap_ptr)

        cap_id = cfg[cap_ptr]
        next_ptr = cfg[cap_ptr + 1]
        caps.append((cap_ptr, cap_id, next_ptr))
        cap_ptr = next_ptr
    return caps

def print_caps(caps):
    print("\n<Capabilities List>")
    print("Offset  ID   Next  Name")
    print("-----------------------------------------")
    for ofs, capid, nxt in caps:
        name = PCI_CAP_NAMES.get(capid, f"Unknown (0x{capid:02X})")
        print(f"0x{ofs:02X}   0x{capid:02X}  0x{nxt:02X}  {name}")

def write_config(bdf: str, offset: int, data: int):
    path = bdf_to_sysfs(bdf)
    if not os.path.exists(path):
        print(f"Device {bdf} not found.")
        sys.exit(1)
    with open(path, "r+b") as f:
        f.seek(offset)
        f.write(struct.pack("<I", data))
    print(f"Wrote 0x{data:08X} to {bdf} @ 0x{offset:02X}")

def main():
    parser = argparse.ArgumentParser(
        description="Simple PCI info dumper",
        add_help=False,
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("-h", "--help", action="store_true", help="Show help message")
    parser.add_argument("-s", metavar="B:D.F", help="Select PCI device by BDF")
    parser.add_argument("-v", action="store_true", help="Verbose: dump header + capabilities")
    parser.add_argument("-w", nargs=2, metavar=("OFFSET", "DATA"),
                        help="Write 32-bit DATA to config OFFSET")

    args = parser.parse_args()

    if len(sys.argv) == 1 or args.help:
        print(textwrap.dedent("""\
            Usage: simplePCI.py [-h --help] -s B:D.F [-v] [-w offset data]
              -h, --help       Show this help
              -s B:D.F         Select PCI device
              -v               Dump PCI header + Capabilities list
              -w ofs val       Write 32-bit value to config space
        """))
        sys.exit(0)

    if not args.s:
        print("Error: -s B:D.F is required")
        sys.exit(1)

    if args.w:
        ofs = int(args.w[0], 0)   # auto-parse hex/dec
        val = int(args.w[1], 0)
        write_config(args.s, ofs, val)
        sys.exit(0)

    cfg = read_config(args.s)

    if args.v:
        print_header(cfg)
        caps = walk_capabilities(cfg)
        print_caps(caps)


if __name__ == "__main__":
    main()
