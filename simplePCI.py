#!/usr/bin/env python3
"""
simplePCI_pcie_gen5.py

Usage:
  sudo python3 simplePCI_pcie_gen5.py <BDF>        # same as -v (header)
  sudo python3 simplePCI_pcie_gen5.py -v <BDF>
  sudo python3 simplePCI_pcie_gen5.py -vv <BDF>   # + PCI Capabilities list
  sudo python3 simplePCI_pcie_gen5.py -vvv <BDF>  # + PCIe capability decode (Gen1..Gen5, LinkCaps2, Target Link Speed, ...)

Notes:
 - Must run as root to read /sys/bus/pci/devices/<BDF>/config
 - BDF can be "02:00.0" or "0000:02:00.0"
"""
import sys
from pathlib import Path
from typing import Optional

SYSFS_DEV = Path("/sys/bus/pci/devices")

# ------------------------------
# Helpers
# ------------------------------
def normalize_bdf(bdf: str) -> str:
    if ':' in bdf and bdf.count(':') == 2:
        return bdf
    if bdf.count(':') == 1:
        return "0000:" + bdf
    return bdf

def find_config(bdf: str) -> Optional[Path]:
    p = SYSFS_DEV / bdf / "config"
    if p.exists():
        return p
    # try suffix match
    if SYSFS_DEV.exists():
        for d in SYSFS_DEV.iterdir():
            if d.name.endswith(bdf):
                cfg = d / "config"
                if cfg.exists():
                    return cfg
    return None

def read_config_bytes(cfg_path: Path, length: int = 4096) -> bytes:
    with open(cfg_path, "rb") as f:
        return f.read(length)

def u8(data: bytes, off: int) -> Optional[int]:
    return data[off] if 0 <= off < len(data) else None

def u16(data: bytes, off: int) -> Optional[int]:
    if 0 <= off+1 < len(data):
        return data[off] | (data[off+1] << 8)
    return None

def u32(data: bytes, off: int) -> Optional[int]:
    if 0 <= off+3 < len(data):
        return (data[off] | (data[off+1] << 8) | (data[off+2] << 16) | (data[off+3] << 24))
    return None

def bits(val:int, hi:int, lo:int) -> int:
    mask = ((1 << (hi-lo+1)) - 1) << lo
    return (val & mask) >> lo

def hex_pad(val:int, width_bytes:int) -> str:
    return f"0x{val:0{width_bytes*2}x}"

# ------------------------------
# Header dump (aligned)
# ------------------------------
def dump_header(data: bytes):
    rows = [
        (0x00, "Vendor ID", 2, u16(data,0x00)),
        (0x02, "Device ID", 2, u16(data,0x02)),
        (0x04, "Command", 2, u16(data,0x04)),
        (0x06, "Status", 2, u16(data,0x06)),
        (0x08, "Revision ID", 1, u8(data,0x08)),
        (0x09, "Prog IF", 1, u8(data,0x09)),
        (0x0A, "Subclass", 1, u8(data,0x0a)),
        (0x0B, "Class Code", 1, u8(data,0x0b)),
        (0x0E, "Header Type", 1, u8(data,0x0e)),
        (0x10, "BAR0", 4, u32(data,0x10)),
        (0x14, "BAR1", 4, u32(data,0x14)),
        (0x18, "BAR2", 4, u32(data,0x18)),
        (0x1C, "BAR3", 4, u32(data,0x1c)),
        (0x20, "BAR4", 4, u32(data,0x20)),
        (0x24, "BAR5", 4, u32(data,0x24)),
        (0x2C, "Subsystem Vendor", 2, u16(data,0x2c)),
        (0x2E, "Subsystem ID", 2, u16(data,0x2e)),
        (0x34, "Capabilities Pointer", 1, u8(data,0x34)),
        (0x3C, "Interrupt Line", 1, u8(data,0x3c)),
        (0x3D, "Interrupt Pin", 1, u8(data,0x3d)),
    ]
    max_name = max(len(r[1]) for r in rows)
    for off, name, size, val in rows:
        if val is None:
            continue
        print(f"[0x{off:02x}] [{name:<{max_name}}] {hex_pad(val, size)}")

# ------------------------------
# PCI Capabilities linked list
# ------------------------------
KNOWN_CAPS = {
    0x01: "Power Management",
    0x05: "MSI",
    0x10: "PCI Express",
    0x11: "MSI-X",
    0x16: "Vendor Specific",
    0x09: "Bridge Subsystem Vendor ID",
    0x0a: "AGP (legacy)",
    # add more if needed
}

def walk_pci_caps(data: bytes, start_ptr: int):
    caps = []
    seen = set()
    ptr = start_ptr
    while ptr and ptr not in seen and ptr < len(data):
        seen.add(ptr)
        cap_id = u8(data, ptr)
        next_ptr = u8(data, ptr+1)
        caps.append((ptr, cap_id, next_ptr))
        if not next_ptr:
            break
        ptr = next_ptr
    return caps

def dump_pci_caps(data: bytes, start_ptr: int):
    if start_ptr is None or start_ptr == 0:
        print("# No PCI capabilities (cap pointer == 0)")
        return
    caps = walk_pci_caps(data, start_ptr)
    print("\n# PCI Capabilities (linked list):")
    for off, cid, nxt in caps:
        name = KNOWN_CAPS.get(cid, "Unknown")
        print(f"  [0x{off:02x}] ID=0x{cid:02x} ({name})  Next=0x{nxt:02x}")

# ------------------------------
# PCIe capability decode (full, including Cap2/LinkCap2 for Gen5)
# Based on PCIe Capability Structure layout (see Intel / PCI-SIG).
# ------------------------------
GEN_MAP = {
    1: "Gen1 (2.5 GT/s)",
    2: "Gen2 (5.0 GT/s)",
    3: "Gen3 (8.0 GT/s)",
    4: "Gen4 (16.0 GT/s)",
    5: "Gen5 (32.0 GT/s)",
}

def decode_pcie_capability(data: bytes, cap_off: int):
    # make sure we have at least first 0x30 bytes (many fields fit)
    if cap_off is None or cap_off == 0:
        print("# No PCIe capability found")
        return
    if cap_off + 0x2 >= len(data):
        print(f"# PCIe capability at 0x{cap_off:02x} out of range")
        return

    cap_id = u8(data, cap_off)
    if cap_id != 0x10:
        print(f"# Not a PCIe capability at 0x{cap_off:02x} (ID=0x{cap_id:02x})")
        return

    print("\n# PCI Express Capability (decoded):")
    cap_hdr_word = u16(data, cap_off+2)            # Capability Register (16-bit)
    cap_version = bits(cap_hdr_word, 3, 0)
    device_port_type = bits(cap_hdr_word, 15, 4)
    print(f"  [0x{cap_off:02x}] Capability Reg (ver/type) : 0x{cap_hdr_word:04x}  version={cap_version}  device_port_type=0x{device_port_type:x}")

    # Device Capabilities (offset +4, 4 bytes)
    dev_caps = u32(data, cap_off+4)
    if dev_caps is not None:
        print(f"  [0x{cap_off+4:02x}] Device Capabilities    : 0x{dev_caps:08x}")
        # example subfields (per spec)
        print(f"    - Max Payload Size Supported : {bits(dev_caps, 2, 0)}")
        print(f"    - Phantom Functions Supported: {bits(dev_caps, 3, 3)}")
        print(f"    - Extended Tag Supported     : {bits(dev_caps, 4, 4)}")
        print(f"    - Endpoint L0s Acceptable Lat: {bits(dev_caps, 6,5)}")
        print(f"    - Endpoint L1 Acceptable Lat : {bits(dev_caps, 8,7)}")

    # Device Control / Status (offset +8, +0A)
    dev_ctrl = u16(data, cap_off+8)
    dev_stat = u16(data, cap_off+0xA)
    if dev_ctrl is not None:
        print(f"  [0x{cap_off+8:02x}] Device Control         : 0x{dev_ctrl:04x}")
    if dev_stat is not None:
        print(f"  [0x{cap_off+0xA:02x}] Device Status          : 0x{dev_stat:04x}")

    # Link Capabilities (offset +0x0C 4 bytes), Link Control + Link Status (+0x10, +0x12)
    link_caps = u32(data, cap_off+0x0C)
    link_ctrl = u16(data, cap_off+0x10)
    link_stat = u16(data, cap_off+0x12)
    if link_caps is not None:
        max_speed_code = bits(link_caps, 3, 0)
        max_width = bits(link_caps, 9, 4)
        aspm_l0s = bits(link_caps, 10,10)
        aspm_l1 = bits(link_caps, 11,11)
        print(f"  [0x{cap_off+0x0C:02x}] Link Capabilities      : 0x{link_caps:08x}")
        print(f"    - Maximum Link Speed (code): {max_speed_code} -> {GEN_MAP.get(max_speed_code, str(max_speed_code))}")
        print(f"    - Maximum Link Width        : x{max_width}")
        print(f"    - ASPM L0s support          : {bool(aspm_l0s)}")
        print(f"    - ASPM L1 support           : {bool(aspm_l1)}")
    if link_ctrl is not None:
        target_speed = bits(link_ctrl, 3, 0)
        retrain = bits(link_ctrl, 5, 5)
        common_clock = bits(link_ctrl, 8, 8)
        print(f"  [0x{cap_off+0x10:02x}] Link Control           : 0x{link_ctrl:04x}")
        print(f"    - Target Link Speed (req)  : {target_speed} -> {GEN_MAP.get(target_speed, target_speed)}")
        print(f"    - Retrain Link             : {bool(retrain)}")
        print(f"    - Common Clock             : {bool(common_clock)}")
    if link_stat is not None:
        cur_speed = bits(link_stat, 3, 0)
        cur_width = bits(link_stat, 9, 4)
        print(f"  [0x{cap_off+0x12:02x}] Link Status            : 0x{link_stat:04x}")
        print(f"    - Current Link Speed (code): {cur_speed} -> {GEN_MAP.get(cur_speed, cur_speed)}")
        print(f"    - Current Link Width       : x{cur_width}")

    # Device Capabilities 2 (offset +0x18, 4 bytes) and Device Control2 (offset +0x1C)
    dev_caps2 = u32(data, cap_off+0x18)
    dev_ctrl2 = u16(data, cap_off+0x1C)
    if dev_caps2 is not None:
        print(f"  [0x{cap_off+0x18:02x}] Device Capabilities 2  : 0x{dev_caps2:08x}")
    if dev_ctrl2 is not None:
        print(f"  [0x{cap_off+0x1C:02x}] Device Control 2       : 0x{dev_ctrl2:04x}")

    # Link Capabilities 2 is at offset +0x2C in the PCIe capability structure (per spec)
    link_caps2 = u32(data, cap_off+0x2C)
    if link_caps2 is not None:
        print(f"  [0x{cap_off+0x2C:02x}] Link Capabilities 2    : 0x{link_caps2:08x}")
        # Link Cap 2 low bits 3:1 encode supported speeds as a bitmask: see spec (each bit indicates GEN)
        # In many vendors: bits [3:1] describe supported speed bitfields for up to Gen5 compatibility bit positions.
        # We'll decode common convention: bit1->Gen1, bit2->Gen2, bit3->Gen3, bit4->Gen4, bit5->Gen5 (positions may vary across revisions)
        supported_mask = bits(link_caps2, 3, 1)
        # but newer docs may use different bit positions; attempt to show individual bits up to bit 7
        supported_bits = [(i, bool((link_caps2 >> i) & 1)) for i in range(0, 8)]
        print(f"    - Supported speed bits (bit index -> value): {supported_bits}")
        # common mapping (readers: check your vendor docs if bits differ)
        # try to infer Gen1..Gen5 presence by checking specific bit positions (best-effort)
        gen_support = []
        # heuristic: common mapping: bit1=Gen1, bit3=Gen2? Because different docs vary; show raw mask
        # We'll explicitly display 'Target Link Speed' if Link Control 2 exists
    # Link Control 2 and Link Status 2 (offset +0x30 and +0x32 normally)
    link_ctrl2 = u16(data, cap_off+0x30)
    link_stat2 = u16(data, cap_off+0x32)
    if link_ctrl2 is not None:
        tgt = bits(link_ctrl2, 3, 0)
        print(f"  [0x{cap_off+0x30:02x}] Link Control 2         : 0x{link_ctrl2:04x}")
        print(f"    - Target Link Speed (control2) : {tgt} -> {GEN_MAP.get(tgt, tgt)}")
    if link_stat2 is not None:
        tgt_stat = bits(link_stat2, 3, 0)
        print(f"  [0x{cap_off+0x32:02x}] Link Status 2          : 0x{link_stat2:04x}")
        print(f"    - Current Target Link Speed: {tgt_stat} -> {GEN_MAP.get(tgt_stat, tgt_stat)}")

    print("\n  Note: Link Capabilities 2 encodings can vary by spec rev; this tool reports raw fields and common decodes for Gen1..Gen5.")

# ------------------------------
# Main
# ------------------------------
def main():
    if len(sys.argv) < 2:
        print("Usage: sudo python3 simplePCI_pcie_gen5.py [-v|-vv|-vvv] <BDF>")
        sys.exit(1)

    # parse args: allow either: <BDF> or -v/-vv/-vvv plus BDF
    verbosity = 1  # default when only BDF provided -> behave like -v
    bdf = None
    for arg in sys.argv[1:]:
        if arg.startswith("-v"):
            verbosity = len(arg)  # -v => 2 (we'll subtract 1 later)
        elif arg.startswith("-"):
            # ignore other flags
            pass
        else:
            bdf = arg
    if bdf is None:
        print("Error: missing BDF (e.g. 02:00.0)")
        sys.exit(2)

    # normalize verbosity: convert -v/-vv/-vvv to numeric levels 1/2/3
    # if user gave "-v" that's string len 2; we convert to level = len("-v") - 1
    # but if user passed only BDF, verbosity remains default 1
    if isinstance(verbosity, int) and verbosity >= 2:
        level = verbosity - 1
    else:
        level = 1

    bdf_norm = normalize_bdf(bdf)
    cfg = find_config(bdf_norm)
    if cfg is None:
        print(f"Device {bdf_norm} not found under {SYSFS_DEV}")
        sys.exit(3)

    try:
        data = read_config_bytes(cfg, 4096)
    except PermissionError:
        print("Permission denied. Run as root (sudo) to read config space.")
        sys.exit(4)

    print(f"# PCI device: {cfg.parent.name}")
    print(f"# Read {len(data)} bytes from {cfg}\n")

    # header (level >=1)
    dump_header(data)

    # capabilities list (level >=2)
    if level >= 2:
        cap_ptr = u8(data, 0x34)
        dump_pci_caps(data, cap_ptr)

    # PCIe capability decode (level >=3)
    if level >= 3:
        # find PCIe capability offset in the capabilities linked list
        cap_ptr = u8(data, 0x34)
        pcie_off = None
        if cap_ptr:
            caps = walk_pci_caps(data, cap_ptr)
            for off, cid, nxt in caps:
                if cid == 0x10:  # PCI Express
                    pcie_off = off
                    break
        if pcie_off is None:
            print("\n# PCIe Capability not found in capabilities list.")
        else:
            decode_pcie_capability(data, pcie_off)

if __name__ == "__main__":
    main()
