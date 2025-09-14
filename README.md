# 📒 simplePCI

### 輕量級 PCI/PCIe Configuration space解析與操作工具

這是一個 **Python 編寫的 PCI/PCIe 工具**，用於讀取並解析裝置的
**Configuration Space**，並提供基礎操作功能，例如列印
Header、Capabilities List，以及執行 **Link Disable / Hot Reset /
Function Level Reset (FLR)**。\
主要適合於 **Linux sysfs 環境**下的 PCIe 測試與除錯。

------------------------------------------------------------------------

## 🗂️ 專案結構

-   `simplePCI.py`
    -   主程式，提供解析與操作功能
-   `/sys/bus/pci/devices/<BDF>/config`
    -   Linux 下的 PCIe 配置空間檔案

------------------------------------------------------------------------

## ⚙️ 運作流程

1.  從 sysfs (`/sys/bus/pci/devices/<BDF>/config`) 讀取 PCI/PCIe
    設備配置空間\
2.  解析 Header、BAR、Subsystem、Interrupt 等欄位\
3.  透過 **Capabilities List** 找出對應功能（如 MSI、PCIe
    Capability、Resizable BAR 等）\
4.  可選擇執行 **特殊操作**：
    -   `--link-disable` → 關閉裝置 PCIe Link\
    -   `--hot-reset` → 執行 Secondary Bus Reset\
    -   `--flr` → 執行 Function Level Reset

------------------------------------------------------------------------

## 🚀 使用方式

### 1. 顯示說明

``` bash
python3 simplePCI.py -h
```

### 2. Dump Header + Capabilities List

``` bash
python3 simplePCI.py -s 03:00.0 -v
```

輸出範例：

    <PCI header>
    Offset  Bits    Name                          Attr     Value
    0x00    15:0    Vendor ID                     RO       0x8086
    0x00    31:16   Device ID                     RO       0x1234
    ...

    <Capabilities List>
    Offset  ID   Next  Name
    -----------------------------------------
    0x50    0x10  0x70  PCI Express
    0x70    0x05  0x00  MSI (Message Signaled Interrupts)

### 3. 寫入配置空間

``` bash
python3 simplePCI.py -s 03:00.0 -w 0x04 0x0007
```

（此範例將 `Command Register` 設定為 `0x7`）

### 4. 觸發特殊操作

``` bash
python3 simplePCI.py -s 03:00.0 --link-disable
python3 simplePCI.py -s 03:00.0 --hot-reset
python3 simplePCI.py -s 03:00.0 --flr
```

------------------------------------------------------------------------

## 📝 功能特色

-   支援讀取 **PCI/PCIe Header 與 Capabilities List**\
-   可查詢並顯示 **所有標準 PCI Capabilities**\
-   提供 **RESET操作**：
    -   Link Disable
    -   Hot Reset
    -   Function Level Reset (FLR)
-   支援透過 `-w` 直接修改 **Configuration space**
