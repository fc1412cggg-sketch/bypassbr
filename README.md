# bypassbr

Login-key bypass / patcher for `deef.exe` (x64).

## พร้อมใช้ทันที (ไม่ต้อง build)

```
1. copy LoginKeyPatcher.exe ไปไว้โฟลเดอร์เดียวกับ deef.exe
2. ดับเบิลคลิก LoginKeyPatcher.exe (หรือรันผ่าน Run_LoginKeyPatcher.bat)
```

> `.exe` เป็น native x64 ไฟล์เดียว (193 KB) ไม่ต้องลง .NET / Python / อะไรเพิ่ม —
> รันบน Windows 10/11 ได้เลย ถ้า patch ไม่ติดให้รันแบบ **Run as Administrator**

## โหมด

```
LoginKeyPatcher.exe any                        → กรอก key อะไรก็ได้ (ห้ามว่าง) เข้าหน้าหลักทันที
LoginKeyPatcher.exe auto                       → ข้ามหน้า login เข้าหลักเลย ไม่ต้องกรอก
LoginKeyPatcher.exe custom MyKey123 "VIP User" → ใช้ได้เฉพาะ key ที่กำหนด (ไม่สนพิมพ์เล็ก/ใหญ่)
LoginKeyPatcher.exe --restore                  → คืนค่า hook เดิม (ต้องมี hook_backup.bin)
```

## Source

| ไฟล์ | คืออะไร |
|---|---|
| `LoginKeyPatcher.exe` | **ตัวพร้อมใช้** (native x64, build จาก `.c`) |
| `LoginKeyPatcher.c` + `sc_build.h` | source ตัวหลัก (C, cross-compile ด้วย zig) |
| `LoginKeyPatcher.cs` | source เวอร์ชัน C# (logic เดียวกัน) |
| `login_key_patch.py` | เวอร์ชัน Python (ไม่ต้องลง lib เพิ่ม) |
| `Build_LoginKeyPatcher.bat` | คอมไพล์ `.cs` → `.exe` บน Windows (ถ้าจะ build เอง) |
| `Run_LoginKeyPatcher.bat` | เมนูเลือกโหมดแล้วรัน |
| `FdrrAutoPatcher.cs` / `MadiumLoader.cs` | ตัวเก่า (เก็บไว้) |

Rebuild ตัว native เองบน Linux:

```
pip install ziglang
python -m ziglang cc -target x86_64-windows-gnu -O2 -o LoginKeyPatcher.exe LoginKeyPatcher.c -lpsapi
```

## หลักการ (สั้นๆ)

- รอ `deef.exe` unpack ใน memory (เช็ค prologue ที่ RVA `0x21A0B0`)
- วาง shellcode ใน RWX block + hook จุด screen-router ที่ RVA `0x21A0B9`
  (`mov rax, shellcode; call rax; nop; nop` = 14 bytes)
- shellcode อ่าน key ที่ user พิมพ์จาก `AppContext+0x1B8` (MSVC `std::string`,
  รองรับ SSO/heap) แล้ว route ไป `mainScreen` (`0x2194B0`) หรือ
  `loginScreen` (`0x214370`) ตามโหมด — ส่ง key ที่พิมพ์จริง pass-through
  กลับไปให้ UI โชว์
- backup 14 bytes เดิมไว้ที่ `hook_backup.bin` อัตโนมัติ
