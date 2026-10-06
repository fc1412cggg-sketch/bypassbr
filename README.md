# bypassbr

Login-key bypass / patcher for `deef.exe` (x64, Enigma-protected).

## พร้อมใช้ทันที (ไม่ต้อง build)

```
1. copy LoginKeyPatcher.exe ไปไว้โฟลเดอร์เดียวกับ deef.exe
2. ดับเบิลคลิก LoginKeyPatcher.exe (หรือรันผ่าน Run_LoginKeyPatcher.bat)
3. ห้ามปิดหน้าต่าง loader ขณะใช้ deef (ต้องค้างไว้เลี้ยง breakpoint)
```

> `.exe` เป็น native x64 ไฟล์เดียว ไม่ต้องลง .NET / Python / อะไรเพิ่ม —
> รันบน Windows 10/11 ได้เลย ถ้าติดตั้ง VEH ไม่ได้ให้รันแบบ **Run as Administrator**
>
> v2 ใช้วิธี **STEALTH: ไม่แก้โค้ด deef.exe ใน memory เลยสัก byte**
> (เลี่ยง Enigma "File corrupted!" check) ด้วย hardware breakpoint + VEH —
> ถ้าเจอป๊อป "debugger detected" แทน ให้แจ้งมา (ต้องเปลี่ยนแผนเป็นขั้นต่อไป)

## โหมด

```
LoginKeyPatcher.exe any                        → กรอก key อะไรก็ได้ (ห้ามว่าง) เข้าหน้าหลักทันที
LoginKeyPatcher.exe auto                       → ข้ามหน้า login เข้าหลักเลย ไม่ต้องกรอก
LoginKeyPatcher.exe custom MyKey123 "VIP User" → ใช้ได้เฉพาะ key ที่กำหนด (ไม่สนพิมพ์เล็ก/ใหญ่)
LoginKeyPatcher.exe --direct any               → วิธีเก่า (แก้โค้ดตรงๆ — Enigma จับได้)
LoginKeyPatcher.exe --restore                  → คืนค่า hook เดิม (สำหรับโหมด direct)
```

## RE tools (หาจุด hook จริง — อ่านอย่างเดียว ไม่แก้โค้ด)

```
LoginKeyPatcher.exe --diag                → ชุดสำรวจครบในรันเดียว (scan calls + หาข้อความ)
LoginKeyPatcher.exe --scan-calls 214370   → หา CALL/JMP ที่เรียก address นั้น
LoginKeyPatcher.exe --findstr "Auth..."   → หาข้อความใน memory
LoginKeyPatcher.exe --scan-ref 7FF6...    → หาโค้ดที่อ้างถึง address นั้น
LoginKeyPatcher.exe --trace 214370 2194B0 → นับว่าโค้ดวิ่งผ่านจุดนั้นไหม (1-4 จุด)
```

ทุกคำสั่งจด log ต่อท้าย `patcher_log.txt` อัตโนมัติ — ส่งไฟล์นี้มาวิเคราะห์ได้เลย

## Source

| ไฟล์ | คืออะไร |
|---|---|
| `LoginKeyPatcher.exe` | **ตัวพร้อมใช้** (native x64, build จาก `.c`) |
| `LoginKeyPatcher.c` + `sc_build.h` | source ตัวหลัก (C, cross-compile ด้วย zig) |
| `LoginKeyPatcher.cs` / `login_key_patch.py` | เวอร์ชัน C#/Python (direct-patch อย่างเดียว — Enigma จับได้, เก็บไว้เทียบ logic) |
| `Build_LoginKeyPatcher.bat` | คอมไพล์ `.cs` → `.exe` บน Windows (ถ้าจะ build เอง) |
| `Run_LoginKeyPatcher.bat` | เมนูเลือกโหมดแล้วรัน |
| `FdrrAutoPatcher.cs` / `MadiumLoader.cs` | ตัวเก่า (เก็บไว้) |

Rebuild ตัว native เองบน Linux:

```
pip install ziglang
python -m ziglang cc -target x86_64-windows-gnu -O2 -o LoginKeyPatcher.exe LoginKeyPatcher.c -lpsapi
```

## หลักการ v2 (STEALTH)

- รอ `deef.exe` unpack ใน memory (เช็ค prologue ที่ RVA `0x21A0B0` — อ่านอย่างเดียว)
- shellcode + VEH handler อยู่ใน memory block ของเราเอง (RX, นอก image — Enigma ไม่เช็ค)
- ฝัง hardware execution breakpoint (Dr0–Dr3, เลือก slot ว่าง) ที่ RVA `0x21A0B9`
  ทุก thread + watchdog คอย arm thread ใหม่ทุก 1 วินาที
- ติดตั้ง VEH ด้วย thread hijack (ไม่สร้าง thread ใหม่, ไม่ attach debugger,
  ไม่แตะ PEB) — มี CreateRemoteThread เป็น fallback
- เมื่อ breakpoint แตก: VEH ส่ง execution มาที่ shellcode → route ไป
  `mainScreen` (`0x2194B0`) หรือ `loginScreen` (`0x214370`) ตามโหมด →
  กระโดดกลับ `hook+14` — stack/register เหมือนเดิมทุกประการ
