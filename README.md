# bypassbr

Login-key bypass / patcher for `deef.exe` (x64).

## Files หลัก

| ไฟล์ | คืออะไร |
|---|---|
| `LoginKeyPatcher.cs` | ตัว patch หลัก (C#, แนะนำ) — 3 โหมดในไฟล์เดียว |
| `login_key_patch.py` | ตัว patch ภาษา Python (logic เดียวกัน, ไม่ต้องลง lib เพิ่ม) |
| `Build_LoginKeyPatcher.bat` | คอมไพล์ `.cs` → `.exe` (x64) |
| `Run_LoginKeyPatcher.bat` | เมนูเลือกโหมดแล้วรัน |
| `FdrrAutoPatcher.cs` / `MadiumLoader.cs` | ตัวเก่า (เก็บไว้) |

## วิธีใช้ (บน Windows 64-bit)

```
1. วางไฟล์ทั้งหมดไว้โฟลเดอร์เดียวกับ deef.exe
2. รัน Build_LoginKeyPatcher.bat (ครั้งเดียว) → ได้ LoginKeyPatcher.exe
3. รัน Run_LoginKeyPatcher.bat แล้วเลือกโหมด (หรือดูคำสั่งด้านล่าง)
```

> รันแบบ **Run as Administrator** ถ้า patch ไม่ติด

## โหมด

```
LoginKeyPatcher.exe any                        → กรอก key อะไรก็ได้ (ห้ามว่าง) เข้าหน้าหลักทันที
LoginKeyPatcher.exe auto                       → ข้ามหน้า login เข้าหลักเลย ไม่ต้องกรอก
LoginKeyPatcher.exe custom MyKey123 "VIP User" → ใช้ได้เฉพาะ key ที่กำหนด (ไม่สนพิมพ์เล็ก/ใหญ่)
LoginKeyPatcher.exe --restore                  → คืนค่า hook เดิม (ต้องมี hook_backup.bin)
```

เวอร์ชัน Python ใช้คำสั่งเหมือนกัน:

```
python login_key_patch.py any
python login_key_patch.py auto
python login_key_patch.py custom MyKey123 "VIP User"
python login_key_patch.py --restore
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
