using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace LoginKeyPatcher
{
    class Program
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool CloseHandle(IntPtr hObject);

        [DllImport("psapi.dll", SetLastError = true)]
        static extern bool EnumProcessModules(IntPtr hProcess, [Out] IntPtr[] lphModule, uint cb, out uint lpcbNeeded);

        [DllImport("psapi.dll", SetLastError = true)]
        static extern uint GetModuleBaseName(IntPtr hProcess, IntPtr hModule, [Out] StringBuilder lpBaseName, uint nSize);

        const uint PROCESS_ALL_ACCESS = 0x1F0FFF;
        const uint PAGE_EXECUTE_READWRITE = 0x40;
        const uint MEM_COMMIT = 0x1000;
        const uint MEM_RESERVE = 0x2000;

        // ===== Reversed addresses (deef.exe x64) =====
        const long RVA_LOGIN_SCREEN = 0x214370;
        const long RVA_MAIN_SCREEN  = 0x2194B0;
        const long RVA_WRAPPER      = 0x21A0B0; // unpack check: expect bytes 40 53
        const long RVA_HOOK         = 0x21A0B9; // 14-byte patch site
        const int  HOOK_LEN         = 14;

        // key std::string inside AppContext (MSVC layout: ptr/size/cap)
        const int OFF_KEY_STR = 0x1B8;
        const int OFF_KEY_LEN = 0x1C8;
        const int OFF_KEY_CAP = 0x1D0;

        // layout inside our allocated RWX block
        const int LAYOUT_CODE      = 0x000;
        const int LAYOUT_USER_STR  = 0x300; // fake username std::string (32 bytes)
        const int LAYOUT_KEY_STR   = 0x320; // fake key std::string (32 bytes, auto mode)
        const int LAYOUT_EXPECT    = 0x340; // expected key raw bytes (custom mode, max 128)
        const int LAYOUT_USER_LONG = 0x3C0; // username chars if len > 15 (max 64)
        const int LAYOUT_KEY_LONG  = 0x400; // key chars if len > 15 (max 64)

        static void Usage()
        {
            Console.WriteLine("Usage:");
            Console.WriteLine("  LoginKeyPatcher.exe [mode] [key] [username]");
            Console.WriteLine();
            Console.WriteLine("  mode:");
            Console.WriteLine("    any     = กรอก key อะไรก็ได้ (ยาว > 0) เข้าหน้าหลักทันที [default]");
            Console.WriteLine("    auto    = ข้ามหน้า login ไปหน้าหลักเลย ไม่ต้องกรอกอะไร");
            Console.WriteLine("    custom  = ใช้ได้เฉพาะ key ที่กำหนด (ไม่สนตัวพิมพ์เล็ก/ใหญ่)");
            Console.WriteLine();
            Console.WriteLine("  Examples:");
            Console.WriteLine("    LoginKeyPatcher.exe any");
            Console.WriteLine("    LoginKeyPatcher.exe auto");
            Console.WriteLine("    LoginKeyPatcher.exe custom MySecret123 \"VIP User\"");
            Console.WriteLine("    LoginKeyPatcher.exe --restore   (คืนค่า hook เดิม)");
            Console.WriteLine();
        }

        static void Main(string[] args)
        {
            Console.Title = "Login Key Patcher - deef bypass";
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("=================================================");
            Console.WriteLine("        LOGIN KEY PATCHER  (deef bypass)         ");
            Console.WriteLine("=================================================");
            Console.ResetColor();

            if (IntPtr.Size != 8)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("[!] ต้องรันตัว patcher แบบ 64-bit (x64) เท่านั้น!");
                Console.ResetColor();
                Console.ReadKey();
                return;
            }

            string mode = "any";
            string key = "";
            string username = "VIP User";

            if (args.Length > 0)
            {
                string a0 = args[0].ToLower();
                if (a0 == "--help" || a0 == "-h" || a0 == "/?") { Usage(); return; }
                if (a0 == "--restore") { DoRestore(); return; }
                if (a0 == "any" || a0 == "auto" || a0 == "custom") mode = a0;
                else { Console.WriteLine("[!] mode ไม่ถูกต้อง"); Usage(); return; }
            }
            if (args.Length > 1) key = args[1];
            if (args.Length > 2) username = args[2];

            if (mode == "custom")
            {
                if (string.IsNullOrEmpty(key))
                {
                    Console.WriteLine("[!] custom mode ต้องระบุ key ด้วย");
                    Usage(); return;
                }
                if (key.Length > 128) { Console.WriteLine("[!] key ยาวเกิน 128 ตัวอักษร"); return; }
            }
            if (username.Length > 64) { Console.WriteLine("[!] username ยาวเกิน 64 ตัวอักษร"); return; }
            if (mode == "auto" && string.IsNullOrEmpty(key)) key = "VIP-PREMIUM";

            Console.WriteLine("[*] Mode: " + mode.ToUpper() +
                (mode == "custom" ? "  (key=\"" + key + "\")" : "") +
                "  user=\"" + username + "\"");

            string currentDir = AppDomain.CurrentDomain.BaseDirectory;
            string targetExe = Path.Combine(currentDir, "deef.exe");

            Process targetProc = null;
            Process[] existing = Process.GetProcessesByName("deef");
            if (existing.Length > 0)
            {
                targetProc = existing[0];
                Console.WriteLine("[+] พบ deef.exe ที่รันอยู่ (PID: " + targetProc.Id + ")");
            }
            else
            {
                if (!File.Exists(targetExe))
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("[!] ไม่พบไฟล์ deef.exe ใน " + currentDir);
                    Console.ResetColor();
                    Console.WriteLine("กดปุ่มใดๆ เพื่อออก...");
                    Console.ReadKey();
                    return;
                }
                Console.WriteLine("[*] กำลังเปิด deef.exe...");
                ProcessStartInfo psi = new ProcessStartInfo(targetExe);
                psi.WorkingDirectory = currentDir;
                psi.UseShellExecute = true;
                targetProc = Process.Start(psi);
                Console.WriteLine("[+] เปิด deef.exe สำเร็จ (PID: " + targetProc.Id + ")");
            }

            // ---- wait for unpack + get base ----
            IntPtr hProc = IntPtr.Zero;
            IntPtr baseAddr = IntPtr.Zero;
            Console.WriteLine("[*] รอโปรแกรมโหลด/Unpack ใน memory...");
            for (int retry = 0; retry < 60; retry++)
            {
                Thread.Sleep(500);
                if (targetProc.HasExited) { Console.WriteLine("[!] โปรแกรมเป้าหมายถูกปิด"); return; }

                hProc = OpenProcess(PROCESS_ALL_ACCESS, false, targetProc.Id);
                if (hProc == IntPtr.Zero) continue;

                IntPtr[] mods = new IntPtr[1024];
                uint cbNeeded;
                if (EnumProcessModules(hProc, mods, (uint)(mods.Length * IntPtr.Size), out cbNeeded))
                {
                    int modCount = (int)(cbNeeded / IntPtr.Size);
                    for (int i = 0; i < modCount; i++)
                    {
                        StringBuilder sb = new StringBuilder(260);
                        GetModuleBaseName(hProc, mods[i], sb, (uint)sb.Capacity);
                        if (sb.ToString().Equals("deef.exe", StringComparison.OrdinalIgnoreCase))
                        {
                            baseAddr = mods[i];
                            break;
                        }
                    }
                }

                if (baseAddr != IntPtr.Zero)
                {
                    IntPtr testAddr = new IntPtr(baseAddr.ToInt64() + RVA_WRAPPER);
                    byte[] testBuf = new byte[8];
                    IntPtr read;
                    if (ReadProcessMemory(hProc, testAddr, testBuf, 8, out read) && read.ToInt32() == 8)
                    {
                        if (testBuf[0] == 0x40 && testBuf[1] == 0x53)
                        {
                            Console.WriteLine("[+] Unpack เสร็จ! Base: 0x" + baseAddr.ToString("X"));
                            break;
                        }
                    }
                }
                CloseHandle(hProc);
                hProc = IntPtr.Zero;
            }

            if (hProc == IntPtr.Zero || baseAddr == IntPtr.Zero)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("[!] หา Base Address ของ deef.exe ไม่เจอ (รันในฐานะ Admin แล้วหรือยัง?)");
                Console.ResetColor();
                Console.ReadKey();
                return;
            }

            long baseLong = baseAddr.ToInt64();
            long loginScreen = baseLong + RVA_LOGIN_SCREEN;
            long mainScreen  = baseLong + RVA_MAIN_SCREEN;
            long hookTarget  = baseLong + RVA_HOOK;

            // ---- backup original hook bytes ----
            byte[] origBytes = new byte[HOOK_LEN];
            IntPtr br;
            if (!ReadProcessMemory(hProc, new IntPtr(hookTarget), origBytes, HOOK_LEN, out br) || br.ToInt32() != HOOK_LEN)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("[!] อ่าน memory ตรงจุด hook ไม่ได้");
                Console.ResetColor();
                CloseHandle(hProc);
                return;
            }
            Console.WriteLine("[*] Original hook bytes: " + BitConverter.ToString(origBytes));
            // ถ้าเคย patch แล้ว (ขึ้นต้นด้วย 48 B8) ให้เตือน แต่ patch ทับได้
            if (origBytes[0] == 0x48 && origBytes[1] == 0xB8)
                Console.WriteLine("[!] ดูเหมือนเคย patch จุดนี้แล้ว — จะ patch ทับ");
            else
                File.WriteAllBytes(Path.Combine(currentDir, "hook_backup.bin"), origBytes);

            // ---- allocate RWX ----
            IntPtr mem = VirtualAllocEx(hProc, IntPtr.Zero, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (mem == IntPtr.Zero)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("[!] VirtualAllocEx ล้มเหลว err=" + Marshal.GetLastWin32Error());
                Console.ResetColor();
                CloseHandle(hProc);
                return;
            }
            long memLong = mem.ToInt64();
            long userStrAddr = memLong + LAYOUT_USER_STR;
            long keyStrAddr  = memLong + LAYOUT_KEY_STR;
            long expectAddr  = memLong + LAYOUT_EXPECT;
            long userLongAddr = memLong + LAYOUT_USER_LONG;
            long keyLongAddr  = memLong + LAYOUT_KEY_LONG;

            IntPtr written;
            // fake username std::string
            WriteStdString(hProc, userStrAddr, userLongAddr, username);
            // fake key std::string (auto mode)
            WriteStdString(hProc, keyStrAddr, keyLongAddr, key);

            byte[] expectedRaw = Encoding.ASCII.GetBytes(key.ToLowerInvariant());
            if (mode == "custom")
                WriteProcessMemory(hProc, new IntPtr(expectAddr), expectedRaw, expectedRaw.Length, out written);

            // ---- build shellcode ----
            byte[] shellcode;
            if (mode == "auto")
                shellcode = BuildAutoShellcode(mainScreen, userStrAddr, keyStrAddr);
            else if (mode == "custom")
                shellcode = BuildCustomShellcode(loginScreen, mainScreen, userStrAddr, expectAddr, expectedRaw.Length);
            else
                shellcode = BuildAnyShellcode(loginScreen, mainScreen, userStrAddr);

            Console.WriteLine("[*] Shellcode size: " + shellcode.Length + " bytes @ 0x" + memLong.ToString("X"));
            WriteProcessMemory(hProc, mem, shellcode, shellcode.Length, out written);

            // ---- install hook: mov rax, shellcode; call rax; nop; nop ----
            byte[] patch = new byte[HOOK_LEN];
            patch[0] = 0x48; patch[1] = 0xB8;
            Array.Copy(BitConverter.GetBytes(memLong), 0, patch, 2, 8);
            patch[10] = 0xFF; patch[11] = 0xD0;
            patch[12] = 0x90; patch[13] = 0x90;

            uint oldProtect;
            VirtualProtectEx(hProc, new IntPtr(hookTarget), (UIntPtr)patch.Length, PAGE_EXECUTE_READWRITE, out oldProtect);
            WriteProcessMemory(hProc, new IntPtr(hookTarget), patch, patch.Length, out written);
            VirtualProtectEx(hProc, new IntPtr(hookTarget), (UIntPtr)patch.Length, oldProtect, out oldProtect);

            // ---- verify ----
            byte[] verify = new byte[HOOK_LEN];
            ReadProcessMemory(hProc, new IntPtr(hookTarget), verify, HOOK_LEN, out br);
            bool ok = true;
            for (int i = 0; i < HOOK_LEN; i++) if (verify[i] != patch[i]) ok = false;

            CloseHandle(hProc);

            if (!ok)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("[!] Verify hook ล้มเหลว!");
                Console.ResetColor();
                return;
            }

            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine();
            Console.WriteLine("[OK] PATCH LOGIN KEY สำเร็จ!");
            if (mode == "any") Console.WriteLine("[OK] กรอก key อะไรก็ได้ (ห้ามว่าง) -> เข้าหน้าหลักทันที");
            else if (mode == "auto") Console.WriteLine("[OK] ข้ามหน้า login เข้าหน้าหลักอัตโนมัติ");
            else Console.WriteLine("[OK] ใช้ key \"" + key + "\" (ไม่สนพิมพ์เล็ก/ใหญ่) เพื่อเข้าใช้งาน");
            Console.ResetColor();
            Console.WriteLine();
            Console.WriteLine("Loader จะค้างเบื้องหลัง (กด Ctrl+C เพื่อปิด — patch ยังอยู่ใน deef จนปิดโปรแกรม)");
            while (true)
            {
                Thread.Sleep(1000);
                if (targetProc.HasExited) break;
            }
        }

        static void DoRestore()
        {
            string backup = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "hook_backup.bin");
            if (!File.Exists(backup)) { Console.WriteLine("[!] ไม่พบไฟล์ hook_backup.bin"); return; }
            byte[] orig = File.ReadAllBytes(backup);
            if (orig.Length != HOOK_LEN) { Console.WriteLine("[!] ไฟล์ backup ไม่ถูกต้อง"); return; }

            Process[] ps = Process.GetProcessesByName("deef");
            if (ps.Length == 0) { Console.WriteLine("[!] deef.exe ไม่ได้รันอยู่"); return; }
            Process targetProc = ps[0];

            IntPtr hProc = OpenProcess(PROCESS_ALL_ACCESS, false, targetProc.Id);
            if (hProc == IntPtr.Zero) { Console.WriteLine("[!] OpenProcess ล้มเหลว"); return; }

            IntPtr baseAddr = IntPtr.Zero;
            IntPtr[] mods = new IntPtr[1024];
            uint cbNeeded;
            if (EnumProcessModules(hProc, mods, (uint)(mods.Length * IntPtr.Size), out cbNeeded))
            {
                int modCount = (int)(cbNeeded / IntPtr.Size);
                for (int i = 0; i < modCount; i++)
                {
                    StringBuilder sb = new StringBuilder(260);
                    GetModuleBaseName(hProc, mods[i], sb, (uint)sb.Capacity);
                    if (sb.ToString().Equals("deef.exe", StringComparison.OrdinalIgnoreCase)) { baseAddr = mods[i]; break; }
                }
            }
            if (baseAddr == IntPtr.Zero) { Console.WriteLine("[!] หา base ไม่เจอ"); CloseHandle(hProc); return; }

            long hookTarget = baseAddr.ToInt64() + RVA_HOOK;
            uint oldProtect;
            IntPtr written;
            VirtualProtectEx(hProc, new IntPtr(hookTarget), (UIntPtr)HOOK_LEN, PAGE_EXECUTE_READWRITE, out oldProtect);
            WriteProcessMemory(hProc, new IntPtr(hookTarget), orig, orig.Length, out written);
            VirtualProtectEx(hProc, new IntPtr(hookTarget), (UIntPtr)HOOK_LEN, oldProtect, out oldProtect);
            CloseHandle(hProc);
            Console.WriteLine("[OK] คืนค่า hook เดิมเรียบร้อย");
        }

        // ================= shellcode builders =================

        // prologue: save regs, rbx = AppContext (rcx), rsi = typed key chars (SSO-aware)
        static void WritePrologue(BinaryWriter bw)
        {
            bw.Write((byte)0x53); // push rbx
            bw.Write((byte)0x56); // push rsi
            bw.Write((byte)0x57); // push rdi
            bw.Write(new byte[] { 0x41, 0x54 }); // push r12
            bw.Write(new byte[] { 0x49, 0x89, 0xE4 }); // mov r12, rsp
            bw.Write(new byte[] { 0x48, 0x83, 0xE4, 0xF0 }); // and rsp, -16 (ABI-safe inner calls)
            bw.Write(new byte[] { 0x48, 0x83, 0xEC, 0x20 }); // sub rsp, 0x20
            bw.Write(new byte[] { 0x48, 0x89, 0xCB });       // mov rbx, rcx
            bw.Write(new byte[] { 0x48, 0x8D, 0xB3, 0xB8, 0x01, 0x00, 0x00 }); // lea rsi, [rbx+0x1B8]
            bw.Write(new byte[] { 0x48, 0x83, 0xBB, 0xD0, 0x01, 0x00, 0x00, 0x0F }); // cmp [rbx+0x1D0], 15
            bw.Write(new byte[] { 0x76, 0x07 });             // jbe +7
            bw.Write(new byte[] { 0x48, 0x8B, 0xB3, 0xB8, 0x01, 0x00, 0x00 }); // mov rsi, [rbx+0x1B8]
        }

        static void WriteEpilogue(BinaryWriter bw)
        {
            bw.Write(new byte[] { 0x4C, 0x89, 0xE4 }); // mov rsp, r12 (restore exact entry Rsp)
            bw.Write(new byte[] { 0x41, 0x5C }); // pop r12
            bw.Write((byte)0x5F); // pop rdi
            bw.Write((byte)0x5E); // pop rsi
            bw.Write((byte)0x5B); // pop rbx
            bw.Write((byte)0xC3); // ret
        }

        static void WriteCallLogin(BinaryWriter bw, long loginScreen)
        {
            bw.Write(new byte[] { 0x48, 0x89, 0xD9 }); // mov rcx, rbx
            bw.Write((byte)0x48); bw.Write((byte)0xB8); bw.Write(loginScreen);
            bw.Write(new byte[] { 0xFF, 0xD0 }); // call rax
            WriteEpilogue(bw);
        }

        // main screen with pass-through: key = user's typed string, user = fake name
        static void WriteCallMainPass(BinaryWriter bw, long fakeUserAddr, long mainScreen)
        {
            bw.Write(new byte[] { 0x48, 0x89, 0xD9 }); // mov rcx, rbx
            bw.Write((byte)0x48); bw.Write((byte)0xBA); bw.Write(fakeUserAddr); // mov rdx, fakeUser
            bw.Write(new byte[] { 0x4C, 0x8D, 0x83, 0xB8, 0x01, 0x00, 0x00 }); // lea r8, [rbx+0x1B8]
            bw.Write(new byte[] { 0x41, 0xB9, 0x01, 0x00, 0x00, 0x00 }); // mov r9d, 1
            bw.Write((byte)0x48); bw.Write((byte)0xB8); bw.Write(mainScreen);
            bw.Write(new byte[] { 0xFF, 0xD0 }); // call rax
            WriteEpilogue(bw);
        }

        // main screen with fake key + fake user (auto mode)
        static void WriteCallMainFake(BinaryWriter bw, long fakeUserAddr, long fakeKeyAddr, long mainScreen)
        {
            bw.Write(new byte[] { 0x48, 0x89, 0xD9 }); // mov rcx, rbx
            bw.Write((byte)0x48); bw.Write((byte)0xBA); bw.Write(fakeUserAddr);
            bw.Write((byte)0x49); bw.Write((byte)0xB8); bw.Write(fakeKeyAddr); // mov r8, fakeKey
            bw.Write(new byte[] { 0x41, 0xB9, 0x01, 0x00, 0x00, 0x00 }); // mov r9d, 1
            bw.Write((byte)0x48); bw.Write((byte)0xB8); bw.Write(mainScreen);
            bw.Write(new byte[] { 0xFF, 0xD0 }); // call rax
            WriteEpilogue(bw);
        }

        // tolower(al): cmp al,'A'; jb +6; cmp al,'Z'; ja +2; or al,0x20
        static void WriteToLowerAL(BinaryWriter bw)
        {
            bw.Write(new byte[] { 0x3C, 0x41 });
            bw.Write(new byte[] { 0x72, 0x06 });
            bw.Write(new byte[] { 0x3C, 0x5A });
            bw.Write(new byte[] { 0x77, 0x02 });
            bw.Write(new byte[] { 0x0C, 0x20 });
        }

        static void WriteToLowerDL(BinaryWriter bw)
        {
            bw.Write(new byte[] { 0x80, 0xFA, 0x41 });
            bw.Write(new byte[] { 0x72, 0x06 });
            bw.Write(new byte[] { 0x80, 0xFA, 0x5A });
            bw.Write(new byte[] { 0x77, 0x02 });
            bw.Write(new byte[] { 0x80, 0xCA, 0x20 });
        }

        static byte[] BuildAnyShellcode(long loginScreen, long mainScreen, long fakeUserAddr)
        {
            MemoryStream ms = new MemoryStream();
            BinaryWriter bw = new BinaryWriter(ms);
            WritePrologue(bw);
            bw.Write(new byte[] { 0x48, 0x8B, 0xBB, 0xC8, 0x01, 0x00, 0x00 }); // mov rdi, [rbx+0x1C8] (typed len)
            bw.Write(new byte[] { 0x48, 0x85, 0xFF }); // test rdi, rdi
            long jzPos = ms.Position;
            bw.Write(new byte[] { 0x74, 0x00 }); // jz -> login
            long jmpMainPos = ms.Position;
            bw.Write(new byte[] { 0xEB, 0x00 }); // jmp -> main
            long loginPos = ms.Position;
            WriteCallLogin(bw, loginScreen);
            long mainPos = ms.Position;
            WriteCallMainPass(bw, fakeUserAddr, mainScreen);
            byte[] code = ms.ToArray();
            code[jzPos + 1] = (byte)(loginPos - (jzPos + 2));
            code[jmpMainPos + 1] = (byte)(mainPos - (jmpMainPos + 2));
            return code;
        }

        static byte[] BuildAutoShellcode(long mainScreen, long fakeUserAddr, long fakeKeyAddr)
        {
            MemoryStream ms = new MemoryStream();
            BinaryWriter bw = new BinaryWriter(ms);
            WritePrologue(bw);
            WriteCallMainFake(bw, fakeUserAddr, fakeKeyAddr, mainScreen);
            return ms.ToArray(); // fall-through straight to main
        }

        static byte[] BuildCustomShellcode(long loginScreen, long mainScreen, long fakeUserAddr, long expectAddr, int expectLen)
        {
            MemoryStream ms = new MemoryStream();
            BinaryWriter bw = new BinaryWriter(ms);
            WritePrologue(bw);
            bw.Write(new byte[] { 0x4C, 0x8B, 0x93, 0xC8, 0x01, 0x00, 0x00 }); // mov r10, [rbx+0x1C8]
            bw.Write((byte)0x49); bw.Write((byte)0xBB); bw.Write(expectAddr);  // mov r11, expectAddr
            bw.Write(new byte[] { 0x49, 0x81, 0xFA }); bw.Write(expectLen);    // cmp r10, expectLen
            long jne1Pos = ms.Position;
            bw.Write(new byte[] { 0x0F, 0x85, 0x00, 0x00, 0x00, 0x00 }); // jne -> login
            bw.Write(new byte[] { 0x31, 0xC9 }); // xor ecx, ecx (i = 0)
            long loopPos = ms.Position;
            bw.Write(new byte[] { 0x8A, 0x04, 0x0E }); // mov al, [rsi+rcx]
            WriteToLowerAL(bw);
            bw.Write(new byte[] { 0x41, 0x8A, 0x14, 0x0B }); // mov dl, [r11+rcx]
            WriteToLowerDL(bw);
            bw.Write(new byte[] { 0x38, 0xC2 }); // cmp dl, al
            long jne2Pos = ms.Position;
            bw.Write(new byte[] { 0x0F, 0x85, 0x00, 0x00, 0x00, 0x00 }); // jne -> login
            bw.Write(new byte[] { 0xFF, 0xC1 }); // inc ecx
            bw.Write(new byte[] { 0x44, 0x39, 0xD1 }); // cmp ecx, r10d
            long jbPos = ms.Position;
            bw.Write(new byte[] { 0x72, 0x00 }); // jb loop
            long jmpMainPos = ms.Position;
            bw.Write(new byte[] { 0xEB, 0x00 }); // jmp -> main
            long loginPos = ms.Position;
            WriteCallLogin(bw, loginScreen);
            long mainPos = ms.Position;
            WriteCallMainPass(bw, fakeUserAddr, mainScreen);

            byte[] code = ms.ToArray();
            Array.Copy(BitConverter.GetBytes((int)(loginPos - (jne1Pos + 6))), 0, code, (int)(jne1Pos + 2), 4);
            Array.Copy(BitConverter.GetBytes((int)(loginPos - (jne2Pos + 6))), 0, code, (int)(jne2Pos + 2), 4);
            code[jbPos + 1] = (byte)(loopPos - (jbPos + 2));
            code[jmpMainPos + 1] = (byte)(mainPos - (jmpMainPos + 2));
            return code;
        }

        // MSVC std::string (32 bytes): SSO if len<=15 else ptr/size/cap
        static void WriteStdString(IntPtr hProc, long structAddr, long charsAddr, string text)
        {
            byte[] chars = Encoding.ASCII.GetBytes(text);
            IntPtr written;
            byte[] st = new byte[32];
            if (chars.Length <= 15)
            {
                Array.Copy(chars, st, chars.Length);
                Array.Copy(BitConverter.GetBytes((ulong)chars.Length), 0, st, 16, 8);
                Array.Copy(BitConverter.GetBytes((ulong)15), 0, st, 24, 8);
            }
            else
            {
                byte[] buf = new byte[chars.Length + 1];
                Array.Copy(chars, buf, chars.Length);
                WriteProcessMemory(hProc, new IntPtr(charsAddr), buf, buf.Length, out written);
                Array.Copy(BitConverter.GetBytes((ulong)charsAddr), 0, st, 0, 8);
                Array.Copy(BitConverter.GetBytes((ulong)chars.Length), 0, st, 16, 8);
                Array.Copy(BitConverter.GetBytes((ulong)chars.Length), 0, st, 24, 8);
            }
            WriteProcessMemory(hProc, new IntPtr(structAddr), st, st.Length, out written);
        }
    }
}
