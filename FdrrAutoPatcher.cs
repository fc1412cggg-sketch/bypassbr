using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace FdrrAutoPatcher
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

        static void Main(string[] args)
        {
            Console.Title = "FDRR / Deef - Direct Main Screen Patcher & Loader";
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("================================================================");
            Console.WriteLine("        FDRR (DEEF) AUTO-PATCHER - DIRECT MAIN SCREEN           ");
            Console.WriteLine("        ปลดล็อคและเข้าสู่หน้าใช้งานหลักโดยตรง (Direct Main UI)     ");
            Console.WriteLine("================================================================");
            Console.ResetColor();

            string currentDir = AppDomain.CurrentDomain.BaseDirectory;
            string targetExe = Path.Combine(currentDir, "deef.exe");

            if (!File.Exists(targetExe))
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("[!] Error: ไม่พบไฟล์ deef.exe ใน " + currentDir);
                Console.ResetColor();
                Console.WriteLine("กดปุ่มใดๆ เพื่อออกจากโปรแกรม...");
                Console.ReadKey();
                return;
            }

            Process targetProc = null;
            Process[] existing = Process.GetProcessesByName("deef");
            if (existing.Length > 0)
            {
                targetProc = existing[0];
                Console.WriteLine("[+] พบ deef.exe ที่กำลังทำงานอยู่ (PID: " + targetProc.Id + ")");
            }
            else
            {
                Console.WriteLine("[*] กำลังเปิดโปรแกรม deef.exe...");
                ProcessStartInfo psi = new ProcessStartInfo(targetExe)
                {
                    WorkingDirectory = currentDir,
                    UseShellExecute = true
                };
                targetProc = Process.Start(psi);
                Console.WriteLine("[+] เปิด deef.exe สำเร็จ (PID: " + targetProc.Id + ")");
            }

            IntPtr hProc = IntPtr.Zero;
            IntPtr baseAddr = IntPtr.Zero;

            Console.WriteLine("[*] กำลังรอให้โปรแกรมโหลดและ Unpack ใน Memory...");
            for (int retry = 0; retry < 60; retry++)
            {
                Thread.Sleep(500);
                if (targetProc.HasExited)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("[!] โปรแกรมเป้าหมายถูกปิด");
                    Console.ResetColor();
                    return;
                }

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
                    // ตรวจสอบความพร้อมของ RVA 0x21a0b0
                    IntPtr testAddr = new IntPtr(baseAddr.ToInt64() + 0x21a0b0);
                    byte[] testBuf = new byte[8];
                    IntPtr read;
                    if (ReadProcessMemory(hProc, testAddr, testBuf, 8, out read) && read.ToInt32() == 8)
                    {
                        if (testBuf[0] == 0x40 && testBuf[1] == 0x53) // push rbx
                        {
                            Console.WriteLine("[+] Unpack เสร็จสมบูรณ์! Base Address: 0x" + baseAddr.ToString("X"));
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
                Console.WriteLine("[!] ไม่สามารถค้นหา Base Address ของ deef.exe ได้");
                Console.ResetColor();
                return;
            }

            long baseLong = baseAddr.ToInt64();
            long mainScreenAddr = baseLong + 0x2194b0;
            long hookTargetAddr = baseLong + 0x21a0b9;

            // จัดสรร Memory สำหรับ Shellcode & Strings
            IntPtr shellcodeMem = VirtualAllocEx(hProc, IntPtr.Zero, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            long shellcodeLong = shellcodeMem.ToInt64();

            long strKeyAddr = shellcodeLong + 0x200;
            long strUserAddr = shellcodeLong + 0x240;

            // เตรียม std::string สำหรับ Key และ Username
            byte[] strKeyBytes = new byte[32];
            byte[] keyChars = Encoding.ASCII.GetBytes("VIP-PREMIUM");
            Array.Copy(keyChars, strKeyBytes, keyChars.Length);
            Array.Copy(BitConverter.GetBytes((ulong)keyChars.Length), 0, strKeyBytes, 16, 8);
            Array.Copy(BitConverter.GetBytes((ulong)15), 0, strKeyBytes, 24, 8);

            byte[] strUserBytes = new byte[32];
            byte[] userChars = Encoding.ASCII.GetBytes("VIP Administrator");
            Array.Copy(userChars, strUserBytes, userChars.Length);
            Array.Copy(BitConverter.GetBytes((ulong)userChars.Length), 0, strUserBytes, 16, 8);
            Array.Copy(BitConverter.GetBytes((ulong)15), 0, strUserBytes, 24, 8);

            IntPtr written;
            WriteProcessMemory(hProc, new IntPtr(strKeyAddr), strKeyBytes, strKeyBytes.Length, out written);
            WriteProcessMemory(hProc, new IntPtr(strUserAddr), strUserBytes, strUserBytes.Length, out written);

            // สร้าง Shellcode:
            // เรียก mainScreen(rcx = AppContext, rdx = strUser, r8 = strKey, r9d = 1) โดยตรง
            MemoryStream ms = new MemoryStream();
            BinaryWriter bw = new BinaryWriter(ms);

            bw.Write(new byte[] { 0x48, 0x89, 0xd9 }); // mov rcx, rbx (App Instance)
            bw.Write(new byte[] { 0x48, 0xba }); bw.Write(strUserAddr); // mov rdx, strUserAddr ("VIP Administrator")
            bw.Write(new byte[] { 0x49, 0xb8 }); bw.Write(strKeyAddr);  // mov r8, strKeyAddr ("VIP-PREMIUM")
            bw.Write(new byte[] { 0x41, 0xb9, 0x01, 0x00, 0x00, 0x00 }); // mov r9d, 1 (Authenticated/VIP Status)
            bw.Write((byte)0x48); bw.Write((byte)0xb8); bw.Write(mainScreenAddr); // mov rax, mainScreenAddr (0x2194b0)
            bw.Write(new byte[] { 0xff, 0xd0 }); // call rax
            bw.Write(new byte[] { 0x48, 0x83, 0xc4, 0x20 }); // add rsp, 0x20
            bw.Write((byte)0x5b); // pop rbx
            bw.Write((byte)0xc3); // ret

            byte[] shellcode = ms.ToArray();
            WriteProcessMemory(hProc, shellcodeMem, shellcode, shellcode.Length, out written);

            // ทำการ Patch ที่ RVA 0x21a0b9 (จุดเรียก Screen Router เดิม) ให้กระโดดมาที่ Shellcode ของเรา
            byte[] hookPatch = new byte[14];
            hookPatch[0] = 0x48; hookPatch[1] = 0xb8; // mov rax, shellcodeLong
            Array.Copy(BitConverter.GetBytes(shellcodeLong), 0, hookPatch, 2, 8);
            hookPatch[10] = 0xff; hookPatch[11] = 0xe0; // jmp rax
            hookPatch[12] = 0x90; hookPatch[13] = 0x90; // nop nop

            uint oldProtect;
            VirtualProtectEx(hProc, new IntPtr(hookTargetAddr), (UIntPtr)hookPatch.Length, PAGE_EXECUTE_READWRITE, out oldProtect);
            WriteProcessMemory(hProc, new IntPtr(hookTargetAddr), hookPatch, hookPatch.Length, out written);
            VirtualProtectEx(hProc, new IntPtr(hookTargetAddr), (UIntPtr)hookPatch.Length, oldProtect, out oldProtect);

            CloseHandle(hProc);

            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine();
            Console.WriteLine("[✓] ========================================================");
            Console.WriteLine("[✓]  PATCH เข้าหน้าใช้งานหลัก (MAIN SCREEN) สำเร็จเรียบร้อย!");
            Console.WriteLine("[✓]  โปรแกรมจะเข้าสู่หน้าเมนูและฟังก์ชันหลักโดยตรงอัตโนมัติ");
            Console.WriteLine("[✓] ========================================================");
            Console.ResetColor();

            Console.WriteLine("\nตัว Loader จะทำงานเบื้องหลังเพื่อคอยควบคุม (กด Ctrl+C เพื่อปิด)");
            while (true)
            {
                Thread.Sleep(1000);
                if (targetProc.HasExited) break;
            }
        }
    }
}
