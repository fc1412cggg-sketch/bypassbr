using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace MadiumLoader
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
            Console.Title = "Madium Key Loader - FDRR Bypass";
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("=================================================");
            Console.WriteLine("        MADIUM KEY LOADER & AUTO-BYPASS         ");
            Console.WriteLine("=================================================");
            Console.ResetColor();

            string currentDir = AppDomain.CurrentDomain.BaseDirectory;
            string targetExe = Path.Combine(currentDir, "deef.exe");

            if (!File.Exists(targetExe))
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("[!] Error: deef.exe not found in " + currentDir);
                Console.ResetColor();
                Console.WriteLine("Press any key to exit...");
                Console.ReadKey();
                return;
            }

            Process targetProc = null;
            Process[] existing = Process.GetProcessesByName("deef");
            if (existing.Length > 0)
            {
                targetProc = existing[0];
                Console.WriteLine("[+] Found running deef.exe (PID: " + targetProc.Id + ")");
            }
            else
            {
                Console.WriteLine("[*] Launching deef.exe...");
                ProcessStartInfo psi = new ProcessStartInfo(targetExe);
                psi.WorkingDirectory = currentDir;
                psi.UseShellExecute = true;
                targetProc = Process.Start(psi);
                Console.WriteLine("[+] Launched deef.exe (PID: " + targetProc.Id + ")");
            }

            IntPtr hProc = IntPtr.Zero;
            IntPtr baseAddr = IntPtr.Zero;

            Console.WriteLine("[*] Waiting for process initialization and unpack...");
            for (int retry = 0; retry < 60; retry++)
            {
                Thread.Sleep(500);
                if (targetProc.HasExited)
                {
                    Console.WriteLine("[!] Process terminated.");
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
                    // Check if unpacked by reading login wrapper memory
                    IntPtr testAddr = new IntPtr(baseAddr.ToInt64() + 0x21a0b0);
                    byte[] testBuf = new byte[8];
                    IntPtr read;
                    if (ReadProcessMemory(hProc, testAddr, testBuf, 8, out read) && read.ToInt32() == 8)
                    {
                        if (testBuf[0] == 0x40 && testBuf[1] == 0x53) // push rbx
                        {
                            Console.WriteLine("[+] Process unpacked! Base address: 0x" + baseAddr.ToString("X"));
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
                Console.WriteLine("[!] Failed to obtain unpacked base address.");
                Console.ResetColor();
                return;
            }

            // Install Madium Hook
            long baseLong = baseAddr.ToInt64();
            long loginScreen = baseLong + 0x214370;
            long mainScreen  = baseLong + 0x2194b0;
            long hookTarget  = baseLong + 0x21a0b9;

            IntPtr shellcodeMem = VirtualAllocEx(hProc, IntPtr.Zero, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            long shellcodeLong = shellcodeMem.ToInt64();

            long str1Addr = shellcodeLong + 0x200;
            long str2Addr = shellcodeLong + 0x240;

            // Prepare std::string "Madium" and "Madium User"
            byte[] str1Bytes = new byte[32];
            byte[] keyChars = Encoding.ASCII.GetBytes("Madium");
            Array.Copy(keyChars, str1Bytes, keyChars.Length);
            Array.Copy(BitConverter.GetBytes((ulong)6), 0, str1Bytes, 16, 8);
            Array.Copy(BitConverter.GetBytes((ulong)15), 0, str1Bytes, 24, 8);

            byte[] str2Bytes = new byte[32];
            byte[] userChars = Encoding.ASCII.GetBytes("Madium User");
            Array.Copy(userChars, str2Bytes, userChars.Length);
            Array.Copy(BitConverter.GetBytes((ulong)11), 0, str2Bytes, 16, 8);
            Array.Copy(BitConverter.GetBytes((ulong)15), 0, str2Bytes, 24, 8);

            IntPtr written;
            WriteProcessMemory(hProc, new IntPtr(str1Addr), str1Bytes, str1Bytes.Length, out written);
            WriteProcessMemory(hProc, new IntPtr(str2Addr), str2Bytes, str2Bytes.Length, out written);

            // Construct shellcode
            MemoryStream ms = new MemoryStream();
            BinaryWriter bw = new BinaryWriter(ms);

            // Entry block
            bw.Write((byte)0x53); // push rbx
            bw.Write((byte)0x56); // push rsi
            bw.Write((byte)0x57); // push rdi
            bw.Write(new byte[] { 0x48, 0x83, 0xec, 0x20 }); // sub rsp, 0x20
            bw.Write(new byte[] { 0x48, 0x89, 0xcb }); // mov rbx, rcx
            bw.Write(new byte[] { 0x48, 0x8d, 0xb3, 0xb8, 0x01, 0x00, 0x00 }); // lea rsi, [rbx + 0x1b8]
            bw.Write(new byte[] { 0x48, 0x83, 0xbb, 0xd0, 0x01, 0x00, 0x00, 0x0f }); // cmp qword ptr [rbx + 0x1d0], 15
            bw.Write(new byte[] { 0x76, 0x07 }); // jbe +7
            bw.Write(new byte[] { 0x48, 0x8b, 0xb3, 0xb8, 0x01, 0x00, 0x00 }); // mov rsi, qword ptr [rbx + 0x1b8]
            bw.Write(new byte[] { 0x48, 0x83, 0xbb, 0xc8, 0x01, 0x00, 0x00, 0x06 }); // cmp qword ptr [rbx + 0x1c8], 6

            long jbLoginPos = ms.Position;
            bw.Write(new byte[] { 0x72, 0x00 }); // jb call_login

            // Check "Madium"
            bw.Write(new byte[] { 0x48, 0x8b, 0x06 }); // mov rax, [rsi]
            bw.Write(new byte[] { 0x48, 0xba, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00 }); // mov rdx, 0xffffffffffff
            bw.Write(new byte[] { 0x48, 0x21, 0xd0 }); // and rax, rdx
            bw.Write(new byte[] { 0x48, 0xba, 0x4d, 0x61, 0x64, 0x69, 0x75, 0x6d, 0x00, 0x00 }); // mov rdx, "Madium"
            bw.Write(new byte[] { 0x48, 0x39, 0xd0 }); // cmp rax, rdx
            long jeMain1Pos = ms.Position;
            bw.Write(new byte[] { 0x74, 0x00 }); // je call_main

            // Check "madium"
            bw.Write(new byte[] { 0x48, 0xba, 0x6d, 0x61, 0x64, 0x69, 0x75, 0x6d, 0x00, 0x00 }); // mov rdx, "madium"
            bw.Write(new byte[] { 0x48, 0x39, 0xd0 }); // cmp rax, rdx
            long jeMain2Pos = ms.Position;
            bw.Write(new byte[] { 0x74, 0x00 }); // je call_main

            // Call login block
            long loginBlockPos = ms.Position;
            bw.Write(new byte[] { 0x48, 0x89, 0xd9 }); // mov rcx, rbx
            bw.Write((byte)0x48); bw.Write((byte)0xb8); bw.Write(loginScreen); // mov rax, loginScreen
            bw.Write(new byte[] { 0xff, 0xd0 }); // call rax
            bw.Write(new byte[] { 0x48, 0x83, 0xc4, 0x20 }); // add rsp, 0x20
            bw.Write((byte)0x5f); // pop rdi
            bw.Write((byte)0x5e); // pop rsi
            bw.Write((byte)0x5b); // pop rbx
            bw.Write((byte)0xc3); // ret

            // Call main block
            long mainBlockPos = ms.Position;
            bw.Write(new byte[] { 0x48, 0x89, 0xd9 }); // mov rcx, rbx
            bw.Write(new byte[] { 0x48, 0xba }); bw.Write(str2Addr); // mov rdx, str2Addr
            bw.Write(new byte[] { 0x49, 0xb8 }); bw.Write(str1Addr); // mov r8, str1Addr
            bw.Write(new byte[] { 0x41, 0xb9, 0x01, 0x00, 0x00, 0x00 }); // mov r9d, 1
            bw.Write((byte)0x48); bw.Write((byte)0xb8); bw.Write(mainScreen); // mov rax, mainScreen
            bw.Write(new byte[] { 0xff, 0xd0 }); // call rax
            bw.Write(new byte[] { 0x48, 0x83, 0xc4, 0x20 }); // add rsp, 0x20
            bw.Write((byte)0x5f); // pop rdi
            bw.Write((byte)0x5e); // pop rsi
            bw.Write((byte)0x5b); // pop rbx
            bw.Write((byte)0xc3); // ret

            byte[] shellcode = ms.ToArray();
            shellcode[jbLoginPos + 1] = (byte)(loginBlockPos - (jbLoginPos + 2));
            shellcode[jeMain1Pos + 1] = (byte)(mainBlockPos - (jeMain1Pos + 2));
            shellcode[jeMain2Pos + 1] = (byte)(mainBlockPos - (jeMain2Pos + 2));

            // Write shellcode
            WriteProcessMemory(hProc, shellcodeMem, shellcode, shellcode.Length, out written);

            // Patch hook target
            byte[] patch = new byte[14];
            patch[0] = 0x48; patch[1] = 0xb8;
            Array.Copy(BitConverter.GetBytes(shellcodeLong), 0, patch, 2, 8);
            patch[10] = 0xff; patch[11] = 0xd0; // call rax
            patch[12] = 0x90; patch[13] = 0x90; // nops

            uint oldProtect;
            VirtualProtectEx(hProc, new IntPtr(hookTarget), (UIntPtr)patch.Length, PAGE_EXECUTE_READWRITE, out oldProtect);
            WriteProcessMemory(hProc, new IntPtr(hookTarget), patch, patch.Length, out written);
            VirtualProtectEx(hProc, new IntPtr(hookTarget), (UIntPtr)patch.Length, oldProtect, out oldProtect);

            CloseHandle(hProc);

            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("\n[✓] MADIUM KEY BYPASS ACTIVATED SUCCESSFULLY!");
            Console.WriteLine("[*] You can now enter the key 'Madium' to instantly access the main menu!");
            Console.ResetColor();
            Console.WriteLine("\nKeeping loader active in background. Press Ctrl+C to close.");
            
            while (true)
            {
                Thread.Sleep(1000);
                if (targetProc.HasExited) break;
            }
        }
    }
}
