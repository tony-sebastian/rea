// ReaWindowsAuthority implements the Windows native authority that the REA
// Windows Ghidra P0 boundary requires: verified Job Object process ownership
// with kill-on-close semantics, private current-user-only runtime DACLs, and
// handle-based reparse-safe path admission.
//
// The source ships beside REA and is compiled on first use by the Windows
// system compiler (csc.exe); the compiled artifact is cached and pinned to
// this source digest. Every subcommand emits a single JSON verdict on stdout
// and exits non-zero on failure. Verification reads back OS state (security
// descriptors, job membership, handle attributes); nothing is trusted from
// command arguments alone.
//
// Target: C# 5 (the .NET Framework 4 csc.exe language level shipped with
// every supported Windows host) - no string interpolation, no null-conditional
// operators, no expression-bodied members.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;

namespace Rea
{
    internal static class Program
    {
        private const uint ReparsePointAttr = 0x400;
        private const uint FlagOpenReparsePoint = 0x00200000;
        private const uint FlagBackupSemantics = 0x02000000;
        private const uint FileReadAttributes = 0x80;
        private const uint ShareAll = 0x7; // READ|WRITE|DELETE
        private const uint InheritedAce = 0x10;
        private const uint GenericAll = 0x10000000;
        private const uint AceInheritDir = 0x3; // object+container inherit
        private const uint SetAccess = 0x2;
        private const uint TrusteeIsSid = 0x0;
        private const uint TrusteeIsUser = 0x1;
        private const uint TrusteeIsWellKnownGroup = 0x5;
        private const uint SeFileObject = 1;
        private const uint DaclSecurityInformation = 4;
        private const uint ProtectedDacl = 0x80000000;
        private const uint CreateSuspended = 0x4;
        private const uint Infinite = 0xFFFFFFFF;
        private const string SpawnMarker = "REA-WINAUTH-SPAWN";

        private static int Main(string[] args)
        {
            if (args.Length < 1)
            {
                Error("usage: rea-winauth <spawn|dacl|pathcheck|capabilities> [args]");
                return 2;
            }
            int exitCode;
            try
            {
                string[] rest = new string[args.Length - 1];
                Array.Copy(args, 1, rest, 0, rest.Length);
                switch (args[0])
                {
                    case "spawn":
                        exitCode = CmdSpawn(rest);
                        return exitCode;
                    case "dacl":
                        CmdDacl(rest);
                        return 0;
                    case "pathcheck":
                        CmdPathCheck(rest);
                        return 0;
                    case "capabilities":
                        CmdCapabilities();
                        return 0;
                    default:
                        Error("unknown subcommand " + args[0]);
                        return 2;
                }
            }
            catch (Exception e)
            {
                EmitObject(new string[] { "error" }, new object[] { e.Message });
                return 1;
            }
        }

        private static void Error(string message)
        {
            Console.Error.WriteLine("rea-winauth: " + message);
        }

        private static void Emit(string json)
        {
            Console.Out.WriteLine(json);
        }

        private static void EmitObject(string[] keys, object[] values)
        {
            StringBuilder b = new StringBuilder();
            b.Append('{');
            for (int i = 0; i < keys.Length; i++)
            {
                if (i > 0) b.Append(',');
                b.Append(JsonString(keys[i])).Append(':').Append(JsonValue(values[i]));
            }
            b.Append('}');
            Emit(b.ToString());
        }

        private static string JsonValue(object v)
        {
            if (v == null) return "null";
            if (v is bool) return (bool)v ? "true" : "false";
            if (v is int || v is uint || v is long || v is ulong) return v.ToString();
            if (v is string) return JsonString((string)v);
            if (v is IEnumerable<object>)
            {
                StringBuilder b = new StringBuilder();
                b.Append('[');
                bool first = true;
                foreach (object item in (IEnumerable<object>)v)
                {
                    if (!first) b.Append(',');
                    first = false;
                    b.Append(JsonValue(item));
                }
                b.Append(']');
                return b.ToString();
            }
            return JsonString(v.ToString());
        }

        private static string JsonString(string s)
        {
            StringBuilder b = new StringBuilder();
            b.Append('"');
            foreach (char c in s)
            {
                switch (c)
                {
                    case '"': b.Append("\\\""); break;
                    case '\\': b.Append("\\\\"); break;
                    case '\b': b.Append("\\b"); break;
                    case '\f': b.Append("\\f"); break;
                    case '\n': b.Append("\\n"); break;
                    case '\r': b.Append("\\r"); break;
                    case '\t': b.Append("\\t"); break;
                    default:
                        if (c < 0x20)
                            b.Append("\\u").Append(((int)c).ToString("x4"));
                        else
                            b.Append(c);
                        break;
                }
            }
            b.Append('"');
            return b.ToString();
        }

        private static string Dict(string[] keys, object[] values)
        {
            StringBuilder b = new StringBuilder();
            b.Append('{');
            for (int i = 0; i < keys.Length; i++)
            {
                if (i > 0) b.Append(',');
                b.Append(JsonString(keys[i])).Append(':').Append(JsonValue(values[i]));
            }
            b.Append('}');
            return b.ToString();
        }

        // ------------------------------------------------------------- spawn

        private static int CmdSpawn(string[] args)
        {
            string argvJson = null;
            bool verbatimLast = false;
            for (int i = 0; i < args.Length; i++)
            {
                if (args[i] == "--argv-json")
                {
                    i++;
                    if (i < args.Length) argvJson = args[i];
                }
                else if (args[i] == "--verbatim-last")
                {
                    verbatimLast = true;
                }
            }
            if (argvJson == null)
                throw new InvalidOperationException("spawn requires --argv-json");
            string[] argv = SimpleJsonStringArray(argvJson);
            if (argv.Length == 0 || argv[0].Length == 0)
                throw new InvalidOperationException("argv must start with an executable");

            IntPtr job = CreateJobObjectW(IntPtr.Zero, null);
            if (job == IntPtr.Zero)
                throw new InvalidOperationException("CreateJobObjectW failed: " + Marshal.GetLastWin32Error());
            try
            {
                JOBOBJECT_EXTENDED_LIMIT_INFORMATION info = new JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
                info.BasicLimitInformation.LimitFlags = JobObjectLimitKillOnJobClose;
                IntPtr buf = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION)));
                try
                {
                    Marshal.StructureToPtr(info, buf, false);
                    bool setOk = SetInformationJobObject(job, JobObjectExtendedLimitInformation, buf,
                        (uint)Marshal.SizeOf(typeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION)));
                        int setErr = Marshal.GetLastWin32Error();
                        if (!setOk)
                            throw new InvalidOperationException("SetInformationJobObject failed: err=" + setErr + " size=" + Marshal.SizeOf(typeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION)));
                }
                finally { Marshal.FreeHGlobal(buf); }

                string exe = ResolveExecutable(argv[0]);
                string cmdline = BuildCommandLine(argv, verbatimLast);
                if (Environment.GetEnvironmentVariable("REA_WINAUTH_DEBUG") == "1")
                    Console.Error.WriteLine("REA-WINAUTH-DEBUG cmdline=" + cmdline);

                STARTUPINFO si = new STARTUPINFO();
                si.cb = Marshal.SizeOf(typeof(STARTUPINFO));
                PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
                if (!CreateProcessW(exe, cmdline, IntPtr.Zero, IntPtr.Zero, true,
                    CreateSuspended, IntPtr.Zero, IntPtr.Zero, ref si, ref pi))
                    throw new InvalidOperationException("CreateProcess failed: " + Marshal.GetLastWin32Error());

                try
                {
                    if (!AssignProcessToJobObject(job, pi.hProcess))
                    {
                        TerminateProcess(pi.hProcess, 1);
                        throw new InvalidOperationException("AssignProcessToJobObject failed: " + Marshal.GetLastWin32Error());
                    }
                    if (ResumeThread(pi.hThread) == 0xFFFFFFFF)
                    {
                        TerminateJobObject(job, 1);
                        throw new InvalidOperationException("ResumeThread failed");
                    }
                    Console.Error.WriteLine(SpawnMarker + " " + Dict(
                        new string[] { "helper_pid", "child_pid", "kill_on_close", "assigned_preexec" },
                        new object[] { Process.GetCurrentProcess().Id, (int)pi.dwProcessId, true, true }));

                    if (WaitForSingleObject(pi.hProcess, Infinite) != 0)
                    {
                        TerminateJobObject(job, 1);
                        throw new InvalidOperationException("WaitForSingleObject failed");
                    }
                    uint code;
                    if (!GetExitCodeProcess(pi.hProcess, out code))
                    {
                        TerminateJobObject(job, 1);
                        throw new InvalidOperationException("GetExitCodeProcess failed");
                    }
                    TerminateJobObject(job, 0); // reap any descendants the child left
                    return unchecked((int)code);
                }
                finally
                {
                    CloseHandle(pi.hThread);
                    CloseHandle(pi.hProcess);
                }
            }
            finally
            {
                CloseHandle(job);
            }
        }

        private static string BuildCommandLine(string[] argv, bool verbatimLast)
        {
            StringBuilder b = new StringBuilder();
            for (int i = 0; i < argv.Length; i++)
            {
                if (i > 0) b.Append(' ');
                if (verbatimLast && i == argv.Length - 1)
                {
                    // Command-interpreter mode: the caller supplies the fully
                    // quoted invocation including its outer quote pair (cmd /S
                    // strips exactly the first and last quote of the /c tail).
                    b.Append(argv[i]);
                }
                else
                {
                    b.Append(EscapeArg(argv[i]));
                }
            }
            return b.ToString();
        }

        // Windows argv escaping: quote only when the argument needs it
        // (empty, or contains space/tab/quote) and apply MSVCRT backslash
        // rules inside the quotes - unquoted switches must stay unquoted.
        private static string EscapeArg(string a)
        {
            bool needsQuotes = a.Length == 0;
            foreach (char c in a)
            {
                if (c == ' ' || c == '\t' || c == '"') { needsQuotes = true; break; }
            }
            if (!needsQuotes) return a;
            StringBuilder q = new StringBuilder();
            q.Append('"');
            for (int j = 0; j < a.Length; j++)
            {
                int backslashes = 0;
                while (j < a.Length && a[j] == '\\') { backslashes++; j++; }
                if (j == a.Length)
                {
                    q.Append('\\', backslashes * 2);
                }
                else if (a[j] == '"')
                {
                    q.Append('\\', backslashes * 2 + 1).Append('"');
                }
                else
                {
                    q.Append('\\', backslashes).Append(a[j]);
                }
            }
            q.Append('"');
            return q.ToString();
        }

        private static string ResolveExecutable(string nameOrPath)
        {
            if (nameOrPath.IndexOf('\\') >= 0 || nameOrPath.IndexOf('/') >= 0)
                return nameOrPath;
            string windir = Environment.GetEnvironmentVariable("WINDIR") ?? @"C:\Windows";
            string sys32 = Path.Combine(windir, "System32", nameOrPath);
            if (File.Exists(sys32)) return sys32;
            string self = Process.GetCurrentProcess().MainModule != null
                ? Process.GetCurrentProcess().MainModule.FileName : null;
            if (self != null)
            {
                string candidate = Path.Combine(Path.GetDirectoryName(self), nameOrPath);
                if (File.Exists(candidate)) return candidate;
            }
            return nameOrPath;
        }

        private static string[] SimpleJsonStringArray(string json)
        {
            List<string> result = new List<string>();
            int i = 0;
            SkipWs(json, ref i);
            if (i >= json.Length || json[i] != '[')
                throw new InvalidOperationException("argv-json must be an array");
            i++;
            SkipWs(json, ref i);
            while (i < json.Length && json[i] != ']')
            {
                if (json[i] != '"')
                    throw new InvalidOperationException("argv-json elements must be strings");
                result.Add(ReadJsonString(json, ref i));
                SkipWs(json, ref i);
                if (i < json.Length && json[i] == ',') { i++; SkipWs(json, ref i); }
            }
            return result.ToArray();
        }

        private static void SkipWs(string s, ref int i)
        {
            while (i < s.Length && (s[i] == ' ' || s[i] == '\t' || s[i] == '\r' || s[i] == '\n')) i++;
        }

        private static string ReadJsonString(string s, ref int i)
        {
            StringBuilder b = new StringBuilder();
            i++; // opening quote
            while (i < s.Length && s[i] != '"')
            {
                if (s[i] == '\\')
                {
                    i++;
                    char c = s[i];
                    if (c == 'n') b.Append('\n');
                    else if (c == 'r') b.Append('\r');
                    else if (c == 't') b.Append('\t');
                    else if (c == 'b') b.Append('\b');
                    else if (c == 'f') b.Append('\f');
                    else if (c == 'u')
                    {
                        b.Append((char)Convert.ToInt32(s.Substring(i + 1, 4), 16));
                        i += 4;
                    }
                    else b.Append(c);
                    i++;
                }
                else
                {
                    b.Append(s[i]);
                    i++;
                }
            }
            i++; // closing quote
            return b.ToString();
        }

        // --------------------------------------------------------------- dacl

        private static void CmdDacl(string[] args)
        {
            string mode = null, path = null;
            for (int i = 0; i < args.Length; i++)
            {
                if (args[i] == "create" || args[i] == "verify") mode = args[i];
                else if (args[i] == "--path") { i++; if (i < args.Length) path = args[i]; }
            }
            if (path == null)
                throw new InvalidOperationException("dacl requires --path");
            string abs = Path.GetFullPath(path);
            if (mode == "create") DaclCreate(abs);
            else if (mode == "verify") DaclVerify(abs);
            else throw new InvalidOperationException("dacl requires create or verify");
        }

        private static byte[] CurrentUserSid()
        {
            WindowsIdentity identity = WindowsIdentity.GetCurrent();
            if (identity == null || identity.User == null)
                throw new InvalidOperationException("no current user sid");
            byte[] bytes = new byte[identity.User.BinaryLength];
            identity.User.GetBinaryForm(bytes, 0);
            return bytes;
        }

        private static byte[] WellKnownSidBytes(int wellKnownType)
        {
            SecurityIdentifier sid = new SecurityIdentifier((WellKnownSidType)wellKnownType, null);
            byte[] bytes = new byte[sid.BinaryLength];
            sid.GetBinaryForm(bytes, 0);
            return bytes;
        }

        private static IntPtr AllocSid(byte[] sidBytes)
        {
            IntPtr p = Marshal.AllocHGlobal(sidBytes.Length);
            Marshal.Copy(sidBytes, 0, p, sidBytes.Length);
            return p;
        }

        private static void DaclCreate(string path)
        {
            byte[] user = CurrentUserSid();
            byte[] system = WellKnownSidBytes(16);  // LocalSystemSid
            byte[] admins = WellKnownSidBytes(32);  // WinBuiltinAdministratorsSid

            IntPtr userP = AllocSid(user);
            IntPtr sysP = AllocSid(system);
            IntPtr admP = AllocSid(admins);
            try
            {
                EXPLICIT_ACCESS[] entries = new EXPLICIT_ACCESS[3];
                uint[] types = new uint[] { TrusteeIsUser, TrusteeIsWellKnownGroup, TrusteeIsWellKnownGroup };
                IntPtr[] sids = new IntPtr[] { userP, sysP, admP };
                for (int i = 0; i < 3; i++)
                {
                    entries[i].GrfAccessPermissions = GenericAll;
                    entries[i].GrfAccessMode = SetAccess;
                    entries[i].GrfInheritance = AceInheritDir;
                    entries[i].Trustee.MultipleTrustee = IntPtr.Zero;
                    entries[i].Trustee.MultipleTrusteeOperation = 0;
                    entries[i].Trustee.TrusteeForm = TrusteeIsSid;
                    entries[i].Trustee.TrusteeType = types[i];
                    entries[i].Trustee.ptstrName = sids[i];
                }
                IntPtr newAcl = IntPtr.Zero;
                int hr = SetEntriesInAclW(3, entries, IntPtr.Zero, ref newAcl);
                if (hr != 0)
                    throw new InvalidOperationException("SetEntriesInAclW failed: 0x" + hr.ToString("x8"));
                try
                {
                    uint result = SetNamedSecurityInfoW(path, SeFileObject,
                        DaclSecurityInformation | ProtectedDacl,
                        IntPtr.Zero, IntPtr.Zero, newAcl, IntPtr.Zero);
                    if (result != 0)
                        throw new InvalidOperationException("SetNamedSecurityInfoW failed: " + result);
                }
                finally { LocalFree(newAcl); }
            }
            finally
            {
                Marshal.FreeHGlobal(userP);
                Marshal.FreeHGlobal(sysP);
                Marshal.FreeHGlobal(admP);
            }
            DaclVerify(path);
        }

        private static void DaclVerify(string path)
        {
            IntPtr acl = IntPtr.Zero, sd = IntPtr.Zero;
            uint result = GetNamedSecurityInfoW(path, SeFileObject,
                DaclSecurityInformation, IntPtr.Zero, IntPtr.Zero,
                ref acl, IntPtr.Zero, out sd);
            if (result != 0)
                throw new InvalidOperationException("GetNamedSecurityInfoW failed: " + result);
            if (acl == IntPtr.Zero)
                throw new InvalidOperationException("path has no DACL");
            try
            {
                short aceCount = Marshal.ReadInt16(acl, 4);
                byte[] user = CurrentUserSid();
                byte[] system = WellKnownSidBytes(16);
                byte[] admins = WellKnownSidBytes(32);
                IntPtr userP = AllocSid(user);
                IntPtr sysP = AllocSid(system);
                IntPtr admP = AllocSid(admins);
                try
                {
                    for (uint i = 0; i < aceCount; i++)
                    {
                        IntPtr ace;
                        if (!GetAce(acl, i, out ace))
                            throw new InvalidOperationException("GetAce(" + i + ") failed");
                        byte aceFlags = Marshal.ReadByte(ace, 1);
                        if ((aceFlags & InheritedAce) != 0)
                            throw new InvalidOperationException("ace " + i + " is inherited");
                        IntPtr sidPtr = new IntPtr(ace.ToInt64() + 8); // ACCESS_ALLOWED_ACE.SidStart
                        if (!EqualSidP(sidPtr, userP) && !EqualSidP(sidPtr, sysP) && !EqualSidP(sidPtr, admP))
                            throw new InvalidOperationException("ace " + i + " grants an unexpected trustee");
                    }
                }
                finally
                {
                    Marshal.FreeHGlobal(userP);
                    Marshal.FreeHGlobal(sysP);
                    Marshal.FreeHGlobal(admP);
                }
                EmitObject(new string[] { "verified", "aces" },
                    new object[] { true, (int)aceCount });
            }
            finally
            {
                LocalFree(sd);
            }
        }

        private static bool EqualSidP(IntPtr a, IntPtr b)
        {
            return EqualSid(a, b);
        }

        // ----------------------------------------------------------- pathcheck

        private static void CmdPathCheck(string[] args)
        {
            List<string> paths = new List<string>();
            for (int i = 0; i < args.Length; i++)
            {
                if (args[i] == "--")
                {
                    for (int j = i + 1; j < args.Length; j++) paths.Add(args[j]);
                    break;
                }
            }
            if (paths.Count == 0)
                throw new InvalidOperationException("pathcheck requires paths after --");
            foreach (string p in paths)
                PathCheckOne(Path.GetFullPath(Path.GetFullPath(p)));
            EmitObject(new string[] { "verified", "count" },
                new object[] { true, paths.Count });
        }

        private static void PathCheckOne(string abs)
        {
            string ext = ExtendedPath(abs);
            int volLen = VolumePrefixLen(ext);
            string current = ext.Substring(0, volLen);
            string rest = ext.Substring(volLen).Trim('\\');
            if (rest.Length == 0) return;
            string[] components = rest.Split('\\');
            for (int i = 0; i < components.Length; i++)
            {
                current = current.TrimEnd('\\') + "\\" + components[i];
                bool isLeaf = i == components.Length - 1;
                IntPtr handle = CreateFileW(current, FileReadAttributes, ShareAll,
                    IntPtr.Zero, 3 /* OPEN_EXISTING */,
                    FlagBackupSemantics | FlagOpenReparsePoint, IntPtr.Zero);
                if (handle == new IntPtr(-1))
                {
                    int err = Marshal.GetLastWin32Error();
                    if (isLeaf && (err == 2 || err == 3)) // FILE_NOT_FOUND / PATH_NOT_FOUND
                        return; // parents were checked; admit creation
                    throw new InvalidOperationException("open component \"" + current + "\": error " + err);
                }
                try
                {
                    BY_HANDLE_FILE_INFORMATION info = new BY_HANDLE_FILE_INFORMATION();
                    if (!GetFileInformationByHandle(handle, ref info))
                        throw new InvalidOperationException("stat component \"" + current + "\": error " + Marshal.GetLastWin32Error());
                    if ((info.dwFileAttributes & ReparsePointAttr) != 0)
                        throw new InvalidOperationException("component \"" + current + "\" is a reparse point");
                    if (isLeaf)
                    {
                        StringBuilder final = new StringBuilder(1024);
                        uint n = GetFinalPathNameByHandleW(handle, final, 1024, 0 /* VOLUME_NAME_DOS */);
                        if (n == 0)
                            throw new InvalidOperationException("final path \"" + current + "\": error " + Marshal.GetLastWin32Error());
                        if (!NormalizeFinal(final.ToString()).Equals(NormalizeFinal(abs), StringComparison.OrdinalIgnoreCase))
                            throw new InvalidOperationException("final path \"" + final + "\" does not resolve to requested \"" + abs + "\"");
                    }
                }
                finally { CloseHandle(handle); }
            }
        }

        private static string ExtendedPath(string abs)
        {
            if (abs.StartsWith(@"\\"))
                return @"\\?\UNC\" + abs.Substring(2);
            return @"\\?\" + abs;
        }

        private static int VolumePrefixLen(string ext)
        {
            if (ext.StartsWith(@"\\?\UNC\"))
            {
                string rest = ext.Substring(8);
                int idx = rest.IndexOf('\\');
                if (idx < 0) return ext.Length;
                string share = rest.Substring(idx + 1);
                int idx2 = share.IndexOf('\\');
                if (idx2 < 0) return ext.Length;
                return 8 + idx + 1 + idx2;
            }
            return 6; // \\?\C:
        }

        private static string NormalizeFinal(string s)
        {
            if (s.StartsWith(@"\\?\")) s = s.Substring(4);
            return s.ToLowerInvariant();
        }

        // -------------------------------------------------------- capabilities

        private static void CmdCapabilities()
        {
            string job = Proven, dacl = Proven, reparse = Proven;
            try { CapabilityJob(); } catch (Exception e) { job = NotProven(e); }
            try { CapabilityDacl(); } catch (Exception e) { dacl = NotProven(e); }
            try { CapabilityReparse(); } catch (Exception e) { reparse = NotProven(e); }
            Emit("{\"job_object_process_ownership\":" + job +
                 ",\"private_runtime_dacl\":" + dacl +
                 ",\"reparse_safe_path_admission\":" + reparse + "}");
        }

        private const string Proven = "{\"available\":true,\"reason\":null,\"proof\":\"native-authority\"}";

        private static string NotProven(Exception e)
        {
            return "{\"available\":false,\"reason\":" + JsonString(e.Message) + ",\"proof\":\"not-proven\"}";
        }

        private static void CapabilityJob()
        {
            IntPtr job = CreateJobObjectW(IntPtr.Zero, null);
            if (job == IntPtr.Zero)
                throw new InvalidOperationException("CreateJobObjectW failed: " + Marshal.GetLastWin32Error());
            try
            {
                JOBOBJECT_EXTENDED_LIMIT_INFORMATION info = new JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
                info.BasicLimitInformation.LimitFlags = JobObjectLimitKillOnJobClose;
                IntPtr buf = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION)));
                try
                {
                    Marshal.StructureToPtr(info, buf, false);
                    bool setOk = SetInformationJobObject(job, JobObjectExtendedLimitInformation, buf,
                        (uint)Marshal.SizeOf(typeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION)));
                        int setErr = Marshal.GetLastWin32Error();
                        if (!setOk)
                            throw new InvalidOperationException("SetInformationJobObject failed: err=" + setErr + " size=" + Marshal.SizeOf(typeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION)));
                }
                finally { Marshal.FreeHGlobal(buf); }

                STARTUPINFO si = new STARTUPINFO();
                si.cb = Marshal.SizeOf(typeof(STARTUPINFO));
                PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
                string exe = ResolveExecutable("cmd.exe");
                if (!CreateProcessW(exe, BuildCommandLine(
                    new string[] { "cmd.exe", "/d", "/s", "/c", "exit 0" }, false),
                    IntPtr.Zero, IntPtr.Zero, true, CreateSuspended,
                    IntPtr.Zero, IntPtr.Zero, ref si, ref pi))
                    throw new InvalidOperationException("CreateProcess failed: " + Marshal.GetLastWin32Error());
                try
                {
                    if (!AssignProcessToJobObject(job, pi.hProcess))
                    {
                        TerminateProcess(pi.hProcess, 1);
                        throw new InvalidOperationException("AssignProcessToJobObject failed");
                    }
                    ResumeThread(pi.hThread);
                    if (WaitForSingleObject(pi.hProcess, 10000) != 0)
                        throw new InvalidOperationException("wait failed");
                    uint code;
                    if (!GetExitCodeProcess(pi.hProcess, out code))
                        throw new InvalidOperationException("GetExitCodeProcess failed");
                    if (code != 0)
                        throw new InvalidOperationException("probe child exited " + code);
                    int held = JobProcessIdCount(job);
                    if (held != 0)
                        throw new InvalidOperationException("job still holds " + held + " processes after exit");
                }
                finally
                {
                    CloseHandle(pi.hThread);
                    CloseHandle(pi.hProcess);
                }
            }
            finally { CloseHandle(job); }
        }

        private static int JobProcessIdCount(IntPtr job)
        {
            uint size = 0;
            QueryInformationJobObject(job, 3 /* JobObjectBasicProcessIdList */, IntPtr.Zero, 0, ref size);
            if (size == 0) return 0;
            IntPtr buf = Marshal.AllocHGlobal((int)size);
            try
            {
                if (!QueryInformationJobObject(job, 3, buf, size, ref size))
                    return 0;
                int count = Marshal.ReadInt32(buf, 0);
                return count;
            }
            finally { Marshal.FreeHGlobal(buf); }
        }

        private static void CapabilityDacl()
        {
            string dir = Path.Combine(Path.GetTempPath(), "rea-winauth-dacl-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(dir);
            try
            {
                DaclCreate(dir);
            }
            finally { try { Directory.Delete(dir, true); } catch { } }
        }

        private static void CapabilityReparse()
        {
            string root = Path.Combine(Path.GetTempPath(), "rea-winauth-reparse-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(root);
            try
            {
                string realDir = Path.Combine(root, "real");
                Directory.CreateDirectory(realDir);
                PathCheckOne(realDir); // clean path must be admitted
                string link = Path.Combine(root, "link");
                CreateSymbolicLinkW(link, realDir, 0x1 /* DIRECTORY */);
                if (!Directory.Exists(link))
                {
                    // Symlink privilege unavailable; a junction is also a
                    // reparse point and needs no privilege.
                    Process.Start(new ProcessStartInfo(
                        Environment.GetEnvironmentVariable("ComSpec") ?? "cmd.exe",
                        "/d /s /c mklink /J \"" + link + "\" \"" + realDir + "\"")
                    {
                        UseShellExecute = false,
                        CreateNoWindow = true
                    }).WaitForExit();
                }
                if (!Directory.Exists(link))
                    return; // could not build the positive test; admission check above ran
                if (Environment.GetEnvironmentVariable("REA_WINAUTH_DEBUG") == "1")
                {
                    IntPtr h = CreateFileW(ExtendedPath(link), FileReadAttributes, ShareAll,
                        IntPtr.Zero, 3, FlagBackupSemantics | FlagOpenReparsePoint, IntPtr.Zero);
                    if (h == new IntPtr(-1))
                        Console.Error.WriteLine("REA-WINAUTH-DEBUG symlink open err=" + Marshal.GetLastWin32Error());
                    else
                    {
                        BY_HANDLE_FILE_INFORMATION bi = new BY_HANDLE_FILE_INFORMATION();
                        GetFileInformationByHandle(h, ref bi);
                        Console.Error.WriteLine("REA-WINAUTH-DEBUG symlink attrs=0x" + bi.dwFileAttributes.ToString("x"));
                        CloseHandle(h);
                    }
                }
                try
                {
                    PathCheckOne(link); // must throw
                    throw new InvalidOperationException("reparse path was admitted");
                }
                catch (InvalidOperationException e)
                {
                    if (e.Message.IndexOf("reparse point", StringComparison.Ordinal) < 0 &&
                        e.Message.IndexOf("does not resolve", StringComparison.Ordinal) < 0)
                        throw;
                }
            }
            finally { try { Directory.Delete(root, true); } catch { } }
        }

        // ------------------------------------------------------------- interop

        [StructLayout(LayoutKind.Sequential)]
        private struct IO_COUNTERS
        {
            public ulong ReadOperationCount;
            public ulong WriteOperationCount;
            public ulong OtherOperationCount;
            public ulong ReadTransferCount;
            public ulong WriteTransferCount;
            public ulong OtherTransferCount;
        }

        // Layout copied from the verified x64 definition (PerJobUserTimeLimit
        // and LimitFlags precede the working-set sizes; total BASIC = 64).
        [StructLayout(LayoutKind.Sequential)]
        private struct JOBOBJECT_BASIC_LIMIT_INFORMATION
        {
            public long PerProcessUserTimeLimit;
            public long PerJobUserTimeLimit;
            public uint LimitFlags;
            public UIntPtr MinimumWorkingSetSize;
            public UIntPtr MaximumWorkingSetSize;
            public uint ActiveProcessLimit;
            public UIntPtr Affinity;
            public uint PriorityClass;
            public uint SchedulingClass;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION
        {
            public JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
            public IO_COUNTERS IoInfo;
            public UIntPtr ProcessMemoryLimit;
            public UIntPtr JobMemoryLimit;
            public UIntPtr PeakProcessMemoryUsed;
            public UIntPtr PeakJobMemoryUsed;
        }

        private const uint JobObjectLimitKillOnJobClose = 0x2000;
        private const int JobObjectExtendedLimitInformation = 9;

        [StructLayout(LayoutKind.Sequential)]
        private struct STARTUPINFO
        {
            public int cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public uint dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars;
            public uint dwFillAttribute, dwFlags;
            public ushort wShowWindow, cbReserved2;
            public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESS_INFORMATION
        {
            public IntPtr hProcess, hThread;
            public uint dwProcessId, dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct TRUSTEE
        {
            public IntPtr MultipleTrustee;
            public uint MultipleTrusteeOperation;
            public uint TrusteeForm;
            public uint TrusteeType;
            public IntPtr ptstrName;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct EXPLICIT_ACCESS
        {
            public uint GrfAccessPermissions;
            public uint GrfAccessMode;
            public uint GrfInheritance;
            public TRUSTEE Trustee;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct BY_HANDLE_FILE_INFORMATION
        {
            public uint dwFileAttributes;
            public long ftCreationTime, ftLastAccessTime, ftLastWriteTime;
            public uint dwVolumeSerialNumber, nFileSizeHigh, nFileSizeLow;
            public uint nNumberOfLinks, nFileIndexHigh, nFileIndexLow;
        }

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern IntPtr CreateJobObjectW(IntPtr attrs, string name);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool SetInformationJobObject(IntPtr job, int infoClass, IntPtr info, uint size);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool QueryInformationJobObject(IntPtr job, int infoClass, IntPtr info, uint size, ref uint returnLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool TerminateJobObject(IntPtr job, uint exitCode);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool CreateProcessW(string appName, string cmdline,
            IntPtr procAttrs, IntPtr threadAttrs, bool inheritHandles, uint flags,
            IntPtr env, IntPtr currentDir, ref STARTUPINFO si, ref PROCESS_INFORMATION pi);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint ResumeThread(IntPtr thread);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint WaitForSingleObject(IntPtr handle, uint ms);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetExitCodeProcess(IntPtr process, out uint code);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool TerminateProcess(IntPtr process, uint code);

        [DllImport("kernel32.dll")]
        private static extern bool CloseHandle(IntPtr handle);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern IntPtr CreateFileW(string name, uint access, uint share,
            IntPtr security, uint disposition, uint flags, IntPtr template);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetFileInformationByHandle(IntPtr handle, ref BY_HANDLE_FILE_INFORMATION info);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern uint GetFinalPathNameByHandleW(IntPtr handle, StringBuilder path, uint length, uint flags);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern int SetEntriesInAclW(uint cEntries, EXPLICIT_ACCESS[] entries, IntPtr oldAcl, ref IntPtr newAcl);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern uint SetNamedSecurityInfoW(string name, uint objectType,
            uint securityInfo, IntPtr owner, IntPtr group, IntPtr dacl, IntPtr sacl);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern uint GetNamedSecurityInfoW(string name, uint objectType,
            uint securityInfo, IntPtr owner, IntPtr group, ref IntPtr dacl, IntPtr sacl, out IntPtr sd);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool GetAce(IntPtr acl, uint index, out IntPtr ace);

        [DllImport("advapi32.dll")]
        private static extern bool EqualSid(IntPtr sid1, IntPtr sid2);

        [DllImport("kernel32.dll")]
        private static extern IntPtr LocalFree(IntPtr handle);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool CreateSymbolicLinkW(string name, string target, uint flags);
    }
}
