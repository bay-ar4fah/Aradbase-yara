import "pe"

rule AsyncRAT_Robust_Heuristic
{
    meta:
        description = "Robust AsyncRAT detection using behavioral & structural indicators"
        author = "bay-ar4fah"
        goal = "Obfuscation-resistant, low false positive"
        version = "1.0"

    strings:

        $dotnet1 = "mscorlib" ascii wide
        $dotnet2 = "System.Net.Sockets" ascii wide
        $dotnet3 = "System.Security.Cryptography" ascii wide
        $dotnet4 = "System.Threading" ascii wide

        $crypto1 = "Rfc2898DeriveBytes" ascii wide
        $crypto2 = "AesManaged" ascii wide
        $crypto3 = "CreateEncryptor" ascii wide
        $crypto4 = "CreateDecryptor" ascii wide

        $net1 = "TcpClient" ascii wide
        $net2 = "NetworkStream" ascii wide
        $net3 = "SslStream" ascii wide
        $net4 = "AuthenticateAsClient" ascii wide

        $reg1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide
        $reg2 = "Registry.CurrentUser" ascii wide
        $reg3 = "Registry.LocalMachine" ascii wide

        $mutex1 = "Mutex" ascii wide
        $mutex2 = "CreateMutex" ascii wide

    condition:

        uint16(0) == 0x5A4D and

        3 of ($dotnet*) and

        2 of ($crypto*) and

        2 of ($net*) and

        1 of ($reg*, $mutex*)
}
