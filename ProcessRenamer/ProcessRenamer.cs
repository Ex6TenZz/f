using System;
using System.Runtime.InteropServices;

class ProcessRenamer
{
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool SetConsoleTitle(string lpConsoleTitle);

    static void Main(string[] args)
    {
        string newTitle = args.Length > 0 ? args[0] : Guid.NewGuid().ToString();
        SetConsoleTitle(newTitle);

        // Junk-код: случайные переменные, строки, вывод
        for (int i = 0; i < new Random().Next(2, 6); i++)
        {
            string junk = Guid.NewGuid().ToString() + newTitle;
            Console.WriteLine("Junk: " + junk);
        }

        // Дополнительный junk: случайные аргументы
        for (int i = 0; i < new Random().Next(1, 4); i++)
        {
            string fakeArg = "junk_" + Guid.NewGuid().ToString("N").Substring(0, 8);
            Console.WriteLine("Arg: " + fakeArg);
        }
    }
}

// Компиляция:
// Для Windows: csc.exe /target:exe /out:ProcessRenamer.exe ProcessRenamer.cs
// Для .NET Core: dotnet build или dotnet publish (если проект)
// Можно автоматизировать через PowerShell:
//   & "C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe" /target:exe /out:ProcessRenamer.exe ProcessRenamer.cs
