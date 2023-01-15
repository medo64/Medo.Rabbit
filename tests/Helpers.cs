using System.Collections.Generic;
using System.Globalization;
using System;
using System.IO;
using System.Reflection;
using System.Security.Cryptography;

namespace Tests;

internal static class Helpers {

    public static byte[] Encrypt(SymmetricAlgorithm algorithm, byte[] key, byte[] iv, byte[] pt) {
        using var ms = new MemoryStream();
        using (var transform = algorithm.CreateEncryptor(key, iv)) {
            using var cs = new CryptoStream(ms, transform, CryptoStreamMode.Write);
            cs.Write(pt, 0, pt.Length);
        }
        return ms.ToArray();
    }

    public static byte[] Decrypt(SymmetricAlgorithm algorithm, byte[] key, byte[] iv, byte[] ct) {
        using var ctStream = new MemoryStream(ct);
        using var transform = algorithm.CreateDecryptor(key, iv);
        using var cs = new CryptoStream(ctStream, transform, CryptoStreamMode.Read);
        using var ms = new MemoryStream();
        cs.CopyTo(ms);
        return ms.ToArray();
    }

    public static void RetrieveVectors(string fileName, out byte[] key, out byte[] iv, out Queue<KeyValuePair<int, byte[]>> data) {
        using var reader = new StreamReader(GetResourceStream(fileName));

        key = GetLineBytes(reader.ReadLine().Trim(), out var headerText);
        if (!headerText.Equals("KEY", StringComparison.InvariantCultureIgnoreCase)) { throw new InvalidDataException(); }

        data = new Queue<KeyValuePair<int, byte[]>>();

        iv = GetLineBytes(reader.ReadLine().Trim(), out var ivHeader);
        if (!ivHeader.Equals("IV", StringComparison.InvariantCultureIgnoreCase)) {  // it's not IV
            var location = int.Parse(ivHeader, NumberStyles.HexNumber);
            data.Enqueue(new KeyValuePair<int, byte[]>(location, iv));
            iv = null;
        }

        while (!reader.EndOfStream) {
            var line = reader.ReadLine();
            if (line.Length > 0) {
                var bytes = GetLineBytes(line, out var locationText);
                var location = int.Parse(locationText, NumberStyles.HexNumber);
                data.Enqueue(new KeyValuePair<int, byte[]>(location, bytes));
            }
        }
    }

    public static byte[] GetLineBytes(string lineText, out string headerText) {
        var parts = lineText.Split(":");
        if (parts.Length != 2) { throw new InvalidDataException(); }

        headerText = parts[0].Split(" ", StringSplitOptions.RemoveEmptyEntries)[^1];
        var bytesText = parts[1].Trim().Replace(" ", "");
        if (bytesText.StartsWith("0x")) { bytesText = bytesText[2..]; }
        return GetBytes(bytesText);
    }

    public static byte[] GetBytes(string bytesText) {
        var data = new Queue<byte>();
        for (var i = 0; i < bytesText.Length; i += 2) {
            data.Enqueue(byte.Parse(bytesText.Substring(i, 2), NumberStyles.HexNumber));
        }
        return data.ToArray();
    }


    public static Stream GetResourceStream(string relativePath) {
        if (relativePath == null) { return null; }
        var helperType = typeof(Helpers).GetTypeInfo();
        var assembly = helperType.Assembly;
        return assembly.GetManifestResourceStream(helperType.Namespace + ".Resources." + relativePath);
    }

}
