using System;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Medo.Security.Cryptography;

using static Tests.Helpers;

namespace Tests;

[TestClass]
public class Rabbit_Tests {

    [DataTestMethod]
    [DataRow("VectorA1.txt")]
    [DataRow("VectorA2.txt")]
    [DataRow("VectorA3.txt")]
    [DataRow("VectorA4.txt")]
    [DataRow("VectorA5.txt")]
    [DataRow("VectorA6.txt")]
    [DataRow("VectorB1.txt")]
    [DataRow("VectorB2.txt")]
    [DataRow("VectorB3.txt")]
    public void Rabbit_Vectors(string fileName) {
        RetrieveVectors(fileName, out var key, out var iv, out var dataQueue);

        using var ct = new MemoryStream();
        using var transform = new Rabbit().CreateEncryptor(key, iv);
        using var cs = new CryptoStream(ct, transform, CryptoStreamMode.Write);

        var n = 0;
        while (dataQueue.Count > 0) {
            var entry = dataQueue.Dequeue();
            var index = entry.Key;
            var expectedBytes = entry.Value;

            while (n <= index) {
                cs.Write(new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 });  // hardcoded to 16-bytes
                n += 16;
            }
            cs.Flush();
            var cipherBytes = new byte[16];
            Array.Copy(ct.ToArray(), n - 16, cipherBytes, 0, 16);  // not efficient but good enough for test
            Assert.AreEqual(BitConverter.ToString(expectedBytes), BitConverter.ToString(cipherBytes));
        }
    }

    [DataTestMethod]
    [DataRow("23C2731E8B5469FD8DABB5BC592A0F3A",
             "712906405EF03201",
             "1AE2D4EDCF9B6063B00FD6FDA0B223ADED157E77031CF0440B",
             "Rabbit stream cipher test")]
    [DataRow("0EA30464E88F321047ACCCFED2AC18F0",
             "CCEBA07AE8B1FBE6",
             "747ED2055DA707D9A04F717F28F8A010DD8A84F31EE3262745",
             "Rabbit stream cipher test")]
    [DataRow("BD9E9C4E91C9B2858741C46AA91A11DE",
             "2374EC9C1026B41C",
             "81FDD1CEF6549AA55032B45197B22F0A4A043B59BE7084CA02",
             "Rabbit stream cipher test")]
    public void Rabbit_Examples(string keyHex, string ivHex, string cipherHex, string plainText) {
        var key = GetBytes(keyHex);
        var iv = GetBytes(ivHex);
        var cipherBytes = GetBytes(cipherHex);

        var ct = Encrypt(new Rabbit(), key, iv, Encoding.ASCII.GetBytes(plainText));
        Assert.AreEqual(BitConverter.ToString(cipherBytes), BitConverter.ToString(ct));

        var pt = Decrypt(new Rabbit(), key, iv, cipherBytes);
        Assert.AreEqual(plainText, Encoding.ASCII.GetString(pt));
    }


    [DataTestMethod]
    [DataRow(PaddingMode.None)]
    [DataRow(PaddingMode.PKCS7)]
    [DataRow(PaddingMode.Zeros)]
    [DataRow(PaddingMode.ANSIX923)]
    [DataRow(PaddingMode.ISO10126)]
    public void Rabbit_EncryptDecrypt(PaddingMode padding) {
        var crypto = new Rabbit() { Padding = padding };
        crypto.GenerateKey();
        crypto.GenerateIV();
        var bytes = RandomNumberGenerator.GetBytes(1024);
        var bytesEnc = new byte[bytes.Length];
        var bytesDec = new byte[bytes.Length];

        var sw = Stopwatch.StartNew();
        using var encryptor = crypto.CreateEncryptor();
        using var decryptor = crypto.CreateDecryptor();
        for (var n = 0; n < 1024; n++) {
            encryptor.TransformBlock(bytes, 0, bytes.Length, bytesEnc, 0);
            decryptor.TransformBlock(bytesEnc, 0, bytesEnc.Length, bytesDec, 0);
        }

        var lastBytesEnc = encryptor.TransformFinalBlock(new byte[10], 0, 10);
        var lastBytesDec = decryptor.TransformFinalBlock(lastBytesEnc, 0, lastBytesEnc.Length);
        sw.Stop();

        Debug.WriteLine($"Duration: {sw.ElapsedMilliseconds} ms");
    }

}
