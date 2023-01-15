using System;
using System.Security.Cryptography;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Medo.Security.Cryptography;

using static Tests.Helpers;
using System.Text;

namespace Tests;

[TestClass]
public class Rabbit_Padding_Tests {

    [DataTestMethod]
    [DataRow(PaddingMode.None)]
    [DataRow(PaddingMode.PKCS7)]
    [DataRow(PaddingMode.Zeros)]
    [DataRow(PaddingMode.ANSIX923)]
    [DataRow(PaddingMode.ISO10126)]
    public void Rabbit_Padding_Full(PaddingMode padding) {
        var key = new byte[16]; RandomNumberGenerator.Fill(key);
        var iv = new byte[8]; RandomNumberGenerator.Fill(iv);
        var data = new byte[48]; RandomNumberGenerator.Fill(data);  // full blocks

        var algorithm = new Rabbit() { Padding = padding, };

        var ct = Encrypt(algorithm, key, iv, data);
        var pt = Decrypt(algorithm, key, iv, ct);
        Assert.AreEqual(data.Length, pt.Length);
        Assert.AreEqual(BitConverter.ToString(data), BitConverter.ToString(pt));
    }

    [DataTestMethod]
    [DataRow(PaddingMode.PKCS7)]
    [DataRow(PaddingMode.Zeros)]
    [DataRow(PaddingMode.ANSIX923)]
    [DataRow(PaddingMode.ISO10126)]
    public void Rabbit_Padding_Partial(PaddingMode padding) {
        var key = new byte[16]; RandomNumberGenerator.Fill(key);
        var iv = new byte[8]; RandomNumberGenerator.Fill(iv);
        var data = new byte[42]; RandomNumberGenerator.Fill(data);

        var algorithm = new Rabbit() { Padding = padding };

        var ct = Encrypt(algorithm, key, iv, data);
        var pt = Decrypt(algorithm, key, iv, ct);
        Assert.AreEqual(data.Length, pt.Length);
        Assert.AreEqual(BitConverter.ToString(data), BitConverter.ToString(pt));
    }


    [DataTestMethod]
    [DataRow(PaddingMode.None)]
    [DataRow(PaddingMode.PKCS7)]
    [DataRow(PaddingMode.Zeros)]
    [DataRow(PaddingMode.ANSIX923)]
    [DataRow(PaddingMode.ISO10126)]
    public void Rabbit_Padding_LargeFinalBlock(PaddingMode padding) {
        var crypto = new Rabbit() { Padding = padding };
        crypto.GenerateKey();
        crypto.GenerateIV();
        var text = "This is a final block wider than block size.";  // more than 128 bits of data
        var bytes = Encoding.ASCII.GetBytes(text);

        using var encryptor = crypto.CreateEncryptor();
        var ct = encryptor.TransformFinalBlock(bytes, 0, bytes.Length);

        Assert.AreEqual(padding == PaddingMode.None ? bytes.Length : 48, ct.Length);

        using var decryptor = crypto.CreateDecryptor();
        var pt = decryptor.TransformFinalBlock(ct, 0, ct.Length);

        Assert.AreEqual(bytes.Length, pt.Length);
        Assert.AreEqual(text, Encoding.ASCII.GetString(pt));
    }

    [DataTestMethod]
    [DataRow(PaddingMode.None)]
    [DataRow(PaddingMode.PKCS7)]
    [DataRow(PaddingMode.Zeros)]
    [DataRow(PaddingMode.ANSIX923)]
    [DataRow(PaddingMode.ISO10126)]
    public void Rabbit_Padding_BlockSizeRounding(PaddingMode padding) {
        var key = new byte[16]; RandomNumberGenerator.Fill(key);
        var iv = new byte[8]; RandomNumberGenerator.Fill(iv);

        for (int n = 0; n < 50; n++) {
            var data = new byte[n];
            RandomNumberGenerator.Fill(data);
            if ((padding == PaddingMode.Zeros) && (data.Length > 0)) { data[^1] = 1; }  // zero padding needs to have the last number non-zero

            var algorithm = new Rabbit() { Padding = padding, };

            var expectedCryptLength = padding switch {
                PaddingMode.None => data.Length,
                PaddingMode.PKCS7 => ((data.Length / 16) + 1) * 16,
                PaddingMode.Zeros => (data.Length / 16 + (data.Length % 16 > 0 ? 1 : 0)) * 16,
                PaddingMode.ANSIX923 => ((data.Length / 16) + 1) * 16,
                PaddingMode.ISO10126 => ((data.Length / 16) + 1) * 16,
                _ => -1

            };
            var ct = Encrypt(algorithm, key, iv, data);
            Assert.AreEqual(expectedCryptLength, ct.Length);

            var pt = Decrypt(algorithm, key, iv, ct);
            Assert.AreEqual(data.Length, pt.Length);
            Assert.AreEqual(BitConverter.ToString(data), BitConverter.ToString(pt));
        }
    }

    [DataTestMethod]
    [DataRow(PaddingMode.None)]
    [DataRow(PaddingMode.PKCS7)]
    [DataRow(PaddingMode.Zeros)]
    [DataRow(PaddingMode.ANSIX923)]
    [DataRow(PaddingMode.ISO10126)]
    public void Rabbit_Padding_Randomised(PaddingMode padding) {
        for (var n = 0; n < 1000; n++) {
            var crypto = new Rabbit() { Padding = padding };
            crypto.GenerateKey();
            crypto.GenerateIV();
            var data = new byte[Random.Shared.Next(100)];
            RandomNumberGenerator.Fill(data);
            if ((padding == PaddingMode.Zeros) && (data.Length > 0)) { data[^1] = 1; }  // zero padding needs to have the last number non-zero

            var ct = Encrypt(crypto, crypto.Key, crypto.IV, data);
            if (padding is PaddingMode.None or PaddingMode.Zeros) {
                Assert.IsTrue(data.Length <= ct.Length);
            } else {
                Assert.IsTrue(data.Length < ct.Length);
            }

            var pt = Decrypt(crypto, crypto.Key, crypto.IV, ct);
            Assert.AreEqual(data.Length, pt.Length);
            Assert.AreEqual(BitConverter.ToString(data), BitConverter.ToString(pt));
        }
    }

}
