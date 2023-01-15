using System.Security.Cryptography;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Medo.Security.Cryptography;

namespace Tests;

[TestClass]
public class Rabbit_Exceptions_Tests {

    [DataTestMethod]
    [DataRow(CipherMode.ECB)]
    [DataRow(CipherMode.CFB)]
    [DataRow(CipherMode.CTS)]
    public void Rabbit_Exceptions_OnlyCbcSupported(CipherMode mode) {
        Assert.ThrowsException<CryptographicException>(() => {
            var _ = new Rabbit() { Mode = mode };
        });
    }

}
