/*
 *      Alessandro Cagliostro, 2020
 *      
 *      https://github.com/alecgn
 */

using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace CryptHash.Net
{
    public enum AesCipherMode { CBC = CipherMode.CBC, ECB = CipherMode.ECB, OFB = CipherMode.OFB, CFB = CipherMode.CFB, CTS = CipherMode.CTS, GCM };
}