

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Utilities.Encoders;
using System;
using System.Collections.Generic;
using System.Text;

// dev_legion分支创建后，第2次改动

namespace AndroidQQ_8_4_1_4680_ECDH.威流
{
    class SM2Utils
    {
        public static void GenerateKeyPair(ResultKey ret)
        {
            SM2 sm2 = SM2.Instance;
            AsymmetricCipherKeyPair key = sm2.ecc_key_pair_generator.GenerateKeyPair();
            ECPrivateKeyParameters ecpriv = (ECPrivateKeyParameters)key.Private;
            ECPublicKeyParameters ecpub = (ECPublicKeyParameters)key.Public;
            BigInteger privateKey = ecpriv.D;
            ECPoint publicKey = ecpub.Q;

            System.Console.Out.WriteLine("公钥: " + Hex.ToHexString(publicKey.GetEncoded()).ToUpper());
            System.Console.Out.WriteLine("私钥: " + Hex.ToHexString(privateKey.ToByteArray()).ToUpper());

            //System.Console.Out.WriteLine("公钥: " + Encoding.ASCII.GetString(Hex.Encode(publicKey.GetEncoded())).ToUpper());
            //System.Console.Out.WriteLine("私钥: " + Encoding.ASCII.GetString(Hex.Encode(privateKey.ToByteArray())).ToUpper());


            ret.bytePubkey = publicKey.GetEncoded();
            ret.bytePrikey = privateKey.ToByteArray();
            ret.base64StrPubkey = Convert.ToBase64String(ret.bytePubkey);
            ret.base64StrPrikey = Convert.ToBase64String(ret.bytePrikey);
        }


        /// <summary>
        /// 加密
        /// </summary>
        /// <param name="publicKey">Base64表示的公钥</param>
        /// <param name="text">需要加密的明文</param>
        /// <returns>返回Base64表示的密文</returns>
        public static string Encrypt(string publicKey, string text)
        {
            if (null == publicKey || null == text)
            {
                return null;
            }

            byte[] publicKeyByte = Convert.FromBase64String(publicKey);

            if (null == publicKeyByte || publicKeyByte.Length == 0)
            {
                return null;
            }
            
            byte[] data = System.Text.Encoding.UTF8.GetBytes(text);

            if (data == null || data.Length == 0)
            {
                return null;
            }

            byte[] source = new byte[data.Length];
            Array.Copy(data, 0, source, 0, data.Length);

            Cipher cipher = new Cipher();
            SM2 sm2 = SM2.Instance;

            ECPoint userKey = sm2.ecc_curve.DecodePoint(publicKeyByte);

            ECPoint c1 = cipher.Init_enc(sm2, userKey);
            cipher.Encrypt(source);

            byte[] c3 = new byte[32];
            cipher.Dofinal(c3);

            string sc1 = Encoding.ASCII.GetString(Hex.Encode(c1.GetEncoded()));
            string sc2 = Encoding.ASCII.GetString(Hex.Encode(source));
            string sc3 = Encoding.ASCII.GetString(Hex.Encode(c3));

            //string hexStr = (sc1 + sc2 + sc3).ToUpper(); //采用C1C2C3模式
            string hexStr = sc1 + sc3 + sc2; //采用C1C3C2模式
            byte[] bytes = Hex.Decode(hexStr);

            return Convert.ToBase64String(bytes);

        }


        /// <summary>
        /// 解密
        /// </summary>
        /// <param name="privateKey">Base64进制表示的私钥</param>
        /// <param name="text">Base64进制表示的密文</param>
        /// <returns></returns>
        public static string Decrypt(string privateKey, string text)
        {
            if ( null == privateKey || null == text )
            {
                return null;
            }

            byte[] privateKeyByte = Convert.FromBase64String(privateKey);

            if (null == privateKeyByte || privateKeyByte.Length == 0)
            {
                return null;
            }

            byte[] encryptedData = Convert.FromBase64String(text);

            if (encryptedData == null || encryptedData.Length == 0)
            {
                return null;
            }

            String data = Encoding.ASCII.GetString(Hex.Encode(encryptedData));

            //采用C1C2C3模式
            //byte[] c1Bytes = Hex.Decode(Encoding.ASCII.GetBytes(data.Substring(0, 130)));
            //int c2Len = encryptedData.Length - 97;
            //byte[] c2 = Hex.Decode(Encoding.ASCII.GetBytes(data.Substring(130, 2 * c2Len)));
            //byte[] c3 = Hex.Decode(Encoding.ASCII.GetBytes(data.Substring(130 + 2 * c2Len, 64)));

            //采用C1C3C2模式
            byte[] c1Bytes = Hex.Decode(Encoding.ASCII.GetBytes(data.Substring(0, 130)));
            int c2Len = encryptedData.Length - 97;
            byte[] c3 = Hex.Decode(Encoding.ASCII.GetBytes(data.Substring(130, 64)));
            byte[] c2 = Hex.Decode(Encoding.ASCII.GetBytes(data.Substring(130 + 64, 2 * c2Len)));

            SM2 sm2 = SM2.Instance;
            BigInteger userD = new BigInteger(1, privateKeyByte);

            ECPoint c1 = sm2.ecc_curve.DecodePoint(c1Bytes);
            Cipher cipher = new Cipher();
            cipher.Init_dec(userD, c1);
            cipher.Decrypt(c2);
            cipher.Dofinal(c3);

            return Encoding.UTF8.GetString(c2);
        }


    }
}
