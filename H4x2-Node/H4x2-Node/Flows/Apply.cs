using H4x2_TinySDK.Ed25519;
using H4x2_TinySDK.Tools;
using System.Numerics;
using H4x2_Node.Controllers;

namespace H4x2_Node.Flows
{
    public class Apply
    {
        public static ApplyPrismResponse Prism(Point toApply, BigInteger prism)
        {
            var response = new ApplyPrismResponse
            {
                Applied = (toApply * prism).ToBase64()
            };
            return response;
        }

        public static ApplyAuthDataResponse AuthData(string uid, string encryptedAuthData, string prismAuth, BigInteger CVK)
        {
            try
            {
                var decryptedAuthData = AES.Decrypt(encryptedAuthData, Convert.FromBase64String(prismAuth));
                if (!decryptedAuthData.Equals("Authenticated")) throw new Exception("ApplyAuthData: Wrong message encrypted");
                new ThrottlingManager().Remove(uid);
            }
            catch
            {
                throw new Exception("Incorrect Password !");
            }
            var response = new ApplyAuthDataResponse
            {
                EncryptedCVK = AES.Encrypt(CVK.ToString(), Convert.FromBase64String(prismAuth))
            };
            return response;
        }   
    }
    public class ApplyPrismResponse
    {
        public string Applied { get; set; }
    }
    public class ApplyAuthDataResponse
    {
        public string EncryptedCVK { get; set; }
    }
}