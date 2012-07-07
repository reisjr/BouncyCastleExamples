using System;
using System.IO;
using System.Collections;
using System.Text;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Store;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.OpenSsl;

namespace ReisJr.BouncyCastle.Examples
{
    public class SigningTimeAttributeReader
    {
        static CmsSignedData ReadPem(String filename)
        {
            StreamReader sR = new StreamReader(filename);
            PemReader pR = new PemReader(sR);

            ContentInfo cI = (ContentInfo) pR.ReadObject();

            sR.Close();

            CmsSignedData cms = new CmsSignedData(cI);

            return cms;
        }

        static void Asn1Print(Asn1Encodable encodable)
        {
            Console.WriteLine(Org.BouncyCastle.Asn1.Utilities.Asn1Dump.DumpAsString(encodable));
        }

        //SigningTime ::= Time

        //Time ::= CHOICE {
        //    utcTime UTCTime,
        //    generalizedTime GeneralizedTime }
        
        static DateTime GetSigningTime(Asn1Encodable encodable)
        {
            // Special attention to the conversion from Der*Time to .Net's DateTime 
            // (May lost timezone information)

            // Try to parse as UTC time
            try
            {
                DerUtcTime timeUtc = (DerUtcTime)DerUtcTime.GetInstance(encodable);
                return timeUtc.ToAdjustedDateTime();
            }
            catch (Exception e)
            {
            }

            // Try to parse as GeneralizedTime
            try
            {
                DerGeneralizedTime timeGenTime = (DerGeneralizedTime)DerGeneralizedTime.GetInstance(encodable);
                return timeGenTime.ToDateTime();
            }
            catch (Exception e)
            {
            }

            return DateTime.Now;
        }

        static void Main(string[] args)
        {
            CmsSignedData cms = ReadPem("..\\..\\signed.pem");
            
            SignerInformationStore signerStore = cms.GetSignerInfos();

            ICollection signers = signerStore.GetSigners();

            foreach (SignerInformation signer in signers)
            {
                Org.BouncyCastle.Asn1.Cms.Attribute signingTimeAttribute;
                
                signingTimeAttribute = signer.SignedAttributes[
                    Org.BouncyCastle.Asn1.Cms.CmsAttributes.SigningTime];

                Asn1Print( signingTimeAttribute.AttrValues );

                DateTime dt = GetSigningTime( signingTimeAttribute.AttrValues[0] );

                Console.WriteLine("Time: " + dt.ToLocalTime());

            }

            Console.ReadLine();
        }
    }
}
