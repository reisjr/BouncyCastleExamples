using System;
using System.IO;
using System.Collections;
using System.Linq;
using System.Text;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Store;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.OpenSsl;

namespace ReisJr.BouncyCastle.Examples
{
    public class SignatureInfo1
    {
        static CmsSignedData ReadPem(String filename)
        {
            StreamReader sR = new StreamReader(filename);
            PemReader pR = new PemReader(sR);

            Org.BouncyCastle.Asn1.Cms.ContentInfo cI = (Org.BouncyCastle.Asn1.Cms.ContentInfo) pR.ReadObject();

            sR.Close();

            CmsSignedData cms = new CmsSignedData(cI);

            return cms;
        }

        static X509Certificate ReadCertificate(String filename)
        {
            X509CertificateParser certParser = new X509CertificateParser();

            Stream stream = new FileStream(filename, FileMode.Open);
            X509Certificate cert = certParser.ReadCertificate(stream);
            stream.Close();
            
            return cert;
        }

        static String ToHexString(byte[] byteArray)
        {
            byte[] hexEncodedArray = Org.BouncyCastle.Utilities.Encoders.Hex.Encode(byteArray, 0, byteArray.Length);
            String hexEncoded = Encoding.Default.GetString(hexEncodedArray);

            return hexEncoded;
        }

        static void Asn1Print(byte[] encoded)
        {
            Asn1Sequence seq = (Asn1Sequence)Asn1Sequence.FromByteArray(encoded);
            Console.WriteLine(Org.BouncyCastle.Asn1.Utilities.Asn1Dump.DumpAsString(seq));
        }

        static void Main(string[] args)
        {
            CmsSignedData cms = ReadPem("..\\..\\signed.pem");
            X509Certificate cert = ReadCertificate("..\\..\\example.cer");
            
            SignerInformationStore signerStore = cms.GetSignerInfos();

            ICollection signers = signerStore.GetSigners();

            foreach (SignerInformation signer in signers)
            {
                // Need to call Verify() first to use GetContentDigest()
                signer.Verify(cert);

                Console.WriteLine("Digest: " + ToHexString(signer.GetContentDigest()).ToUpper());
                Console.WriteLine("Enc Alg Oid: " + signer.EncryptionAlgOid);
                Console.WriteLine("Digest Alg Oid: " + signer.DigestAlgorithmID.ObjectID);
                Console.WriteLine("Signature: " + ToHexString(signer.GetSignature()).ToUpper());

                Console.WriteLine("\nSigner Info: \n");

                Asn1Print(signer.ToSignerInfo().GetDerEncoded());
            }

            Console.ReadLine();
        }
    }
}
