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
    public class StringSigner
    {
        static void SaveDer(CmsSignedData cms, String filename)
        {
            byte[] pkcs7 = cms.GetEncoded();

            // Save signed file
            FileStream pkcs7File = new FileStream(filename, FileMode.Create);

            pkcs7File.Write(pkcs7, 0, pkcs7.Length);

            pkcs7File.Close();
        }

        static void SavePem(CmsSignedData cms, String filename)
        {
            StreamWriter sW = new StreamWriter(filename);
            PemWriter pW = new PemWriter(sW);
            
            Org.BouncyCastle.Asn1.Cms.ContentInfo cI = Org.BouncyCastle.Asn1.Cms.ContentInfo.GetInstance((Asn1Sequence)Asn1Sequence.FromByteArray(cms.GetEncoded()));

            pW.WriteObject(cI);            
            
            sW.Close();
        }

        static IX509Store CreateStore(X509Certificate cert)
        {
            IList certList = new ArrayList();
            certList.Add(cert);

            X509CollectionStoreParameters storeParams = new X509CollectionStoreParameters(certList);
            IX509Store store = X509StoreFactory.Create("Certificate/Collection", storeParams);

            return store;
        }
        
        static void Main(string[] args)
        {                        
            // Open p12 containing private key
            FileStream fS = new FileStream("..\\..\\example.p12", FileMode.Open);

            Pkcs12Store p12Store = new Pkcs12Store(fS, "1234".ToCharArray());            

            // Read private key and certificate
            AsymmetricKeyParameter key = p12Store.GetKey("example").Key;           
            X509Certificate cert = p12Store.GetCertificate("example").Certificate;

            fS.Close();

            CmsSignedDataGenerator cmsGen = new CmsSignedDataGenerator();
           
            cmsGen.AddSigner(key, cert, Org.BouncyCastle.Cms.CmsSignedDataGenerator.DigestSha1);
            
            IX509Store certs = CreateStore(cert);
            
            cmsGen.AddCertificates(certs);

            byte[] data = System.Text.Encoding.UTF8.GetBytes("HELLO WORLD");

            // Prepare data
            Org.BouncyCastle.Cms.CmsProcessableByteArray dataToBeSigned = new Org.BouncyCastle.Cms.CmsProcessableByteArray(data);

            CmsSignedData cms = cmsGen.Generate(dataToBeSigned, true);

            SaveDer(cms, "..\\..\\signed.p7s");
            SavePem(cms, "..\\..\\signed.pem");           
         }
    }
}
