using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using ReisJr.BouncyCastle.Utils;
using Org.BouncyCastle.X509;

namespace ReisJr.BouncyCastle.Examples
{
    public class Program
    {
        static void Main(string[] args)
        {
            X509Certificate issuerCert = CertificateUtils.LoadCertificate("..\\..\\serasa_srf_2005.cer");
            X509Certificate eeCert1 = CertificateUtils.LoadCertificate("..\\..\\serasa_srf_2005_david_reis_jr.cer");
            X509Certificate eeCert3 = CertificateUtils.LoadCertificate("..\\..\\serasa_srf_2005_david_reis_jr_exp.cer");
            X509Certificate eeCert4 = CertificateUtils.LoadCertificate("..\\..\\serasa_srf_2005_david_reis_jr_exp_2.cer");

            OcspClient ocspCli = new OcspClient();

            // NOTE: If the certificate is expired, OCSP will report good.
            Console.WriteLine(ocspCli.Query(eeCert1, issuerCert));
            Console.WriteLine(ocspCli.Query(eeCert3, issuerCert));
            Console.WriteLine(ocspCli.Query(eeCert4, issuerCert));
        }
    }
}

