using System;
using System.IO;
using System.IO.Compression;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;

namespace XMLPractice
{
    class Program
    {
        static void Main(string[] args)
        {
            var currDir = Directory.GetCurrentDirectory();
            var inputXMLsDirectory = Path.GetFullPath(Path.Combine(currDir, @"..\..\..\", "XMLDocstosign"));
            bool success = LoadXmlFiles(inputXMLsDirectory);
            string outputPath;

            if (success)
            {
                string methodName = "uploadFile";
                var result = MakeWebServiceCall(methodName, "test");
                outputPath = ZipFiles(inputXMLsDirectory);
            }

        }

        private static string MakeWebServiceCall(string methodName, string requestXmlString)
        {
            WebRequest webRequest = WebRequest.Create("https://demo.efaktura.bg/soap/billerFiles.php");

            HttpWebRequest httpRequest = (HttpWebRequest)webRequest;
            httpRequest.Method = "POST";
            //this is to include mime types(attachments)
            httpRequest.ContentType = "multipart/related";
            
            //methodName should be uploadFile
        //    httpRequest.Headers.Add()
            httpRequest.Headers.Add("SOAPAction: https://demo.efaktura.bg/soap/billerFiles.php" + methodName);
            Stream requestStream = httpRequest.GetRequestStream();

            //Create Stream and Complete Request
            StreamWriter streamWriter = new StreamWriter(requestStream);
            streamWriter.Write(GetSoapString(requestXmlString));
            streamWriter.Close();

            //Get response
            WebResponse webResponse = httpRequest.GetResponse();
            Stream responseStream = webResponse.GetResponseStream();
            StreamReader streamReader = new StreamReader(responseStream);
            string resulXmlFromWebService = streamReader.ReadToEnd();
            //Console.WriteLine(resulXmlFromWebService);
            //return resulXmlFromWebService;

            ////Read the response into an xml document - that breaks if the document does not work
            System.Xml.XmlDocument soapResonseXMLDocument = new System.Xml.XmlDocument();

            soapResonseXMLDocument.LoadXml(streamReader.ReadToEnd());

            //return only the xml representing the response details (inner request)
            return soapResonseXMLDocument.GetElementsByTagName(methodName + "Result")[0].InnerXml;
        }


        private static string GetSoapString(string requestXmlString)
        {
            var plainTextBytes = System.Text.Encoding.UTF8.GetBytes(requestXmlString);
            var fileName = System.Convert.ToBase64String(plainTextBytes);
            string x = @"<note>
< to > Tove </ to >
< from > Jani </ from >
< heading > Reminder </ heading >
< body > Don't forget me this weekend!</body>
   </ note > ";
            StringBuilder soapRequest = new StringBuilder();
            soapRequest.AppendLine(@"<?xml version=""1.0"" encoding=""UTF-8""?>");
       //     soapRequest.AppendLine(@"<root>");
            soapRequest.AppendLine(@"<SOAP-ENV:Envelope xmlns:SOAP-ENV = ""http://schemas.xmlsoap.org/soap/envelope/""");

            soapRequest.AppendLine(@"xmlns:xsd=""http://www.w3.org/2001/XMLSchema""");
            soapRequest.AppendLine(@"xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance""");
            soapRequest.AppendLine(@"xmlns:SOAP-ENC=""http://schemas.xmlsoap.org/soap/encoding/""");
            soapRequest.AppendLine(@"SOAP-ENV:encodingStyle=""http://schemas.xmlsoap.org/soap/encoding/""");
            soapRequest.AppendLine(@"xmlns:ns4=""https://efaktura.bg/soap/"">");
            soapRequest.AppendLine(@"<SOAP-ENV:Body>");
            soapRequest.AppendLine(@"<ns4:uploadFile>");
            soapRequest.AppendLine(@"<ns4:authorizationId>QzYxNTgyLUI3M0s0N0VKNTQ=</ns4:authorizationId>");
            soapRequest.AppendLine(@"<ns4:authorizationKey>VFdUWEJQLUhORVo5Si03NEVWOFotUU01SjlU</ns4:authorizationKey>");
            soapRequest.AppendLine($@"<ns4:fileName>{fileName}</ns4:fileName>");
            soapRequest.AppendLine(@"<fileCont href=""cid: e2315277bec2dfea98e1ca49f8d310b1""/></ns4:uploadFile>");
            soapRequest.AppendLine(@"</SOAP-ENV:Body>");
            soapRequest.AppendLine(@"</SOAP-ENV:Envelope>");
        //    soapRequest.AppendLine(@"</root>");
            Console.WriteLine(soapRequest);
            XmlDocument doc = new XmlDocument();

            doc.LoadXml(soapRequest.ToString());
            return soapRequest.ToString();
        }

        //Generate xml based on the C# object from the database
        public static bool LoadXmlFiles(string targetDirectory)
        {
            bool success = true;
            // Process the list of files found in the directory.
            //We assume files are of type.xml in the folder
            try
            {

                string[] fileEntries = Directory.GetFiles(targetDirectory);

                var certificate = GetDefaultCertificateStoredOnTheCard();

                foreach (string fileName in fileEntries)
                {
                    try
                    {
                        XmlDocument xmlDoc = new XmlDocument();
                        xmlDoc.PreserveWhitespace = true;
                        xmlDoc.Load(fileName);
                        SignXmlDocumentWithCertificate(xmlDoc, certificate);
                        //  Console.WriteLine($"{fileName} XML file signed.");
                        var currDir2 = Directory.GetCurrentDirectory();
                        var threedirectories = Path.GetFullPath(Path.Combine(currDir2, @"..\..\..\XMLDocstosign\SignedDocs"));
                        var lastIndex = fileName.LastIndexOf("\\");
                        var newFileName = fileName.Substring(lastIndex, fileName.Length - lastIndex - 4);
                        var xmlsignedDoc = threedirectories + newFileName + "_signed.xml";
                        Console.WriteLine(xmlsignedDoc);
                        //   Console.WriteLine(xmlsignedDoc);
                        xmlDoc.Save(xmlsignedDoc);

                        success = true;
                    }

                    catch (Exception e)
                    {
                        Console.WriteLine(e.Message);
                        success = false;
                    }
                }
            }

            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                success = false;
            }

            return success;
        }

        public static void SignXmlDocumentWithCertificate(XmlDocument xmlDoc, X509Certificate2 cert)
        {
            SignedXml signedXml = new SignedXml(xmlDoc);
            //we will sign it with private key
            signedXml.SigningKey = cert.PrivateKey;

            if (cert.PrivateKey == null)
            {
                throw new ArgumentException("Please make sure the application for electronic signatures is installed, so the private key can be obtained from the smart card!");
            }
            Reference reference = new Reference();
            //sign the entire doc
            reference.Uri = "";
            XmlDsigEnvelopedSignatureTransform env = new XmlDsigEnvelopedSignatureTransform();
            reference.AddTransform(env);
            signedXml.AddReference(reference);

            //PublicKey part
            RSACryptoServiceProvider rsaprovider = (RSACryptoServiceProvider)cert.PublicKey.Key;
            RSAKeyValue rkv = new RSAKeyValue(rsaprovider);


            KeyInfo keyInfo = new KeyInfo();
            keyInfo.AddClause(new KeyInfoX509Data(cert));
            //We add the public key here
            keyInfo.AddClause(rkv);

            signedXml.KeyInfo = keyInfo;
            signedXml.ComputeSignature();

            // Get the XML representation of the signature and save
            // it to an XmlElement object.
            XmlElement xmlDigitalSignature = signedXml.GetXml();

            // Append the element to the XML document.
            xmlDoc.DocumentElement.AppendChild(xmlDoc.ImportNode(xmlDigitalSignature, true));
        }

        public static X509Certificate2 GetDefaultCertificateStoredOnTheCard()
        {
            X509Store store = new X509Store("MY", StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
            X509Certificate2Collection certs = store.Certificates.Find(X509FindType.FindByTimeValid, DateTime.Now, true);

            // by thumbprint, there is only one
            certs = certs.Find(X509FindType.FindByThumbprint, "6BB4F9D483206F44A992799541114536579CF2B3", true);

            if (certs.Count == 0)
            {
                throw new ArgumentException("Please insert smart card to obtain certificate.");
            }
            X509Certificate2 cert = certs[0];

            RSACryptoServiceProvider key;

            if (cert.HasPrivateKey)
            {
                // software cert
                key = cert.PrivateKey as RSACryptoServiceProvider;

            }
            else
            {
                // certificate from smartcard
                CspParameters csp = new CspParameters(1, "Microsoft Base Smart Card Crypto Provider");
                csp.Flags = CspProviderFlags.UseDefaultKeyContainer;
                key = new RSACryptoServiceProvider(csp);
            }

            return cert;
        }

        public static string ZipFiles(string inputXMLsDirectory)
        {
            string extractPath = inputXMLsDirectory + @"\..\results.zip";
            var signedDocsFolder = inputXMLsDirectory + @".\SignedDocs";

            int fileCount = Directory.GetFiles(signedDocsFolder).Length;

            if (fileCount > 2)
            {
                try
                {
                    ZipFile.CreateFromDirectory(signedDocsFolder, extractPath);
                }
                catch (IOException e)
                {
                    Console.WriteLine("Zip file has already been created. Please delete file if you want to make a new one.");
                }
                return extractPath;
            }
            else
            {
                return signedDocsFolder;
            }         
        }
    }
}
