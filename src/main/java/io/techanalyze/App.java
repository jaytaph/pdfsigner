package io.techanalyze;

import java.io.FileInputStream;
import java.io.PrintWriter;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Calendar;

import com.itextpdf.text.pdf.AcroFields;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.security.CertificateInfo;
import com.itextpdf.text.pdf.security.PdfPKCS7;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class App {

    static final String KEYSTORE_INSTANCE = "PKCS12";


    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        KeyStore ks = KeyStore.getInstance(KEYSTORE_INSTANCE);
        ks.load(new FileInputStream(args[1]), args[2].toCharArray());

        PrintWriter out = new PrintWriter(System.out);
        PdfReader reader = new PdfReader(args[0]);
        AcroFields af = reader.getAcroFields();
        ArrayList<String> names = af.getSignatureNames();
        for (String name : names) {
            out.println("Signature name: " + name);
            out.println("Signature covers whole document: " + af.signatureCoversWholeDocument(name));
            out.println("Document revision: " + af.getRevision(name) + " of " + af.getTotalRevisions());

            PdfPKCS7 pk = af.verifySignature(name);
            Calendar cal = pk.getSignDate();
            Certificate[] pkc = pk.getCertificates();
            out.println("Subject: " + CertificateInfo.getSubjectFields(pk.getSigningCertificate()));
            out.println("Revision modified: " + !pk.verify());

            // Can't verify them :(
//            List<VerificationException> errors = CertificateVerification.verifyCertificates(pkc, ks, null, cal);
//            if (errors.size() == 0)
//                out.println("Certificates verified against the KeyStore");
//            else
//                out.println("ERROR" + errors);
        }
        out.flush();
        out.close();
    }

}
