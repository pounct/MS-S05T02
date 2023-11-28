package cat.itacademy.barcelonactiva.abdellaoui.fethi.s05.t02.security;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
// The Bouncy Castle Crypto package is a Java implementation of cryptographic algorithms.
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

public class GenerateKeyPair {

	public static void main(String[] args) throws NoSuchAlgorithmException, IOException {

		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");

		var keyPair = keyPairGenerator.generateKeyPair();
		byte[] pub = keyPair.getPublic().getEncoded();
		byte[] pri = keyPair.getPrivate().getEncoded();
		
		PemWriter pemWriter = new PemWriter(
				new OutputStreamWriter(new FileOutputStream("./src/main/resources/certs/public.pem")));
		PemObject pemObject = new PemObject("PUBLIC KEY", pub);
		pemWriter.writeObject(pemObject);
		pemWriter.close();
		
		PemWriter pemWriter2 = new PemWriter(
				new OutputStreamWriter(new FileOutputStream("./src/main/resources/certs/private.pem")));
		PemObject pemObject2 = new PemObject("PRIVATE KEY", pri);
		pemWriter2.writeObject(pemObject2);
		pemWriter2.close();
		System.out.println("keys created!!");
	}
}
