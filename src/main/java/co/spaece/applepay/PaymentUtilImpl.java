package co.spaece.applepay;

import static org.bouncycastle.jce.provider.BouncyCastleProvider.PROVIDER_NAME;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.Enumeration;
import java.util.List;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.lang3.ArrayUtils;
import org.bouncycastle.asn1.ASN1UTCTime;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DLSet;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.encoders.Hex;

class PaymentUtilImpl implements PaymentUtil {
	private final String appleRootCACertificatePath;
	private final String appleMerchantPrivateKeyPath;
	private static KeyStore publicCertificatekeyStore;
	private static KeyStore privateCertificateKeyStore;
	
	PaymentUtilImpl(String appleRootCACertificatePath, String appleMerchantPrivateKeyPath) {
		this.appleRootCACertificatePath = appleRootCACertificatePath;
		this.appleMerchantPrivateKeyPath = appleMerchantPrivateKeyPath;
	}
	
	static {
		if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
			Security.addProvider(new BouncyCastleProvider());
		}
	}
	
	@Override
	public PaymentData decryptPaymentToken(PaymentToken paymentToken, String privateKeyPassword)
			throws CertificateException, KeyStoreException, IOException, NoSuchAlgorithmException, NoSuchProviderException {
		
		// Load merchant private key
		initializePrivateCertificateKeyStore(appleMerchantPrivateKeyPath, privateKeyPassword);
		
		// Load Apple root certificate
		initializePublicCertificateKeyStore(appleRootCACertificatePath);
		
		try {
			return decrypt(paymentToken, privateKeyPassword);
		}
		catch (Exception e) {
			throw new RuntimeException(e);
		}
	}
	
	@SuppressWarnings({ "unused", "unchecked" })
	protected PaymentData decrypt(PaymentToken tokenData, String privateKeyPassword)
			throws Exception {
		
		byte[] signatureBytes = Base64.getDecoder().decode(tokenData.getSignature());
		byte[] dataBytes = Base64.getDecoder().decode(tokenData.getData());
		
		byte[] transactionIdBytes = Hex.decode(tokenData.getHeader().getTransactionId());
		byte[] ephemeralPublicKeyBytes = Base64.getDecoder().decode(tokenData.getHeader().getEphemeralPublicKey());
		
		byte[] signedBytes = ArrayUtils.addAll(ephemeralPublicKeyBytes, dataBytes);
		signedBytes = ArrayUtils.addAll(signedBytes, transactionIdBytes);
		
		CMSSignedData signedData = new CMSSignedData(new CMSProcessableByteArray(signedBytes), signatureBytes);
		
		// Check certificate path
		Store<?> certificateStore = signedData.getCertificates();
		List<X509Certificate> certificates = new ArrayList<>();
		JcaX509CertificateConverter certificateConverter = new JcaX509CertificateConverter();
		certificateConverter.setProvider(PROVIDER_NAME);
		for (Object o : certificateStore.getMatches(null)) {
			X509CertificateHolder certificateHolder = (X509CertificateHolder) o;
			certificates.add(certificateConverter.getCertificate(certificateHolder));
		}
		CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509", PROVIDER_NAME);
		CertPath certificatePath = certificateFactory.generateCertPath(certificates);
		
		PKIXParameters params = new PKIXParameters(publicCertificatekeyStore);
		params.setRevocationEnabled(false);
		
		CertPathValidator validator = CertPathValidator.getInstance("PKIX", PROVIDER_NAME);
		
		// Verify signature
		SignerInformationStore signerInformationStore = signedData.getSignerInfos();
		boolean verified = false;
		for (SignerInformation o : signerInformationStore.getSigners()) {
			Collection<?> matches = certificateStore.getMatches(o.getSID());
			if (!matches.isEmpty()) {
				X509CertificateHolder certificateHolder = (X509CertificateHolder) matches.iterator().next();
				if (o.verify(
						new JcaSimpleSignerInfoVerifierBuilder().setProvider(PROVIDER_NAME).build(certificateHolder))) {
					DERSequence sequence = (DERSequence) o.getSignedAttributes().get(CMSAttributes.signingTime)
							.toASN1Primitive();
					DLSet set = (DLSet) sequence.getObjectAt(1);
					ASN1UTCTime signingTime = (ASN1UTCTime) set.getObjectAt(0).toASN1Primitive();
					// Merchants can check the signing time of this payment to determine its
					// freshness.
					System.out.println("Signature verified.  Signing time is " + signingTime.getDate());
					verified = true;
				}
			}
		}
		
		if (verified) {
			// Ephemeral public key
			KeyFactory keyFactory = KeyFactory.getInstance("EC", PROVIDER_NAME);
			PublicKey ephemeralPublicKey = keyFactory.generatePublic(new X509EncodedKeySpec(ephemeralPublicKeyBytes));
			
			// Key agreement
			String asymmetricKeyInfo = "ECDH";
			KeyAgreement agreement = KeyAgreement.getInstance(asymmetricKeyInfo, PROVIDER_NAME);
			agreement.init(getMerchantPrivateKey(privateKeyPassword));
			agreement.doPhase(ephemeralPublicKey, true);
			byte[] sharedSecret = agreement.generateSecret();
			
			byte[] derivedSecret = performKDF(sharedSecret, extractMerchantIdFromCertificateOid());
			
			// Decrypt the payment data
			String symmetricKeyInfo = "AES/GCM/NoPadding";
			Cipher cipher = Cipher.getInstance(symmetricKeyInfo, PROVIDER_NAME);
			
			SecretKeySpec key = new SecretKeySpec(derivedSecret, cipher.getAlgorithm());
			IvParameterSpec ivspec = new IvParameterSpec(new byte[16]);
			cipher.init(Cipher.DECRYPT_MODE, key, ivspec);
			byte[] decryptedPaymentData = cipher.doFinal(dataBytes);
			
			// JSON payload
			String data = new String(decryptedPaymentData, StandardCharsets.UTF_8);
			ObjectMapper objectMapper = new ObjectMapper();
			return objectMapper.readValue(data, PaymentData.class);
		} else {
			return null;
		}
	}
	
	private static final byte[] APPLE_OEM = "Apple".getBytes(StandardCharsets.US_ASCII);
	
	private static final byte[] COUNTER = { 0x00, 0x00, 0x00, 0x01 };
	
	private static final byte[] ALG_IDENTIFIER_BYTES = "id-aes256-GCM".getBytes(StandardCharsets.US_ASCII);
	
	private static byte[] performKDF(byte[] sharedSecret, byte[] merchantId) throws Exception {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		baos.write(COUNTER);
		baos.write(sharedSecret);
		baos.write(ALG_IDENTIFIER_BYTES.length);
		baos.write(ALG_IDENTIFIER_BYTES);
		baos.write(APPLE_OEM);
		baos.write(merchantId);
		MessageDigest messageDigest = MessageDigest.getInstance("SHA256", PROVIDER_NAME);
		return messageDigest.digest(baos.toByteArray());
	}
	
	protected PrivateKey getMerchantPrivateKey(String privateKeyPassword) {
		// Load the PKCS#12 keystore from the .p12 file
		try {
			String privateKeyAlias = extractAliasFromCertificate();
			
			// Retrieve the private key using the provided alias and password
			PrivateKey privateKey = (PrivateKey) privateCertificateKeyStore.getKey(privateKeyAlias,
					privateKeyPassword.toCharArray());
			
			if (privateKey == null) {
				throw new Exception("No private key found with the alias: " + privateKeyAlias);
			}
			
			return privateKey;
		}
		catch (Exception ignored) {
		
		}
		
		return null;
	}
	
	protected byte[] extractMerchantIdFromCertificateOid() throws Exception {
		String alias = extractAliasFromCertificate();
		X509Certificate cert = (X509Certificate) privateCertificateKeyStore.getCertificate(alias);
		byte[] merchantIdentifierTlv = cert.getExtensionValue("1.2.840.113635.100.6.32");
		byte[] merchantIdentifier = new byte[64];
		System.arraycopy(merchantIdentifierTlv, 4, merchantIdentifier, 0, 64);
		
		return Hex.decode(merchantIdentifier);
	}
	
	String extractAliasFromCertificate() throws KeyStoreException {
		Enumeration<String> aliases = privateCertificateKeyStore.aliases();
		String alias = null;
		while (aliases.hasMoreElements()) {
			alias = aliases.nextElement();
		}
		
		return alias;
	}
	
	@SuppressWarnings("unused")
	private static byte[] performKDF(byte[] sharedSecret, String merchantId) throws Exception {
		MessageDigest messageDigest = MessageDigest.getInstance("SHA256", PROVIDER_NAME);
		return performKDF(sharedSecret, messageDigest.digest(merchantId.getBytes(StandardCharsets.UTF_8)));
	}
	
	private static void initializePublicCertificateKeyStore(String rootCAPath)
			throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException, NoSuchProviderException {
		// Load the Apple Root CA certificate from the specified file path
		try (InputStream certInputStream = new FileInputStream(rootCAPath)) {
			// Initialize an empty BKS KeyStore
			publicCertificatekeyStore = KeyStore.getInstance("BKS", PROVIDER_NAME);
			publicCertificatekeyStore.load(null, "defaultPassword".toCharArray()); // Initialize the KeyStore with a password
			
			// Create a CertificateFactory for X.509 certificates
			CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
			
			// Generate a Certificate from the file input stream
			Certificate appleRootCACert = certificateFactory.generateCertificate(certInputStream);
			
			// Add the certificate to the KeyStore with an alias
			publicCertificatekeyStore.setCertificateEntry("appleRootCA", appleRootCACert);
		}
	}
	
	protected void initializePrivateCertificateKeyStore(String privateKeyPath, String privateKeyPassword)
			throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
		try (FileInputStream fis = new FileInputStream(privateKeyPath)) {
			privateCertificateKeyStore = KeyStore.getInstance("PKCS12");
			privateCertificateKeyStore.load(fis, privateKeyPassword.toCharArray());
		}
	}
}
