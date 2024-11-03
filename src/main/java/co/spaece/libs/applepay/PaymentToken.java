package co.spaece.libs.applepay;

public class PaymentToken {
	
	private String version;
	
	private String data;
	
	private String signature;
	
	private Header header;
	
	public static class Header {
		
		private String ephemeralPublicKey;
		
		private String publicKeyHash;
		
		private String transactionId;
		
		public String getEphemeralPublicKey() {
			return ephemeralPublicKey;
		}
		
		public void setEphemeralPublicKey(String ephemeralPublicKey) {
			this.ephemeralPublicKey = ephemeralPublicKey;
		}
		
		public String getPublicKeyHash() {
			return publicKeyHash;
		}
		
		public void setPublicKeyHash(String publicKeyHash) {
			this.publicKeyHash = publicKeyHash;
		}
		
		public String getTransactionId() {
			return transactionId;
		}
		
		public void setTransactionId(String transactionId) {
			this.transactionId = transactionId;
		}
	}
	
	public String getVersion() {
		return version;
	}
	
	public void setVersion(String version) {
		this.version = version;
	}
	
	public String getData() {
		return data;
	}
	
	public void setData(String data) {
		this.data = data;
	}
	
	public String getSignature() {
		return signature;
	}
	
	public void setSignature(String signature) {
		this.signature = signature;
	}
	
	public Header getHeader() {
		return header;
	}
	
	public void setHeader(Header header) {
		this.header = header;
	}
}
