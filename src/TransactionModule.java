import java.math.BigInteger;
import org.bouncycastle.jcajce.provider.digest.SHA3;
import org.bouncycastle.util.encoders.Hex;

public class TransactionModule {
	public BigInteger Transact(BigInteger hashMessage, BigInteger simpleMessage,  BigInteger amt) {
		
		SHA3.DigestSHA3 digestSHA3 = new SHA3.Digest224();
		byte[] digestedMessage = digestSHA3.digest(hashMessage.toByteArray());
		
		byte[] byteSimpleMessage = simpleMessage.toByteArray();
		byte[] byteSimpleMessagePadded = new byte[100];
		
		for(int b = byteSimpleMessage.length - 1; b >= 0; b--) {
			byteSimpleMessagePadded[byteSimpleMessagePadded.length - 1 - b] = byteSimpleMessage[byteSimpleMessage.length - 1 - b];
		}
				
		BigInteger nonce;
		BigInteger T1 = BigInteger.ZERO;

		byte[] byteNoncePadded = new byte[16];
		for(int i = 0; i < Math.pow(2, 24); i++) {
			nonce = new BigInteger(Integer.toString(i));
			byte[] byteNonce = nonce.toByteArray();
			for(int j = byteNonce.length - 1; j >= 0; j--) {
				byteNoncePadded[byteNoncePadded.length - 1 - j] = byteNonce[byteNonce.length - 1 - j];
			}
			byte[] m1 = new byte[1152];
			
			System.arraycopy(digestedMessage, 0, m1, 0, digestedMessage.length);
			System.arraycopy(byteSimpleMessagePadded, 0, m1, digestedMessage.length, byteSimpleMessagePadded.length);
			System.arraycopy(byteNoncePadded, 0, m1, digestedMessage.length +  byteSimpleMessagePadded.length, byteNoncePadded.length);

			byte[] digestedM1 = digestSHA3.digest(m1);

			if(CheckPreImage(digestedM1)) {
				System.out.println("valid nonce found -> " + Hex.toHexString(byteNoncePadded));
				T1 = new BigInteger(1, digestedM1);
				break;
			}
		}
		return T1;
	}
	
	public Boolean CheckPreImage(byte[] digestedM1) {
		for(int i = 0; i < 3; i++) {
			if(digestedM1[i] != 0) {
				return false;
			}
		}
		System.out.println("FOUND A PREIMAGE! -> " + Hex.toHexString(digestedM1));
		return true;
	}
}
