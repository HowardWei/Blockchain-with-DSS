import java.math.BigInteger;
import org.bouncycastle.jcajce.provider.digest.SHA3;
import org.bouncycastle.util.encoders.Hex;

public class DSSmodule {
	public BigInteger[] Sign(BigInteger sk, BigInteger message, BigInteger p, BigInteger q, BigInteger g, BigInteger key) {
		BigInteger r;
		BigInteger s;
		
		r = g.modPow(key, p).mod(q);
		System.out.println("r -> " + r);
		
		SHA3.DigestSHA3 digestSHA3 = new SHA3.Digest224();
		byte[] digestedMessage = digestSHA3.digest(message.toByteArray());
		BigInteger intDigestedMessage = new BigInteger(1, digestedMessage).mod(q);
				
		s = key.modInverse(q).multiply(intDigestedMessage.subtract(sk.multiply(r))).mod(q);
		System.out.println("s -> " + s);
		
		BigInteger[] digitalSignature = new BigInteger[]{r, s};
		return digitalSignature;
	}
	
	public Boolean Verify(BigInteger pk, BigInteger message, BigInteger p, BigInteger q, BigInteger g, BigInteger[] digitalSignature) {
		Boolean result = true;
		BigInteger u;
		BigInteger v;
		BigInteger w;
		
		if(digitalSignature[0].compareTo(BigInteger.ZERO) != 1 || digitalSignature[0].compareTo(q) != -1) {
			result = false;
		}
		
		if(digitalSignature[1].compareTo(BigInteger.ZERO) != 1 || digitalSignature[0].compareTo(q) != -1) {
			result = false;
		}
		
		SHA3.DigestSHA3 digestSHA3 = new SHA3.Digest224();
		byte[] digestedMessage = digestSHA3.digest(message.toByteArray());
		BigInteger intDigestedMessage = new BigInteger(1, digestedMessage).mod(q);
		
		BigInteger inverseS = digitalSignature[1].modInverse(q);
		
		u = intDigestedMessage.multiply(inverseS).mod(q);
		System.out.println("u -> " + u);
		v = digitalSignature[0].negate().multiply(inverseS).mod(q);
		System.out.println("v -> " + v);
		w = g.modPow(u, p).multiply(pk.modPow(v, p)).mod(p).mod(q);
		System.out.println("w -> " + w);
		
		if(w.compareTo(digitalSignature[0]) != 0) {
			return false;
		}
				
		return result;
	}
}
