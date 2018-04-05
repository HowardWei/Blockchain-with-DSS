import java.math.BigInteger;

import org.bouncycastle.util.encoders.Hex;

public class BlockchainDSS {
	static BigInteger p;
	static BigInteger q;
	static BigInteger g;
	static BigInteger sk1;
	static BigInteger pk1;
	static BigInteger sk2;
	static BigInteger pk2;
	static BigInteger sk3;
	static BigInteger pk3;
	static DSSmodule dssModule = new DSSmodule();
	static TransactionModule transactModule = new TransactionModule();
	
	public static void main(String[] args) {
		// TODO Auto-generated method stub
		try {
			loadData();
			if(SystemParametersCheck()) {
				System.out.println("Valid system parameters (p, g, q)");
			} else {
				throw new IllegalArgumentException("Invalid system parameters (p, g, q)");
			}
			if(ExistingKeysCheck(sk1, pk1)) {
				System.out.println("Valid keys (sk1, pk1)");
			} else {
				throw new IllegalArgumentException("Invalid system keys (sk1, pk1)");
			}
			
			GenerateNewKeys(new BigInteger("3"), new BigInteger("5"));
			
			System.out.println("Generated new ski-pki key-pairs");

			if(ExistingKeysCheck(sk2, pk2)) {
				System.out.println("Valid keys (sk2, pk2)");
			} else {
				throw new IllegalArgumentException("Invalid system keys (sk2, pk2)");
			}
			
			System.out.println("sk2 -> " + sk2);
			System.out.println("pk2 -> " + pk2);

			if(ExistingKeysCheck(sk3, pk3)) {
				System.out.println("Valid keys (sk3, pk3)");
			} else {
				throw new IllegalArgumentException("Invalid system keys (sk3, pk3)");
			}
			
			System.out.println("sk3 -> " + sk3);
			System.out.println("pk3 -> " + pk3);
			
			BigInteger key1 = new BigInteger("71");
			BigInteger key2 = new BigInteger("31");
			
			if(CheckKey(key1, q)) {
				System.out.println("Key1 OK -> " + key1);
			} else {
				throw new IllegalArgumentException("Invalid DSS key k1");
			}
			if(CheckKey(key2, q)) {
				System.out.println("Key2 OK -> " + key2);
			} else {
				throw new IllegalArgumentException("Invalid DSS key k2");
			}
			
			BigInteger message1 = GenerateMessage(pk1, pk2, BigInteger.ONE, "FULL");
			System.out.println("message1 created -> " + message1.toString());
			BigInteger message2 = GenerateMessage(pk2, pk3, BigInteger.ONE, "FULL");
			System.out.println("message2 created -> " + message2.toString());
			BigInteger simpleMessage1 = GenerateMessage(pk1, pk2, BigInteger.ONE, "SIMPLE");
			System.out.println("simpleMessage1 created -> " + simpleMessage1.toString());
			BigInteger simpleMessage2 = GenerateMessage(pk2, pk3, BigInteger.ONE, "SIMPLE");
			System.out.println("simpleMessage2 created -> " + simpleMessage2.toString());

			BigInteger[] Sig1 = dssModule.Sign(sk1, message1, p, q, g, key1);
			System.out.println("Sig1 created -> (" + Sig1[0] + ", " + Sig1[1] + ")");
			
			Boolean verified = dssModule.Verify(pk1, message1, p, q, g, Sig1);
			if(verified) {
				System.out.println("Sig1 verified");
				System.out.println("Transacting T1...");
				BigInteger T1 = transactModule.Transact(BigInteger.ONE, simpleMessage1, BigInteger.ONE);
				if(T1.compareTo(BigInteger.ZERO) == 0) {
					System.out.println("No preimage found for T1...");
				}
			}
			
			BigInteger[] Sig2 = dssModule.Sign(sk2, message2, p, q, g, key2);
			System.out.println("Sig2 created -> (" + Sig2[0] + ", " + Sig2[1] + ")");
			
			verified = dssModule.Verify(pk2, message2, p, q, g, Sig2);
			if(verified) {
				System.out.println("Sig2 verified");
				System.out.println("Transacting T2...");
				BigInteger T2 = transactModule.Transact(message1, simpleMessage2, BigInteger.ONE);
				if(T2.compareTo(BigInteger.ZERO) == 0) {
					System.out.println("No preimage found for T2...");
				}
			}
						
		} catch (IllegalArgumentException ex) {
			System.out.println(ex.toString());
		}
	}
	
	public static Boolean CheckKey(BigInteger key, BigInteger q) {
		Boolean result = true;
		try {
			key.modInverse(q);
			if(key.compareTo(BigInteger.ONE) == -1 || key.compareTo(q) != -1) {
				result = false;
			}
		} catch(ArithmeticException ex) {
			result = false;
			System.out.println("Key does not have an inverse modulo q");
		}
		return result;
	}
	
	public static BigInteger GenerateMessage(BigInteger pk1, BigInteger pk2, BigInteger amt, String type) {
		try {
			byte[] bytePK1 = pk1.toByteArray();
			byte[] bytePK2 = pk2.toByteArray();
			byte[] byteAmt = amt.toByteArray();
			
			if(type.equals("FULL")) {
				byte[] concatByte = new byte[bytePK1.length + bytePK2.length + byteAmt.length];
				System.arraycopy(bytePK1, 0, concatByte, 0, bytePK1.length);
				System.arraycopy(bytePK2, 0, concatByte, bytePK1.length, bytePK2.length);
				System.arraycopy(byteAmt, 0, concatByte, bytePK1.length + bytePK2.length, byteAmt.length);
				
				return new BigInteger(1, concatByte);
			} else if (type.equals("SIMPLE")) {
				byte[] concatByte = new byte[100];
				
				byte lastBytePK1 = bytePK1[49];
				byte firstBytePK2 = bytePK2[0];
				byte firstBitPK2 = (byte) ((firstBytePK2 >> 7) & 1);

				if(firstBitPK2 == 1) {
					lastBytePK1 = (byte) (lastBytePK1 | (1));
				} else {
					lastBytePK1 = (byte) (lastBytePK1 & ~(1));
				}
				bytePK1[49] = lastBytePK1;
				
				BigInteger shiftedPK2 = pk2.shiftLeft(1);
				byte[] shiftedBytePK2 = shiftedPK2.toByteArray();
				
				byte lastBytePK2 = shiftedBytePK2[49];
				lastBytePK2 = (byte) (lastBytePK2 | (1));
				lastBytePK2 = (byte) (lastBytePK2 & ~(1 << 1 ));
				shiftedBytePK2[49] = lastBytePK2;

				System.arraycopy(bytePK1, 0, concatByte, 0, 50);
				System.arraycopy(shiftedBytePK2, 0, concatByte, 50, 50);
				
				return new BigInteger(1, concatByte);
			} else {
				throw new IllegalArgumentException("Invalid message type for GenerateMessage.");
			}
		} catch(IllegalArgumentException ex) {
			System.out.println(ex.toString());
			return new BigInteger("-1");
		}
	}
	
	public static void GenerateNewKeys(BigInteger seed1, BigInteger seed2) {
		sk2 = seed1;
		sk3 = seed2;
		pk2 = g.modPow(sk2, p);
		pk3 = g.modPow(sk3, p);
	}
	
	public static Boolean ExistingKeysCheck(BigInteger sk, BigInteger pk) {
		Boolean result = true;
		BigInteger qMinus1 = q.subtract(new BigInteger("1"));

		if(sk.compareTo(BigInteger.ONE) == -1 || sk.compareTo(qMinus1) == 1) {
			result = false;
		}

		if(pk.compareTo(g.modPow(sk, p)) != 0) {
			result = false;
		}
		
		return result;
	}
	
	public static Boolean SystemParametersCheck() {
		Boolean result = true;
		BigInteger pMinus1 = p.subtract(BigInteger.ONE);
		BigInteger gOrder = g.modPow(q, p);
		
		if(!isPrime(p) || !isPrime(q)) {
			result = false;
		}
		
		if(p.bitLength() < 512 || p.bitLength() > 1024 || p.bitLength() % 64 != 0) {
			result = false;
		}
		
		if(pMinus1.mod(q).compareTo(BigInteger.ZERO) != 0 || q.bitLength() != 160) {
			result = false;
		}
			
		if(g.compareTo(BigInteger.ZERO) == -1 || g.compareTo(pMinus1) == 1 || gOrder.compareTo(BigInteger.ONE) != 0) {
			result = false;
		}

		return result;
	}
	
	public static Boolean isPrime(BigInteger num) {
		// with 99.22% certainty
		if(!num.isProbablePrime(7)) {
			return false;
		}
		return true;
	}
	
	public static void loadData() {
		p = new BigInteger("168199388701209853920129085113302407023173962717160229197318545484823101018386724351964316301278642143567435810448472465887143222934545154943005714265124445244247988777471773193847131514083030740407543233616696550197643519458134465700691569680905568000063025830089599260400096259430726498683087138415465107499");
		q = new BigInteger("959452661475451209325433595634941112150003865821");
		g = new BigInteger("94389192776327398589845326980349814526433869093412782345430946059206568804005181600855825906142967271872548375877738949875812540433223444968461350789461385043775029963900638123183435133537262152973355498432995364505138912569755859623649866375135353179362670798771770711847430626954864269888988371113567502852");
		sk1 = new BigInteger("432398415306986194693973996870836079581453988813");
		pk1 = new BigInteger("49336018324808093534733548840411752485726058527829630668967480568854756416567496216294919051910148686186622706869702321664465094703247368646506821015290302480990450130280616929226917246255147063292301724297680683401258636182185599124131170077548450754294083728885075516985144944984920010138492897272069257160");
	}
}