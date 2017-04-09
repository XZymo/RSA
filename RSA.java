/**
 * This library implements the Rivest-Shamir-Adelman public key encryption scheme.
 * Converts bytes to BigInteger for applying the corresponding operations. This is not
 * intended for practical use even if paired with a secure truely-random seed. (see line 45)
 * Serves as an RSA library for educational purposes.
 *
 *	@author Daniel Fitzhenry
 *	@date	30/01/2017
**/
//package Security; <- enter requried classpath

import java.math.BigInteger;
import java.security.SecureRandom;
import java.nio.ByteBuffer;
import java.io.InputStreamReader;
import java.io.BufferedReader;
import java.io.IOException;

public class RSA{
	
	/** Secure PRG (psuedo-safe)
	 */
	private SecureRandom generator;
	
	/** Private and public exponents d, e, respcetively, and RSA modulus N
	 */
	private BigInteger d, e, N;
	
	/** The bit length of our primes.
	 */
	private final int SIZE;

	/**CONSTRUCTOR
	 *	Generates keys for the encryption scheme.
	 *	Notice these keys can only be generated/set
	 *	at instantiation (i.e. safer to construct new instance
	 *	if new keys are necessary)
	 *	@param	int bitLength
	 **/
	public RSA(int bitLength){
		SIZE = bitLength;
		
		// Initializes pseudo-safe random generator (constrained by seed-generation).
		/** See SecureRandom(SecureRandomSpi secureRandomSpi, Provider provider) **/
		generator = new SecureRandom(ByteBuffer.allocate(Long.SIZE / Byte.SIZE).putLong(System.nanoTime()).array());
		
		// Instantiate two distinct SIZE-bit prime numbers p, q and modulus ɸ(N)
		BigInteger p, q, P;
		
		// Efficiently distiguish q and p → q ≠ p
		p = new BigInteger(SIZE, 10, generator);
		do { q = new BigInteger(SIZE, 10, generator); } 
		while (q.compareTo(p) == 0);

		// RSA MODULUS: N = p * q
		N = p.multiply(q);

		// ɸ(N): P = (p-1) * (q-1)
		P = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));

		// PUBLIC EXPONENT: e → e┴P && e < P
		do { e = new BigInteger(2*SIZE, generator); }
		while (lessAndCoprime(e,P));
		
		// PRIVATE EXPONENT: d = e^-1 mod P (modular inverse e with respect to ɸ(N))
		d = e.modInverse(P);
		
		// Discard p, q and ɸ(N) to secure scheme (CRUSIAL)
		p = q = P = null;
	}
	
	/**GET
	 *	Getter functions
	 **/
	public byte[] gete() { return e.toByteArray(); }
	public byte[] getN() { return N.toByteArray(); }
	
	/**ENCRYPT
	 *	This method signs a plaintext m,
	 *	using e and N by efficient modular exponentiation
	 *	@param	BigInteger m
	 *	@return	BigInteger ciphertext
	 **/
	public BigInteger encrypt(BigInteger m){ return m.modPow(e, N); }
	
	/**SIGN
	 *	This method signs a plaintext m,
	 *	using another's exponent and modulus
	 *	by efficient modular exponentiation
	 *	@param	BigInteger m
	 *	@param	BigInteger exp
	 *	@param	BigInteger mod
	 *	@return	BigInteger ciphertext
	 **/
	public BigInteger sign(BigInteger m, BigInteger exp, BigInteger mod){ return m.modPow(exp, mod); }
	
	/**SIGNBYTES
	 *	This method signs a plaintext m in bytes,
	 *	with a given exponent exp and modulus mod
	 *	by efficient modular exponentiation
	 *	@param	byte[] m
	 *	@param	byte[] exp
	 *	@param	byte[] mod
	 *	@return	byte[] ciphertext
	 **/
	public byte[] sign(byte[] m, byte[] exp, byte[] mod){
		return parseBackBytes(parse(m).modPow(parse(exp), parse(mod)));
	}
	
	/**DECRYPT
	 *	This method decrypts a ciphertext c,
	 *	using d and N by efficient modular exponentiation
	 *	*NOTE* can only decipher c signed by THIS RSA public key!
	 *	@param	BigInteger c
	 *	@return	BigInteger plaintext
	 **/
	public BigInteger decrypt(BigInteger c){ return c.modPow(d, N); }
	
	/**PARSE
	 *	This method parses any inputted string
	 *	into a plaintext message if the string
	 *	is not null or empty otherwise returns message 0.
	 *	@param	String input
	 *	@return	BigInteger plaintext
	 **/
	public BigInteger parse(String input){
		if (input == null || input.isEmpty()) return BigInteger.ZERO;
		return new BigInteger(input.getBytes());
	}
	/**
	 *	This method parses any inputted byte array
	 *	into a plaintext message if the byte array
	 *	is not null or empty otherwise returns message 0.
	 *	@param	byte[] input
	 *	@return	BigInteger plaintext
	 **/
	public BigInteger parse(byte[] input){
		if (input == null || input.length == 0) return BigInteger.ZERO;
		return new BigInteger(input);
	}
	
	/**PARSEBACKSTRING
	 *	This method parses any BigInteger
	 *	back into a String
	 *	@param	BigInteger input
	 *	@return	String plaintext
	 **/
	public String parseBackString(BigInteger input){
		if (input == null) return "";
		return new String(input.toByteArray());
	}
	
	/**PARSEBACKBYTES
	 *	This method parses any BigInteger
	 *	back into an array of bytes
	 *	@param	BigInteger input
	 *	@return	byte[] plaintext
	 **/
	public byte[] parseBackBytes(BigInteger input){
		if (input == null) return "".getBytes();
		return input.toByteArray();
	}

	/**LESSANDCOPRIME
	 *	This method checks if a given number
	 *	is less than and coprime to a given modulus
	 *	@param	BigInteger m
	 *	@param	BigInteger mod
	 *	@return	boolean (m < mod && m ┴ mod)
	 **/
	private boolean lessAndCoprime(BigInteger m, BigInteger mod){
		return (m.compareTo(mod) != -1) || (m.gcd(mod).compareTo(BigInteger.ONE) != 0);
	}
	
	/**TOSTRING
	 *	@return	String
	 **/
	@Override
	public String toString(){
		// Publish e and N. In practice, not d
		return "\nN = " + N.toString()+"\n\ne = " + e.toString()+"\n\nd = " + d.toString()+"\n\n";
	}
	
	/**GETINPUT
	 *	safely get input from stdin (FOR TERMINAL)
	 *	@return	BigInteger representation of input signable by this RSA object
	 **/
	public BigInteger getInput() throws IOException{
		BigInteger m;
		do {
			System.out.println("Enter a message (m less than and coprime to N):");
			m = parse((new BufferedReader(new InputStreamReader(System.in))).readLine());
			System.out.println("\nencoded:\n" + m.toString()+"\n");
		} while (lessAndCoprime(m,N));
		return m;
	}

	/** MAIN **
	 *	For testing purposes, demonstrates usage
	 *	@param	String argv[]
	 **/
	public static void main(String[] argv){
		BigInteger ciphertext, plaintext, message;
		long start, result;
		
		// TEST
		System.out.print("Initializing encryptor...");
		start = System.nanoTime();
		
		RSA encryptor = new RSA(2048);
		
		result = System.nanoTime() - start;
		// RESULT
		System.out.println("done! That took "+ result * 1e-9 +" seconds.\n"+encryptor);

		try	{
			message = encryptor.getInput();

			// sign using this encryptor's public key.
			ciphertext = encryptor.encrypt(message);

			// decrypt using this encryptor's private exponent 
			plaintext = encryptor.decrypt(ciphertext);

			System.out.println("ciphertext (m → c):\n" + ciphertext.toByteArray().length+"\n");
			System.out.println("plaintext (c → m):\n" + plaintext.toByteArray().length+"\n");

			System.out.println("Eciphered:\n" + encryptor.parseBackString(ciphertext)+"\n");
			System.out.println("Deciphered:\n" + encryptor.parseBackString(plaintext)+"\n");
			System.out.println("Plantext == Original message..."+((plaintext.equals(message))?"TRUE!":"Oops..."));
			System.out.print("Ciphertext == Signed with (e, N)...");
			System.out.println(((ciphertext.equals(new BigInteger(encryptor.sign(plaintext.toByteArray(), encryptor.gete(), encryptor.getN()))))?"TRUE!":"Oops..."));
		} catch (IOException e) {
			System.err.print(e);
			e.printStackTrace();
		}
	}
	/**/
}