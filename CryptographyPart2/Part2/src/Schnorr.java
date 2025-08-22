import java.math.BigInteger;
import java.security.SecureRandom;
import java.nio.charset.StandardCharsets;

public class Schnorr {

    public static class Signature {
        public final BigInteger z, h;

        public Signature(BigInteger h, BigInteger z) {
            this.z = z;
            this.h = h;
        }
    }

    /**
     * Produce a Schnorr signature (z,h) for message using a private key
     * deterministically derived from the passphrase (per spec).
     */
    public Signature generateKeypair(byte[] message, Edwards curve, String passphrase) {
        final BigInteger r = curve.getR();
        SHA3SHAKE shake = new SHA3SHAKE();
        shake.init(-128);
        shake.absorb(passphrase.getBytes(StandardCharsets.UTF_8));
        byte[] sBytes = shake.squeeze(64);
        BigInteger s = new BigInteger(sBytes).mod(r);
        byte[] nonce = new byte[32];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(nonce);
        BigInteger k = new BigInteger(nonce);
        k = k.mod(curve.getR());
        Edwards.Point U = curve.gen().mul(k);
        SHA3SHAKE sha = new SHA3SHAKE();
        sha.init(256);
        sha.absorb(U.y.toByteArray());
        sha.absorb(message);
        byte[] byteH = sha.digest();
        BigInteger h = new BigInteger(byteH);
        h = h.mod(curve.getR());
        BigInteger Z = k.subtract(h.multiply(s)).mod(curve.getR());

        return new Signature(h, Z);
    }

    /**
     * Verify Schnorr signature (z,h) on message with public key V.
     */
    public boolean verify(byte[] message, Edwards curve, Edwards.Point V, Signature sign) {
        final BigInteger r = curve.getR();
        final Edwards.Point G = curve.gen();

        Edwards.Point Uprime = G.mul(sign.z).add(V.mul(sign.h));
        SHA3SHAKE sha = new SHA3SHAKE();
        sha.init(256);
        sha.absorb(Uprime.y.toByteArray());
        sha.absorb(message);
        byte[] byteH = sha.digest();
        BigInteger hP = new BigInteger(byteH);
        hP = hP.mod(curve.getR());

        return hP.equals(sign.h);
    }

    
}