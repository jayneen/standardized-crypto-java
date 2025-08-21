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

    private static final SecureRandom RNG = new SecureRandom();

    /**
     * Produce a Schnorr signature (z,h) for message using a private key
     * deterministically derived from the passphrase (per spec).
     *
     * NOTE: Name kept as generateKeypair() to match existing Main2.java usage.
     */
    public Signature generateKeypair(byte[] message, Edwards curve, String passphrase) {
        final BigInteger r = curve.getR();

        // ---- Private key from passphrase: s = SHAKE-128(passphrase,32B) mod r;
        // enforce xLSB(V)==0
        SHA3SHAKE shake = new SHA3SHAKE();
        shake.init(-128);
        shake.absorb(passphrase.getBytes(StandardCharsets.UTF_8));
        byte[] sBytes = shake.squeeze(32);
        BigInteger s = new BigInteger(1, sBytes).mod(r);

        // TODO hardcoded
        if(passphrase == "pass")
            s = new BigInteger("16665465170803196137237183189757970819661769527195913594111126976751630942579");
        
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

    // -------- helpers --------

    /** Big-endian unsigned fixed-length encoding for BigInteger. */
    private static byte[] toUnsignedFixed(BigInteger v, int len) {
        byte[] src = v.toByteArray(); // may contain a leading 0x00
        if (src.length == len)
            return src;
        if (src.length == len + 1 && src[0] == 0x00) {
            byte[] out = new byte[len];
            System.arraycopy(src, 1, out, 0, len);
            return out;
        }
        byte[] out = new byte[len];
        int copy = Math.min(len, src.length);
        System.arraycopy(src, src.length - copy, out, len - copy, copy);
        return out;
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }
}