import java.math.BigInteger;
import java.security.SecureRandom;
import java.nio.charset.StandardCharsets;

public class Schnorr {

    public static class Signature {
        public final BigInteger z, h;
        public Signature(BigInteger z, BigInteger h) {
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
        final Edwards.Point G = curve.gen();

        // ---- Private key from passphrase: s = SHAKE-128(passphrase,32B) mod r; enforce xLSB(V)==0
        byte[] sBytes = new byte[32];
        SHA3SHAKE.SHAKE(128, passphrase.getBytes(StandardCharsets.UTF_8), 256, sBytes);
        BigInteger s = new BigInteger(1, sBytes).mod(r);
        Edwards.Point V = G.mul(s);
        if (V.getX().testBit(0)) {
            s = r.subtract(s);
            V = V.negate();
        }

        BigInteger k;
        do {
            k = new BigInteger(r.bitLength(), RNG).mod(r);
        } while (k.signum() == 0);

        Edwards.Point U = G.mul(k);

        byte[] hyInput = concat(toUnsignedFixed(U.y, 32), message);
        byte[] hDigest = new byte[32];
        SHA3SHAKE.SHA3(256, hyInput, hDigest);
        BigInteger h = new BigInteger(1, hDigest).mod(r);

        BigInteger z = k.subtract(h.multiply(s)).mod(r);

        return new Signature(z, h);
    }

    /**
     * Verify Schnorr signature (z,h) on message with public key V.
     */
    public boolean verify(byte[] message, Edwards curve, Edwards.Point V, BigInteger z, BigInteger h) {
        final BigInteger r = curve.getR();
        final Edwards.Point G = curve.gen();

        Edwards.Point Uprime = G.mul(z).add(V.mul(h));

        byte[] hyInput = concat(toUnsignedFixed(Uprime.y, 32), message);
        byte[] hDigest = new byte[32];
        SHA3SHAKE.SHA3(256, hyInput, hDigest);
        BigInteger hPrime = new BigInteger(1, hDigest).mod(r);

        return hPrime.equals(h.mod(r));
    }

    // -------- helpers --------

    /** Big-endian unsigned fixed-length encoding for BigInteger. */
    private static byte[] toUnsignedFixed(BigInteger v, int len) {
        byte[] src = v.toByteArray(); // may contain a leading 0x00
        if (src.length == len) return src;
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