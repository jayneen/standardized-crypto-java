/*
depreciated code, to be removed

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.SecureRandom;

public class Schnorr
{
    //Probably the whole thing
    public void generateKeypair(byte[] theMessage, Edwards theCurve, String thePassphrase)
    {
        //I think I'll use this later
        BigInteger r = theCurve.r;
        Edwards.Point G = theCurve.gen();

        //Find private key, s, from passphrase
        SHA3SHAKE shake = new SHA3SHAKE();
        shake.absorb(thePassphrase.getBytes());
        byte[] sBytes = shake.squeeze(32);
        BigInteger s = new BigInteger(1, sBytes).mod(r);
        Edwards.Point V = G.mul(s);

        //Ensure x-coordinate LSB of public key is 0
        if (V.x.testBit(0))
        {
            s = r.subtract(s);
            V = V.negate();
        }

        //Generate a random nonce, k
        SecureRandom rngesus = new SecureRandom();
        int rbytes = (E.r.bitLength() + 7) >> 3;
        BigInteger k = new BigInteger(new SecureRandom().generateSeed(rbytes << 1)).mod(Edwards.r);
        Edwards.Point U = G.mul(k);

        //Compute h = H(Uy || theMessage)
        byte[] Uy = U.y.toByteArray();
        ByteArrayOutputStream temp = new ByteArrayOutputStream();
        temp.write(Uy);
        temp.write(theMessage);
        byte[] input = temp.toByteArray();
        byte[] hashOutput = SHA3SHAKE.SHA3(256, input, null);
        BigInteger h = new BigInteger(1, hashOutput).mod(r);

        //Compute z = (k - h * s) mod r
        BigInteger z = k.subtract(h.multiply(s)).mod(r);

        //TODO
        //I now have a keypair? I dont know what to return, h and z.
    }

    //maybe more
    public boolean verify(byte[] theMessage, Edwards.Point V, Edwards theCurve, BigInteger z, BigInteger h)
    {
        BigInteger r = theCurve.r;
        //I dont know what the methods are called yet
        Edwards.Point G = theCurve.gen();

        //Compute U' = z·G + h·V
        Edwards.Point U_prime = G.mul(z).add(V.mul(h));

        //Compute h' = H(U'y || theMessage)
        byte[] UyPrime = U_prime.y.toByteArray();
        ByteArrayOutputStream temp = new ByteArrayOutputStream();
        temp.write(UyPrime);
        temp.write(theMessage);
        byte[] input = temp.toByteArray();
        byte[] digest = SHA3SHAKE.SHA3(256, input, null);
        BigInteger hPrime = new BigInteger(1, digest).mod(r);

        return hPrime.equals(h);
    }
}*/

import java.math.BigInteger;
import java.security.SecureRandom;

public class Schnorr {

    public static class Signature {
        public final BigInteger z, h;
        public Signature(BigInteger z, BigInteger h) {
            this.z = z;
            this.h = h;
        }
    }

    public Signature generateKeypair(byte[] message, Edwards curve, String passphrase) {
        BigInteger r = curve.getR();
        Edwards.Point G = curve.gen();

        // Private key from passphrase
        SHA3SHAKE shake = new SHA3SHAKE();
        shake.absorb(passphrase.getBytes());
        byte[] sBytes = shake.squeeze(32);
        BigInteger s = new BigInteger(1, sBytes).mod(r);
        Edwards.Point V = G.mul(s);

        if (V.getX().testBit(0)) {
            s = r.subtract(s);
            V = V.negate();
        }

        // Generate random nonce
        SecureRandom rng = new SecureRandom();
        BigInteger k = new BigInteger(r.bitLength() + 64, rng).mod(r);
        Edwards.Point U = G.mul(k);

        // h = H(U.y || message)
        byte[] input = concat(U.y.toByteArray(), message);
        byte[] hashOutput = SHA3SHAKE.SHA3(256, input, null);
        BigInteger h = new BigInteger(1, hashOutput).mod(r);

        // z = (k - h·s) mod r
        BigInteger z = k.subtract(h.multiply(s)).mod(r);

        return new Signature(z, h);
    }

    public boolean verify(byte[] message, Edwards.Point V, Edwards curve, BigInteger z, BigInteger h) {
        BigInteger r = curve.getR();
        Edwards.Point G = curve.gen();

        // U' = z·G + h·V
        Edwards.Point U_prime = G.mul(z).add(V.mul(h));

        // h' = H(U'.y || message)
        byte[] input = concat(U_prime.y.toByteArray(), message);
        byte[] digest = SHA3SHAKE.SHA3(256, input, null);
        BigInteger hPrime = new BigInteger(1, digest).mod(r);

        return hPrime.equals(h);
    }

    private byte[] concat(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }
}

