import java.math.BigInteger;

public class Edwards {

    private static final BigInteger P; // p = 2^256 - 189

    private static final BigInteger D; // d = 15343

    private final BigInteger r;


    //Initialize the Prime modulus and the curve parameter
    static {
        P = BigInteger.ONE.shiftLeft(256).subtract(BigInteger.valueOf(189));

        D = BigInteger.valueOf(15343);
    }

    public Edwards() {
        r = BigInteger.ONE.shiftLeft(254).subtract(new BigInteger(
                "87175310462106073678594642380840586067"));
    }

    /**
     * Determine if a given affine coordinate pair P = (x,y)
     * defines a point on the curve
     *
     * @param x x-coordinate of presumed point on the curve
     * @param y y-coordinate of presumed point on the curve
     * @return whether P is really a point on the curve
     */
    public boolean isPoint(BigInteger x, BigInteger y) {
        x = x.mod(P);
        y = y.mod(P);
        final BigInteger x2 = x.multiply(x).mod(P);
        final BigInteger y2 = y.multiply(y).mod(P);
        final BigInteger leftHandSide = x2.add(y2).mod(P);
        final BigInteger rightHandSide =
                BigInteger.ONE.add(D.multiply(x2).mod(P).multiply(y2).mod(P)).mod(P);

        return leftHandSide.equals(rightHandSide);
    }

    /**
     * Create a point from its y-coordinate and the least significant bit (LSB) of its
     * x-coordinate.
     *
     * @param y        the y-coordinate of the desired point.
     * @param x_hasLSB the LSB of its x-coordinate
     * @return point (x,y) if it exists and has order r, otherwise the neutral element O =
     * (0,1)
     */
    public Point getPoint(BigInteger y, Boolean x_hasLSB) {
        y = y.mod(P);

        final BigInteger y2 = y.multiply(y).mod(P);
        final BigInteger num = BigInteger.ONE.subtract(y2).mod(P);
        final BigInteger den = BigInteger.ONE.subtract(D.multiply(y2).mod(P)).mod(P);

        if (den.signum() == 0) {
            return new Point();
        }

        //Will be used to take the square root of to recover x from y
        final BigInteger value = num.multiply(den.modInverse(P)).mod(P);

        final BigInteger x = sqrt(value, P, x_hasLSB);

        if (x == null) {
            return new Point();
        }

        //The point class
        final Point pnt = new Point(x, y);

        if (!isPoint(pnt.x, pnt.y)) {
            return new Point();
        }

        if (!pnt.mul(r).isZero()) {
            return new Point();
        }

        return pnt;

    }

    /**
     * Fine a generator G on the curve with the smallest possible y-coordinate in absoulte
     * value.
     *
     * @return G.
     */
    public Point gen() {
        final BigInteger y0 = P.subtract(BigInteger.valueOf(4)).mod(P);
        return getPoint(y0, false);
    }

    public static BigInteger sqrt(BigInteger value, BigInteger p, boolean hasLSB) {
        //assert p mod 4 == 3

        //Checks if the first 2 bits are 1, if not throw exception
        if (!(p.testBit(0) && p.testBit(1))) {
            throw new IllegalArgumentException("p % 4 != 3");
        }
        value = value.mod(P);

        if (value.signum() == 0) {
            return BigInteger.ZERO;
        }

        BigInteger r = value.modPow(p.shiftRight(2).add(BigInteger.ONE), p);

        if (r.testBit(0) != hasLSB) {
            r = p.subtract(r);
        }

        return r.multiply(r).subtract(value).mod(p).signum() == 0 ? r : null;
    }

    //getter for schnorr
    public BigInteger getR() {
        return r;
    }

    public static class Point {

    private final BigInteger x;
    final BigInteger y;
    private final boolean isZero;

    // private static final BigInteger P = BigInteger.valueOf(2).pow(256).subtract(BigInteger.valueOf(189));
    // private static final BigInteger D = BigInteger.valueOf(15343);

    /**
     * Create a copy of the neutral element on this curve.
     */
    public Point() {
        this.x = BigInteger.ZERO;
        this.y = BigInteger.ONE;
        this.isZero = true;
    }

    /**
     * Create a point from its coordinates (assuming
     * these coordinates really define a point on the curve).
     *
     * @param x the x-coordinate of the desired point
     * @param y the y-coordinate of the desired point
     */
    private Point(BigInteger x, BigInteger y) {
        this.x = x.mod(P);
        this.y = y.mod(P);
        this.isZero = this.x.equals(BigInteger.ZERO) && this.y.equals(BigInteger.ONE);
    }

    /**
     * Determine if this point is the neutral element O on the curve.
     *
     * @return true iff this point is O
     */
    public boolean isZero() {
        return this.isZero;
    }

    /**
     * Determine if a given point P stands for
     * the same point on the curve as this.
     *
     * @param P a point (presumably on the same curve as this)
     * @return true iff P stands for the same point as this
     */
    public boolean equals(Point P) {
        if (this.isZero && P.isZero) {
            return true;
        }
        return this.x.equals(P.x) && this.y.equals(P.y);
    }

    /**
     * Given a point P = (x, y) on the curve,
     * return its opposite -P = (-x, y).
     *
     * @return -P
     */
    public Point negate() {
        if (isZero) {
            return this;
        }
        return new Point(x.negate().mod(P), y);
    }

    /**
     * Add two given points on the curve, this and P.
     *
     * @param Q a point on the curve
     * @return this + P
     */
    public Point add(Point Q) {
        if (this.isZero)
            return Q;
        if (Q.isZero)
            return this;

        BigInteger x1 = this.x;
        BigInteger y1 = this.y;
        BigInteger x2 = Q.x;
        BigInteger y2 = Q.y;

        BigInteger x1x2 = x1.multiply(x2).mod(P);
        BigInteger y1y2 = y1.multiply(y2).mod(P);
        BigInteger x1y2 = x1.multiply(y2).mod(P);
        BigInteger y1x2 = y1.multiply(x2).mod(P);
        BigInteger dxxyy = D.multiply(x1x2).multiply(y1y2).mod(P);

        BigInteger numeratorX = x1y2.add(y1x2).mod(P);
        BigInteger denominatorX = BigInteger.ONE.add(dxxyy).mod(P);

        BigInteger numeratorY = y1y2.subtract(x1x2).mod(P);
        BigInteger denominatorY = BigInteger.ONE.subtract(dxxyy).mod(P);

        BigInteger invDenX = denominatorX.modInverse(P);
        BigInteger invDenY = denominatorY.modInverse(P);

        BigInteger x3 = numeratorX.multiply(invDenX).mod(P);
        BigInteger y3 = numeratorY.multiply(invDenY).mod(P);

        return new Point(x3, y3);
    }

    /**
     * Multiply a point P = (x, y) on the curve by a scalar m.
     *
     * @param m a scalar factor (an integer mod the curve order)
     * @return m*P
     */
    public Point mul(BigInteger m) {
        Point result = new Point();
        Point base = this;

        while (m.signum() > 0) {
            if (m.testBit(0)) {
                result = result.add(base);
            }
            base = base.add(base);
            m = m.shiftRight(1);
        }

        return result;
    }

    //getter for schnorr
    public BigInteger getX() {
        return x;
    }
    /**
     * Display a human-readable representation of this point.
     *
     * @return a string of form "(x, y)" where x and y are
     *         the coordinates of this point
     */
    public String toString() {
        return "(" + x.toString() + ", " + y.toString() + ")";
    }
}

}
