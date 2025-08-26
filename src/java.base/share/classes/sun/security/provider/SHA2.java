/*
 * Copyright (c) 2002, 2023, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Oracle designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Oracle in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */

package sun.security.provider;

import java.util.Arrays;
import java.util.Objects;

import jdk.internal.util.Preconditions;
import jdk.internal.vm.annotation.IntrinsicCandidate;
import static sun.security.provider.ByteArrayAccess.*;

/**
 * This class implements the Secure Hash Algorithm SHA-256 developed by
 * the National Institute of Standards and Technology along with the
 * National Security Agency.
 *
 * <p>It implements java.security.MessageDigestSpi, and can be used
 * through Java Cryptography Architecture (JCA), as a pluggable
 * MessageDigest implementation.
 *
 * @since       1.4.2
 * @author      Valerie Peng
 * @author      Andreas Sterbenz
 */
abstract class SHA2 extends DigestBase {

    private static final int ITERATION = 64;
    private static final int BLOCKSIZE = 64;
    // Constants for each round
    private static final int[] ROUND_CONSTS = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };

    // buffer used by implCompress()
    private int[] W;

    // state of this object
    private int[] state;

    // initial state value. different between SHA-224 and SHA-256
    private final int[] initialHashes;

    /**
     * Creates a new SHA object.
     */
    SHA2(String name, int digestLength, int[] initialHashes) {
        super(name, digestLength, BLOCKSIZE);
        this.initialHashes = initialHashes;
        state = new int[8];
        resetHashes();
    }

    /**
     * Resets the buffers and hash value to start a new hash.
     */
    void implReset() {
        resetHashes();
        if (W != null) {
            Arrays.fill(W, 0);
        }
    }

    private void resetHashes() {
        System.arraycopy(initialHashes, 0, state, 0, state.length);
    }

    void implDigest(byte[] out, int ofs) {
        long bitsProcessed = bytesProcessed << 3;

        int index = (int)bytesProcessed & 0x3f;
        int padLen = (index < 56) ? (56 - index) : (120 - index);
        engineUpdate(padding, 0, padLen);

        i2bBig4((int)(bitsProcessed >>> 32), buffer, 56);
        i2bBig4((int)bitsProcessed, buffer, 60);
        implCompress(buffer, 0);

        i2bBig(state, 0, out, ofs, engineGetDigestLength());
    }


    protected void implDigestFixedLengthPreprocessed(
            byte[] input, int inLen, byte[] output, int outOffset, int outLen) {
        implReset();

        for (int ofs = 0; ofs < inLen; ofs += BLOCKSIZE) {
            implCompress0(input, ofs);
        }
        i2bBig(state, 0, output, outOffset, outLen);
    }

    /**
     * Process the current block to update the state variable state.
     */
    void implCompress(byte[] buf, int ofs) {
        implCompressCheck(buf, ofs);
        implCompress0(buf, ofs);
    }

    private void implCompressCheck(byte[] buf, int ofs) {
        Objects.requireNonNull(buf);

        // Checks similar to those performed by the method 'b2iBig64'
        // are sufficient for the case when the method 'implCompress0' is
        // replaced with a compiler intrinsic.
        Preconditions.checkFromIndexSize(ofs, BLOCKSIZE, buf.length, Preconditions.AIOOBE_FORMATTER);
    }

    // The method 'implCompressImpl' seems not to use its parameters.
    // The method can, however, be replaced with a compiler intrinsic
    // that operates directly on the array 'buf' (starting from
    // offset 'ofs') and not on array 'W', therefore 'buf' and 'ofs'
    // must be passed as parameter to the method.
    @IntrinsicCandidate
    private void implCompress0(byte[] buf, int ofs) {
        if (W == null) {
            W = new int[64];
        }
        b2iBig64(buf, ofs, W);
        // The first 16 ints are from the byte stream, compute the rest of
        // the W[]'s
        for (int t = 16; t < ITERATION; t++) {
            int W_t2 = W[t - 2];
            int W_t15 = W[t - 15];

            // S(x,s) is right rotation of x by s positions:
            //   S(x,s) = (x >>> s) | (x << (32 - s))
            // R(x,s) is right shift of x by s positions:
            //   R(x,s) = (x >>> s)

            // delta0(x) = S(x, 7) ^ S(x, 18) ^ R(x, 3)
            int delta0_W_t15 =
                    Integer.rotateRight(W_t15, 7) ^
                    Integer.rotateRight(W_t15, 18) ^
                     (W_t15 >>>  3);

            // delta1(x) = S(x, 17) ^ S(x, 19) ^ R(x, 10)
            int delta1_W_t2 =
                    Integer.rotateRight(W_t2, 17) ^
                    Integer.rotateRight(W_t2, 19) ^
                     (W_t2 >>> 10);

            W[t] = delta0_W_t15 + delta1_W_t2 + W[t-7] + W[t-16];
        }

        int a = state[0];
        int b = state[1];
        int c = state[2];
        int d = state[3];
        int e = state[4];
        int f = state[5];
        int g = state[6];
        int h = state[7];

        for (int i = 0; i < ITERATION; i++) {
            // S(x,s) is right rotation of x by s positions:
            //   S(x,s) = (x >>> s) | (x << (32 - s))

            // sigma0(x) = S(x,2) xor S(x,13) xor S(x,22)
            int sigma0_a =
                    Integer.rotateRight(a, 2) ^
                    Integer.rotateRight(a, 13) ^
                    Integer.rotateRight(a, 22);

            // sigma1(x) = S(x,6) xor S(x,11) xor S(x,25)
            int sigma1_e =
                    Integer.rotateRight(e, 6) ^
                    Integer.rotateRight(e, 11) ^
                    Integer.rotateRight(e, 25);

            // ch(x,y,z) = (x and y) xor ((complement x) and z)
            //           = z xor (x and (y xor z));
            int ch_efg = g ^ (e & (f ^ g));

            // maj(x,y,z) = (x and y) xor (x and z) xor (y and z)
            //            = (x and y) xor ((x xor y) and z)
            int maj_abc = (a & b) ^ ((a ^ b) & c);

            int T1 = h + sigma1_e + ch_efg + ROUND_CONSTS[i] + W[i];
            int T2 = sigma0_a + maj_abc;
            h = g;
            g = f;
            f = e;
            e = d + T1;
            d = c;
            c = b;
            b = a;
            a = T1 + T2;
        }

        state[0] += a;
        state[1] += b;
        state[2] += c;
        state[3] += d;
        state[4] += e;
        state[5] += f;
        state[6] += g;
        state[7] += h;
    }

    public Object clone() throws CloneNotSupportedException {
        SHA2 copy = (SHA2) super.clone();
        copy.state = copy.state.clone();
        copy.W = null;
        return copy;
    }

    /**
     * SHA-224 implementation class.
     */
    public static final class SHA224 extends SHA2 {
        private static final int[] INITIAL_HASHES = {
            0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
            0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4
        };

        public SHA224() {
            super("SHA-224", 28, INITIAL_HASHES);
        }
    }

    /**
     * SHA-256 implementation class.
     */
    public static final class SHA256 extends SHA2 {

        // === policy/thresholds (no FIPS logic) ===
        private static final boolean gpuEnabled;
        private static final int     gpuThresholdBytes;   // offload only when total >= this
        private static final int     gpuMaxStageBytes;    // cap staging to avoid huge allocations

        static {
            boolean enabled = true;
            try {
                // manual kill-switch if you need to force CPU for A/B testing
                String dis = System.getProperty("com.ibm.crypto.gpu.disable", "false");
                if ("true".equalsIgnoreCase(dis)) enabled = false;
            } catch (SecurityException ignored) {}
            gpuEnabled = enabled;

            int thr = 64 * 1024;             // default: 64 KiB
            int cap = 256 * 1024 * 1024;     // default: 256 MiB
            try {
                thr = Integer.getInteger("com.ibm.crypto.gpu.threshold", thr);
                cap = Integer.getInteger("com.ibm.crypto.gpu.maxStaging", cap);
            } catch (SecurityException ignored) {}
            gpuThresholdBytes = Math.max(0, thr);
            gpuMaxStageBytes  = Math.max(64 * 1024, cap);
        }

        // === CUDA4J reflection handles ===
        private static volatile boolean rtReady = false;
        private static volatile boolean rtTried = false;

        private static Class<?> devClz, modClz, kerClz, bufClz, gridClz, streamClz;
        private static java.lang.reflect.Constructor<?> devCtor, modFromBytesCtor, kerFromModCtor, bufCtor, gridCtor;
        private static java.lang.reflect.Method launchM, copyFromM, copyToM, closeM, syncM;

        private static Object device;   // CudaDevice
        private static Object module;   // CudaModule
        private static Object kernel;   // CudaKernel (function "sha256_blocks")
        private static Object stream;   // optional CudaStream (not strictly required)

        // === per-instance staging while we consider GPU ===
        private byte[] stageBuf;
        private int    stageLen;
        private boolean staging;

        public SHA256() {
            super("SHA-256", 64, 32); // blockLen=64, digestLen=32
            staging = gpuEnabled;
            if (staging) {
                stageBuf = new byte[8192];
                stageLen = 0;
            }
        }

        @Override
        protected void engineUpdate(byte input) {
            if (staging) {
                if (!appendStage(input)) {
                    // exceeded staging cap: replay to CPU path and continue on CPU
                    byte[] prev = drainStage();
                    abandonStaging();
                    super.engineUpdate(prev, 0, prev.length);
                    super.engineUpdate(input);
                }
                return;
            }
            super.engineUpdate(input);
        }

        @Override
        protected void engineUpdate(byte[] b, int off, int len) {
            if (staging) {
                if (!appendStage(b, off, len)) {
                    byte[] prev = drainStage();
                    abandonStaging();
                    super.engineUpdate(prev, 0, prev.length);
                    super.engineUpdate(b, off, len);
                }
                return;
            }
            super.engineUpdate(b, off, len);
        }

        @Override
        void implDigest(byte[] out, int ofs) {
            if (!staging) {
                // already streaming through CPU => finish on CPU
                super.implDigest(out, ofs);
                return;
            }

            // GPU candidate: we buffered the entire message
            byte[] data = drainStage();

            if (data.length < gpuThresholdBytes || !ensureRuntime()) {
                // too small or GPU not ready => replay into CPU path and finish
                super.implReset();
                super.engineUpdate(data, 0, data.length);
                super.implDigest(out, ofs);
                return;
            }

            try {
                byte[] digest = gpuDigestWholeMessage(data);
                System.arraycopy(digest, 0, out, ofs, 32);
            } catch (Throwable t) {
                // any issue => safe CPU fallback
                super.implReset();
                super.engineUpdate(data, 0, data.length);
                super.implDigest(out, ofs);
            } finally {
                reset(); // clear staging state
            }
        }

        @Override
        void implReset() {
            super.implReset();
            if (stageBuf != null) java.util.Arrays.fill(stageBuf, (byte)0);
            stageLen = 0;
        }

        // ---------- staging helpers ----------
        private boolean appendStage(int b) {
            if (stageLen >= gpuMaxStageBytes) return false;
            ensureStage(1);
            stageBuf[stageLen++] = (byte)(b & 0xFF);
            return true;
        }
        private boolean appendStage(byte[] a, int off, int len) {
            long need = (long)stageLen + len;
            if (need > gpuMaxStageBytes) return false;
            ensureStage(len);
            System.arraycopy(a, off, stageBuf, stageLen, len);
            stageLen += len;
            return true;
        }
        private void ensureStage(int add) {
            int need = stageLen + add;
            if (need <= stageBuf.length) return;
            int n = Math.max(stageBuf.length << 1, need);
            stageBuf = java.util.Arrays.copyOf(stageBuf, n);
        }
        private byte[] drainStage() {
            byte[] out = java.util.Arrays.copyOf(stageBuf, stageLen);
            stageLen = 0;
            return out;
        }
        private void abandonStaging() {
            staging = false;
            stageBuf = null;
            stageLen = 0;
        }

        // ---------- CUDA4J runtime ----------
        private static boolean ensureRuntime() {
            if (rtReady) return true;
            if (rtTried) return false;
            synchronized (SHA256.class) {
                if (rtReady || rtTried) return rtReady;
                rtTried = true;
                try {
                    devClz  = Class.forName("com.ibm.cuda.CudaDevice");
                    modClz  = Class.forName("com.ibm.cuda.CudaModule");
                    kerClz  = Class.forName("com.ibm.cuda.CudaKernel");
                    bufClz  = Class.forName("com.ibm.cuda.CudaBuffer");
                    gridClz = Class.forName("com.ibm.cuda.CudaGrid");
                    // stream is optional; keep it if available
                    try { streamClz = Class.forName("com.ibm.cuda.CudaStream"); } catch (Throwable ignore) {}

                    devCtor           = devClz.getConstructor(int.class);
                    // most CUDA4J builds have a module(byte[]) ctor; use it to avoid path-dependent I/O
                    modFromBytesCtor  = modClz.getConstructor(devClz, byte[].class);
                    kerFromModCtor    = kerClz.getConstructor(modClz, String.class);
                    bufCtor           = bufClz.getConstructor(devClz, long.class);
                    // CudaGrid(gridDimX, blockDimX) ctor is common; y/z default to 1
                    try {
                        gridCtor = gridClz.getConstructor(int.class, int.class);
                    } catch (NoSuchMethodException e) {
                        // fallback to full 6-arg ctor if needed
                        gridCtor = gridClz.getConstructor(int.class,int.class,int.class,int.class,int.class,int.class);
                    }

                    // methods
                    launchM   = kerClz.getMethod("launch", gridClz, Object[].class);
                    copyFromM = bufClz.getMethod("copyFrom", byte[].class, int.class, int.class);
                    copyToM   = bufClz.getMethod("copyTo",   byte[].class, int.class, int.class);
                    closeM    = bufClz.getMethod("close");
                    if (streamClz != null) {
                        syncM = streamClz.getMethod("synchronize");
                    }

                    // create device
                    device = devCtor.newInstance(0);

                    // load PTX -> module
                    String ptxPath = System.getProperty("com.ibm.crypto.gpu.sha256.ptx", "");
                    byte[] ptxBytes;
                    if (ptxPath == null || ptxPath.isEmpty()) {
                        String home = System.getProperty("java.home");
                        java.nio.file.Path p = java.nio.file.Paths.get(home, "lib", "security", "cuda", "sha256.ptx");
                        ptxBytes = java.nio.file.Files.readAllBytes(p);
                    } else {
                        ptxBytes = java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(ptxPath));
                    }
                    module = modFromBytesCtor.newInstance(device, ptxBytes);

                    // fetch kernel function from module
                    kernel = kerFromModCtor.newInstance(module, "sha256_blocks");

                    rtReady = true;
                } catch (Throwable t) {
                    rtReady = false; // stay CPU
                }
                return rtReady;
            }
        }

        private static byte[] gpuDigestWholeMessage(byte[] data) throws Exception {
            // host-side padding (FIPS 180-4)
            byte[] padded = padSHA256(data);
            int total = padded.length;
            int nBlocks = total / 64;

            // allocate device buffers (input bytes, 32-byte digest)
            Object inBuf  = bufCtor.newInstance(device, Long.valueOf(total));
            Object outBuf = bufCtor.newInstance(device, Long.valueOf(32));

            try {
                // H->D copy
                copyFromM.invoke(inBuf, padded, 0, total);

                // grid config: one thread is fine (kernel loops over blocks)
                Object grid;
                try {
                    grid = gridCtor.newInstance(Integer.valueOf(1), Integer.valueOf(1));
                } catch (IllegalArgumentException iae) {
                    // full ctor fallback: gridX,gridY,gridZ, blockX,blockY,blockZ
                    grid = gridCtor.newInstance(1,1,1, 1,1,1);
                }

                // launch: args = (inBuf, nBlocks, outBuf)
                launchM.invoke(kernel, grid, new Object[]{ inBuf, Integer.valueOf(nBlocks), outBuf });

                // D->H copy
                byte[] out = new byte[32];
                copyToM.invoke(outBuf, out, 0, 32);
                return out;

            } finally {
                try { closeM.invoke(inBuf);  } catch (Throwable ignore) {}
                try { closeM.invoke(outBuf); } catch (Throwable ignore) {}
            }
        }

        private static byte[] padSHA256(byte[] data) {
            long bitLen = ((long) data.length) * 8L;
            int n = data.length + 1 + 8;  // +0x80 + length
            int rem = n % 64;
            int padZero = (rem <= 56) ? (56 - rem) : (56 + (64 - rem));
            int total = data.length + 1 + padZero + 8;

            byte[] out = new byte[total];
            System.arraycopy(data, 0, out, 0, data.length);
            out[data.length] = (byte)0x80;
            // zeros already 0
            for (int i = 0; i < 8; i++) {
                out[total - 1 - i] = (byte)((bitLen >>> (8 * i)) & 0xFF);
            }
            return out;
        }
    }
}
