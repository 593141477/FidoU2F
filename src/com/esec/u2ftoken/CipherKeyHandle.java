package com.esec.u2ftoken;

import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.ECPrivateKey;
import javacard.security.PrivateKey;
import javacard.security.KeyBuilder;
import javacardx.crypto.Cipher;

/** 
 * Key handle is encrypted private key and application parameter. 
 * @author z4yx
 * @version 2019-08-03
 */
public class CipherKeyHandle implements KeyHandleGenerator {

	private SecretKeys mCipher = null;
	private ECPrivateKey mPrivKey = null;
	private byte[] mPrivKeyAndSha;

	public CipherKeyHandle() {
		mPrivKeyAndSha = JCSystem.makeTransientByteArray((short) 64, JCSystem.CLEAR_ON_DESELECT);
		mCipher = new SecretKeys(KeyBuilder.LENGTH_DES3_2KEY);
		mPrivKey = (ECPrivateKey)KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, KeyBuilder.LENGTH_EC_FP_256, false);
		SecP256r1.setCurveParameters(mPrivKey);
	}

	public byte[] generateKeyHandle(byte[] applicationSha256, ECPrivateKey privateKey) {
		short sLen = privateKey.getS(mPrivKeyAndSha, (short) 0);
		if(sLen < (short)32) {
			short off = (short)32;
			off -= sLen;
			Util.arrayFillNonAtomic(mPrivKeyAndSha, (short) 0, off, (byte) 0);
			privateKey.getS(mPrivKeyAndSha, off);
		}
		Util.arrayCopyNonAtomic(applicationSha256, (short) 0, mPrivKeyAndSha, (short) 32, (short) 32);
		// return mPrivKeyAndSha; /// For DEBUG only

		byte[] keyHandle = SharedMemory.getInstance().m64BytesKeyHandle;
		mCipher.keyWrap(mPrivKeyAndSha, (short) 0, (short) mPrivKeyAndSha.length, keyHandle, (short) 0, Cipher.MODE_ENCRYPT);
		return keyHandle;
	}
	
	/**
	 * Check the application parameter and the index.
	 */
	public ECPrivateKey verifyKeyHandle(byte[] keyHandle, byte[] applicationSha256) {
		// byte[] mPrivKeyAndSha = keyHandle; /// For DEBUG only
		mCipher.keyWrap(keyHandle, (short) 0, (short) keyHandle.length, mPrivKeyAndSha, (short) 0, Cipher.MODE_DECRYPT);

		// Check the application parameter
		if (Util.arrayCompare(mPrivKeyAndSha, (short) 32, applicationSha256, (short) 0, (short) 32) != (byte)0x00) {
			return null;
		}

		mPrivKey.setS(mPrivKeyAndSha, (short) 0, (short) 32);

		return mPrivKey;
	}
}
