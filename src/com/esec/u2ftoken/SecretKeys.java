package com.esec.u2ftoken;

import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.Key;
import javacard.security.AESKey;
import javacard.security.CryptoException;
import javacard.security.DESKey;
import javacard.security.KeyBuilder;
import javacard.security.RandomData;
import javacardx.crypto.Cipher;

/** 
 * @author Yang Zhou 
 * @version 创建时间：2015-12-10 下午06:51:23 
 * 与密钥相关的操作和数据封装类
 */
public class SecretKeys {
	
	public static final byte MODE_ENCRYPT = 0x01; // 加密模式
	public static final byte MODE_DECRYPT = 0x02; // 解密模式
	
	public static final byte KEY_TYPE_AES = 0x01; // 本示例保存的是AES密钥
	public static final byte KEY_TYPE_DES = 0x02; // 本示例保存的是DES密钥
	
	private short mKeyType = 0x00;
	
	/**
	 * 密钥的实体
	 */
	private Key mKeyInstance = null;
	
	/**
	 * 初始化key wrap算法的密钥
	 * 采用AES-256，生成的AES密钥有256位
	 * 采用DES3-2KEY，生成的DES密钥有128位
	 */
	public SecretKeys(short keyType) {
		RandomData rng = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
		byte[] keyData = JCSystem.makeTransientByteArray((short) 16, JCSystem.CLEAR_ON_DESELECT);
		rng.generateData(keyData, (short) 0, (short) 16);
		mKeyType = keyType;
		if (mKeyType == KeyBuilder.LENGTH_DES3_2KEY) {
			mKeyInstance = KeyBuilder.buildKey(KeyBuilder.TYPE_DES, mKeyType, false);
			((DESKey)mKeyInstance).setKey(keyData, (short) 0);
		} else if (mKeyType == KeyBuilder.LENGTH_AES_128) {
			try {
				mKeyInstance = KeyBuilder.buildKey(KeyBuilder.TYPE_AES, mKeyType, false);
			} catch(CryptoException e) {
//				ISOException.throwIt(JCSystem.getVersion());
				short reason = e.getReason();
				ISOException.throwIt(reason);
			}
			((AESKey)mKeyInstance).setKey(keyData, (short) 0);
		}else {
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);
		}
		
	}
	
	/**
	 * key wrap算法，这里采用 AES-256 的 ALG_AES_BLOCK_128_CBC_NOPAD
	 * @param data 需要 wrap 的数据
	 * @param inOffset
	 * @param inLength
	 * @param outBuff
	 * @param outOffset
	 * @param mode 加密或解密。 Cipher.MODE_ENCRYPT 或 Cipher.MODE_DECRYPT
	 */
	public void keyWrap(byte[] data, short inOffset, short inLength, byte[] buffer, short outOffset, byte mode) {
		Cipher cipher = null;
		if (mKeyType == KeyBuilder.LENGTH_DES3_2KEY) {
			cipher = Cipher.getInstance(Cipher.ALG_DES_CBC_NOPAD, false);
		} else if (mKeyType == KeyBuilder.LENGTH_AES_128) {
			cipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
		} else {
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);
		}
		cipher.init(mKeyInstance, mode); // 初始向量(iv)是0
		
		// 加密或解密，doFinal后，cipher对象将被重置
		try {
			cipher.doFinal(data, inOffset, inLength, buffer, outOffset);
		} catch(Exception e) {
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);
		}
	}
}
