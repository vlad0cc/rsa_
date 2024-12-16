package com.anuj.security.encryption;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;
import java.util.Scanner;
import javax.crypto.Cipher;

public class RSAEncryptionDecryption {
	private static final String PUBLIC_KEY_FILE = "Public.key";
	private static final String PRIVATE_KEY_FILE = "Private.key";

	public static void main(String[] args) throws IOException {
		try (Scanner scanner = new Scanner(System.in)) {
			RSAEncryptionDecryption rsaObj = new RSAEncryptionDecryption();

			while (true) {
				System.out.println("\nВыберите действие:");
				System.out.println("1: Генерация ключей");
				System.out.println("2: Шифрование данных");
				System.out.println("3: Расшифровка данных");
				System.out.println("4: Выход");

				int choice = scanner.nextInt();
				scanner.nextLine(); // Очистка ввода

				switch (choice) {
					case 1:
						rsaObj.generateKeys();
						break;
					case 2:
						if (!keysExist()) {
							System.out.println("Ключи не найдены. Пожалуйста, сначала сгенерируйте ключи.");
							break;
						}
						System.out.println("Введите текст для шифрования:");
						String dataToEncrypt = scanner.nextLine();
						byte[] encryptedData = rsaObj.encryptData(dataToEncrypt);
						if (encryptedData != null) {
							System.out.println("Зашифрованные данные (Base64): " + Base64.getEncoder().encodeToString(encryptedData));
						}
						break;
					case 3:
						if (!keysExist()) {
							System.out.println("Ключи не найдены. Пожалуйста, сначала сгенерируйте ключи.");
							break;
						}
						System.out.println("Введите зашифрованные данные (Base64):");
						String encryptedInput = scanner.nextLine();
						byte[] encryptedBytes = Base64.getDecoder().decode(encryptedInput);
						rsaObj.decryptData(encryptedBytes);
						break;
					case 4:
						System.out.println("Выход из программы.");
						return;
					default:
						System.out.println("Неверный выбор. Пожалуйста, повторите попытку.");
				}
			}
		}
	}

	private static boolean keysExist() {
		File publicKeyFile = new File(PUBLIC_KEY_FILE);
		File privateKeyFile = new File(PRIVATE_KEY_FILE);
		return publicKeyFile.exists() && privateKeyFile.exists();
	}

	private void generateKeys() throws IOException {
		try {
			System.out.println("-------ГЕНЕРАЦИЯ ПУБЛИЧНОГО И ПРИВАТНОГО КЛЮЧА-------------");
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
			keyPairGenerator.initialize(2048); // Используется длина ключа 2048 бит для высокой безопасности
			KeyPair keyPair = keyPairGenerator.generateKeyPair();
			PublicKey publicKey = keyPair.getPublic();
			PrivateKey privateKey = keyPair.getPrivate();
			System.out.println("Публичный ключ - " + publicKey);
			System.out.println("Приватный ключ - " + privateKey);

			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			RSAPublicKeySpec rsaPubKeySpec = keyFactory.getKeySpec(publicKey, RSAPublicKeySpec.class);
			RSAPrivateKeySpec rsaPrivKeySpec = keyFactory.getKeySpec(privateKey, RSAPrivateKeySpec.class);

			saveKeys(PUBLIC_KEY_FILE, rsaPubKeySpec.getModulus(), rsaPubKeySpec.getPublicExponent());
			saveKeys(PRIVATE_KEY_FILE, rsaPrivKeySpec.getModulus(), rsaPrivKeySpec.getPrivateExponent());

			System.out.println("Ключи успешно сгенерированы и сохранены в файлы.");
		} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
			e.printStackTrace();
		}
	}

	private void saveKeys(String fileName, BigInteger mod, BigInteger exp) throws IOException {
		try (FileOutputStream fos = new FileOutputStream(fileName);
			 ObjectOutputStream oos = new ObjectOutputStream(new BufferedOutputStream(fos))) {
			System.out.println("Генерация файла " + fileName + "...");
			oos.writeObject(mod);
			oos.writeObject(exp);
			System.out.println(fileName + " успешно сгенерирован");
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	private byte[] encryptData(String data) throws IOException {
		System.out.println("\n----------------НАЧАЛО ШИФРОВАНИЯ------------");
		System.out.println("Данные до шифрования: " + data);
		byte[] dataToEncrypt = data.getBytes();
		byte[] encryptedData = null;
		try {
			PublicKey pubKey = readPublicKeyFromFile(PUBLIC_KEY_FILE);
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.ENCRYPT_MODE, pubKey);
			encryptedData = cipher.doFinal(dataToEncrypt);
			System.out.println("----------------ШИФРОВАНИЕ ЗАВЕРШЕНО------------");
		} catch (Exception e) {
			System.out.println("Ошибка при шифровании данных: " + e.getMessage());
		}
		return encryptedData;
	}

	private void decryptData(byte[] data) throws IOException {
		System.out.println("\n----------------НАЧАЛО РАСШИФРОВКИ------------");
		try {
			PrivateKey privateKey = readPrivateKeyFromFile(PRIVATE_KEY_FILE);
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.DECRYPT_MODE, privateKey);
			byte[] decryptedData = cipher.doFinal(data);
			System.out.println("Расшифрованные данные: " + new String(decryptedData));
			System.out.println("----------------РАСШИФРОВКА ЗАВЕРШЕНА------------");
		} catch (Exception e) {
			System.out.println("Ошибка при расшифровке данных: " + e.getMessage());
		}
	}

	public PublicKey readPublicKeyFromFile(String fileName) throws IOException {
		try (FileInputStream fis = new FileInputStream(new File(fileName));
			 ObjectInputStream ois = new ObjectInputStream(fis)) {
			BigInteger modulus = (BigInteger) ois.readObject();
			BigInteger exponent = (BigInteger) ois.readObject();
			RSAPublicKeySpec rsaPublicKeySpec = new RSAPublicKeySpec(modulus, exponent);
			KeyFactory fact = KeyFactory.getInstance("RSA");
			return fact.generatePublic(rsaPublicKeySpec);
		} catch (Exception e) {
			System.out.println("Ошибка при чтении публичного ключа: " + e.getMessage());
		}
		return null;
	}

	public PrivateKey readPrivateKeyFromFile(String fileName) throws IOException {
		try (FileInputStream fis = new FileInputStream(new File(fileName));
			 ObjectInputStream ois = new ObjectInputStream(fis)) {
			BigInteger modulus = (BigInteger) ois.readObject();
			BigInteger exponent = (BigInteger) ois.readObject();
			RSAPrivateKeySpec rsaPrivateKeySpec = new RSAPrivateKeySpec(modulus, exponent);
			KeyFactory fact = KeyFactory.getInstance("RSA");
			return fact.generatePrivate(rsaPrivateKeySpec);
		} catch (Exception e) {
			System.out.println("Ошибка при чтении приватного ключа: " + e.getMessage());
		}
		return null;
	}
}
