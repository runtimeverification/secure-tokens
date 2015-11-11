package com.github.sarxos.securetoken.impl;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;

import java.security.*;
import java.math.BigInteger;

public class Hardware4Nix {

	private static String sn = null;

	public static final String getSerialNumber() {


		if (sn == null) {
			readCPUID();
		}
		if (sn == null) {
			readDmidecode();
		}
		if (sn == null) {
			readLshal();
		}
		if (sn == null) {
			throw new RuntimeException("Cannot find computer SN");
		}

		return sn;
	}

	private static BufferedReader read(String command) {

		OutputStream os = null;
		InputStream is = null;

		Runtime runtime = Runtime.getRuntime();
		Process process = null;
		try {
			process = runtime.exec(command.split(" "));
		} catch (IOException e) {
			throw new RuntimeException(e);
		}

		os = process.getOutputStream();
		is = process.getInputStream();

		try {
			os.close();
		} catch (IOException e) {
			throw new RuntimeException(e);
		}

		return new BufferedReader(new InputStreamReader(is));
	}

	private static void readDmidecode() {

		String line = null;
		String marker = "Serial Number:";
		BufferedReader br = null;

		try {
			br = read("dmidecode -t system");
			while ((line = br.readLine()) != null) {
				if (line.indexOf(marker) != -1) {
					sn = line.split(marker)[1].trim();
					break;
				}
			}
		} catch (IOException e) {
			throw new RuntimeException(e);
		} finally {
			if (br != null) {
				try {
					br.close();
				} catch (IOException e) {
					throw new RuntimeException(e);
				}
			}
		}
	}

	private static void readCPUID() {

		String line = null;
		BufferedReader br = null;
        String currSN = "";

		try {
			br = read("lscpu");
			while ((line = br.readLine()) != null) {
				if (line.indexOf("Byte Order") != -1 || line.indexOf("Vendor") != -1 || line.indexOf("family") != -1 || line.indexOf("Model") != -1) {
					currSN += line.split(":")[1].trim();
				}
			}
            try {
                MessageDigest m = MessageDigest.getInstance("MD5");
                m.reset();
                m.update(currSN.getBytes());
                byte[] digest = m.digest();
                BigInteger bigInt = new BigInteger(1,digest);
                String hashtext = bigInt.toString(16);
                sn = hashtext;
            }
            catch (Exception ex) {
                throw new RuntimeException("System must support MD5 for Linux install!");
            }
		} catch (IOException e) {
			throw new RuntimeException(e);
		} finally {
			if (br != null) {
				try {
					br.close();
				} catch (IOException e) {
					throw new RuntimeException(e);
				}
			}
		}
	}

	private static void readLshal() {

		String line = null;
		String marker = "system.hardware.serial =";
		BufferedReader br = null;

		try {
			br = read("lshal");
			while ((line = br.readLine()) != null) {
				if (line.indexOf(marker) != -1) {
					sn = line.split(marker)[1].replaceAll("\\(string\\)|(\\')", "").trim();
					break;
				}
			}
		} catch (IOException e) {
			throw new RuntimeException(e);
		} finally {
			if (br != null) {
				try {
					br.close();
				} catch (IOException e) {
					throw new RuntimeException(e);
				}
			}
		}
	}
}
