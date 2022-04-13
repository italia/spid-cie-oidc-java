package it.spid.cie.oidc.test.util;

import java.io.File;
import java.nio.file.Files;
import java.time.LocalDateTime;
import java.time.ZoneOffset;

public class TestUtils {

	public static  String getContent(String resourceName) throws Exception {
		ClassLoader classLoader = TestUtils.class.getClassLoader();
		File file = new File(classLoader.getResource(resourceName).getFile());

		return Files.readString(file.toPath());
	}

	public static long makeIssuedAt() {
		return LocalDateTime.now().toEpochSecond(ZoneOffset.UTC);
	}

	public static long makeExpiresOn() {
		return LocalDateTime.now().toEpochSecond(ZoneOffset.UTC) + (60 * 30);
	}

}
