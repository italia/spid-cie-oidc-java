package it.spid.cie.oidc.test.util;

import java.io.File;
import java.nio.file.Files;

public class TestUtils {

	public static  String getContent(String resourceName) throws Exception {
		ClassLoader classLoader = TestUtils.class.getClassLoader();
		File file = new File(classLoader.getResource(resourceName).getFile());

		return Files.readString(file.toPath());
	}

}
