package DriveAPP;

import com.google.api.client.auth.oauth2.Credential;
import com.google.api.client.extensions.java6.auth.oauth2.AuthorizationCodeInstalledApp;
import com.google.api.client.extensions.jetty.auth.oauth2.LocalServerReceiver;
import com.google.api.client.googleapis.auth.oauth2.GoogleAuthorizationCodeFlow;
import com.google.api.client.googleapis.auth.oauth2.GoogleClientSecrets;
import com.google.api.client.googleapis.javanet.GoogleNetHttpTransport;
import com.google.api.client.http.FileContent;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.google.api.client.util.store.FileDataStoreFactory;
import com.google.api.services.drive.Drive;
import com.google.api.services.drive.DriveScopes;
import com.google.api.services.drive.model.File;
import com.google.api.services.drive.model.FileList;
import com.rockaport.alice.Alice;
import com.rockaport.alice.AliceContextBuilder;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;

import javax.crypto.SecretKey;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;

public class DriveQuickstart {
	private static final String APPLICATION_NAME = "Google Drive API Java Quickstart";
	private static final JsonFactory JSON_FACTORY = JacksonFactory.getDefaultInstance();
	private static final String TOKENS_DIRECTORY_PATH = "tokens";

	/**
	 * Global instance of the scopes required by this quickstart. If modifying these
	 * scopes, delete your previously saved tokens/ folder.
	 */
	private static final List<String> SCOPES = new ArrayList<String>() {
		{
			add(DriveScopes.DRIVE_FILE);
			add(DriveScopes.DRIVE_METADATA);
			add(DriveScopes.DRIVE_PHOTOS_READONLY);
			add(DriveScopes.DRIVE_APPDATA);
			add(DriveScopes.DRIVE_METADATA_READONLY);
			add(DriveScopes.DRIVE_SCRIPTS);
		}
	};

	private static final String CREDENTIALS_FILE_PATH = "/credentials.json";

	
	private static Credential getCredentials(final NetHttpTransport HTTP_TRANSPORT) throws IOException {
		// Load client secrets.
		InputStream in = DriveQuickstart.class.getResourceAsStream(CREDENTIALS_FILE_PATH);
		if (in == null) {
			throw new FileNotFoundException("Resource not found: " + CREDENTIALS_FILE_PATH);
		}
		GoogleClientSecrets clientSecrets = GoogleClientSecrets.load(JSON_FACTORY, new InputStreamReader(in));

		// Build flow and trigger user authorization request.

		GoogleAuthorizationCodeFlow flow = new GoogleAuthorizationCodeFlow.Builder(HTTP_TRANSPORT, JSON_FACTORY,
				clientSecrets, SCOPES)
						.setDataStoreFactory(new FileDataStoreFactory(new java.io.File(TOKENS_DIRECTORY_PATH)))
						.setAccessType("offline").build();
		LocalServerReceiver receiver = new LocalServerReceiver.Builder().setPort(8888).build();
		return new AuthorizationCodeInstalledApp(flow, receiver).authorize("user");
	}

	public static void main(String... args) throws IOException, GeneralSecurityException, URISyntaxException {
		
		//testEncription();
		try {
			testEncriptionWithSplit();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		final NetHttpTransport HTTP_TRANSPORT = GoogleNetHttpTransport.newTrustedTransport();
		Drive service = new Drive.Builder(HTTP_TRANSPORT, JSON_FACTORY, getCredentials(HTTP_TRANSPORT))
				.setApplicationName(APPLICATION_NAME).build();

		// Print the names and IDs for up to 10 files.
		FileList result = service.files().list().setPageSize(10).setFields("nextPageToken, files(id, name)")
				.setSupportsTeamDrives(true).execute();
		List<File> files = result.getFiles();
		if (files == null || files.isEmpty()) {
			System.out.println("No files found.");
		} else {
			System.out.println("Files:");
			for (File file : files) {
				System.out.printf("%s (%s)\n", file.getName(), file.getId());
			}
		}
	}

	private static void testEncription() throws URISyntaxException, GeneralSecurityException, IOException {
		Alice alice = new Alice(new AliceContextBuilder().build());
		
		URL url = DriveQuickstart.class.getClassLoader().getResource("DriveAPP/bigi.txt");
		java.io.File inputFile = new java.io.File(url.toURI());
		java.io.File encryptedFile = new java.io.File("the encrypted file");
		java.io.File decryptedFile = new java.io.File("the decrypted file.txt");
		
		final String secretKey = "ssshhhhhhhhhhh!!!!";
		
		alice.encrypt(
				inputFile, 
				encryptedFile, 
				secretKey.toCharArray());

		alice.decrypt(
				encryptedFile, 
				decryptedFile, 
				secretKey.toCharArray());
	}
	
	private static void testEncriptionWithSplit() throws Exception {
		Alice alice = new Alice(new AliceContextBuilder().build());
		
		// Files for testing
		URL url = DriveQuickstart.class.getClassLoader().getResource("DriveAPP/bigi.txt");
		java.io.File inputFile = new java.io.File(url.toURI());
		java.io.File encryptedFile = new java.io.File("the encrypted file");
		java.io.File decryptedFile = new java.io.File("the decrypted file.txt");
		java.io.File base64File1 = new java.io.File("base64File1");
		java.io.File base64File2 = new java.io.File("base64File2");
		java.io.File encryptedFileFromBase64 = new java.io.File("encryptedFromBase64");
		java.io.File decryptedFromBase64 = new java.io.File("decryptedFromBase64");
		
		// Password needs to be char array
		final String secretKey = "ssshhhhhhhhhhh!!!!";
		char[] pass = secretKey.toCharArray();
		
		// Encrypt input file
		byte[] inputBytes = IOUtils.toByteArray(new FileInputStream(inputFile));
		byte[] encr = alice.encrypt(inputBytes , pass);
		
		// Make base64 encoding of the encrypted file
		String encoded = encode64(encr);
		
		// Split base64 string in two files
		FileOutputStream fos1 = new FileOutputStream(base64File1);
		FileOutputStream fos2 = new FileOutputStream(base64File2);
		
		try (PrintStream out = new PrintStream(fos1)) {
		    out.print(encoded.substring(0, 20));
		}
		try (PrintStream out = new PrintStream(fos2)) {
		    out.print(encoded.substring(20));
		}
		
		// Build the base64 string from the fields containing its pieces
		String base64recomposed = recomposeBase64String(base64File1, base64File2);
		
		// test the recomposed base64 is the same as the original
		if(! encoded.equals(base64recomposed)){
			throw new Exception("The encoded base64 string doesnt match "
					+ "the one obtained from merging the files");
		};
		
		
		// Decrypt
		byte[] decryptedBytes = alice.decrypt(decode64(base64recomposed), pass);
		
		IOUtils.write(decryptedBytes, new FileOutputStream(decryptedFromBase64));

	}

	private static String recomposeBase64String(java.io.File base64File1, java.io.File base64File2) throws IOException {
		List<String> lines = FileUtils.readLines(base64File1, "UTF-8");
		List<String> lines2 = FileUtils.readLines(base64File2, "UTF-8");
		String base64recomposed = lines.get(0) + lines2.get(0);
		return base64recomposed;
	}

	private static byte[] decode64(String s) {
		byte[] dec = Base64.getDecoder().decode(s);
		return dec;
	}

	private static String encode64(java.io.File encryptedFile) throws IOException {
		InputStream is = new FileInputStream(encryptedFile);
		byte[] base64 = IOUtils.toByteArray(is);
		return encode64(base64);
	}
	
	private static String encode64(byte[] encrypted) throws IOException {
		String base64encodedString = Base64.getEncoder().encodeToString(encrypted);
		return base64encodedString;
	}
}