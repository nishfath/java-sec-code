package org.joychou.controller;

import org.apache.commons.codec.binary.Base64;
import org.joychou.security.SecurityUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;

@RestController
public class PathTraversal {

    protected final Logger logger = LoggerFactory.getLogger(this.getClass());

    /**
     * http://localhost:8080/path_traversal/vul?filepath=../../../../../etc/passwd
     */
@GetMapping("/path_traversal/vul")
public String getImage(String filepath) throws IOException {
    return getImgBase64(filepath);
}


@GetMapping("/path_traversal/sec")
public String getImageSec(String filepath) throws IOException {
    // Apply strict validation and normalization to prevent directory traversal
    String sanitizedPath = sanitizeFilePath(filepath);
    if (sanitizedPath == null) {
        logger.info("Illegal file path: " + filepath);
        return "Bad boy. Illegal file path.";
    }
    return getImgBase64(sanitizedPath);
}

        return getImgBase64(filepath);
    }

private String getImgBase64(String imgFile) throws IOException {
    logger.info("Working directory: " + System.getProperty("user.dir"));
    logger.info("File path: " + imgFile);

    File f = new File(imgFile);
    try {
        // Additional security check to ensure file is within allowed directory
        String canonicalPath = f.getCanonicalPath();
        String baseDir = new File(getBaseImageDirectory()).getCanonicalPath();
        
        if (!canonicalPath.startsWith(baseDir)) {
            logger.warn("Attempted directory traversal attack: " + imgFile);
            return "Access denied: Invalid file location.";
        }
        
        if (f.exists() && !f.isDirectory()) {
            byte[] data = Files.readAllBytes(Paths.get(imgFile));
            return new String(Base64.encodeBase64(data));
        } else {
            return "File doesn't exist or is not a file.";
        }
    } catch (IOException e) {
        logger.error("Error processing file: " + e.getMessage());
        return "Error processing file.";
    }
}

        // Verify the requested file is within the allowed base directory
        if (!requestedFile.toPath().startsWith(baseDirectory.toPath())) {
            logger.warn("Path traversal attempt detected: " + imgFile);
            return "Access denied: Invalid file path.";
        }
        
        // Check if file exists and is not a directory
        if (requestedFile.exists() && !requestedFile.isDirectory()) {
            byte[] data = Files.readAllBytes(requestedFile.toPath());
            return new String(ApacheBase64.encodeBase64(data));
        } else {
            return "File doesn't exist or is not a file.";
        }
    } catch (IOException | InvalidPathException e) {
        logger.error("Error accessing file: " + e.getMessage(), e);
        return "Error: Could not access the requested file.";
    }
}

    }

    public static void main(String[] argv) throws IOException {
        String aa = new String(Files.readAllBytes(Paths.get("pom.xml")), StandardCharsets.UTF_8);
        System.out.println(aa);
    }
}